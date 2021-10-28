#include <nexus/quic/socket.hpp>
#include <nexus/quic/detail/engine_impl.hpp>
#include <nexus/quic/detail/socket_impl.hpp>
#include <array>
#include <cstring>

#include <netinet/ip.h>
#include <lsquic.h>

namespace nexus::quic {

void prepare_socket(udp::socket& sock, bool is_server, error_code& ec)
{
  if (sock.non_blocking(true, ec); ec) {
    return;
  }
  if (sock.set_option(receive_ecn{true}, ec); ec) {
    return;
  }
  if (is_server) {
    ec = nexus::detail::set_options(sock, receive_dstaddr{true},
                                    udp::socket::reuse_address{true});
  }
}

namespace detail {

static udp::socket bind_socket(const boost::asio::any_io_executor& ex,
                               const udp::endpoint& endpoint, bool is_server)
{
  // open the socket
  auto socket = udp::socket{ex, endpoint.protocol()};
  // set socket options before bind(), because the server enables REUSEADDR
  error_code ec;
  prepare_socket(socket, is_server, ec);
  if (ec) {
    throw system_error(ec);
  }
  socket.bind(endpoint); // may throw
  return socket;
}

socket_impl::socket_impl(engine_impl& engine, udp::socket&& socket,
                         ssl::context& ssl)
    : engine(engine),
      socket(std::move(socket)),
      ssl(ssl),
      local_addr(this->socket.local_endpoint())
{}

socket_impl::socket_impl(engine_impl& engine, const udp::endpoint& endpoint,
                         bool is_server, ssl::context& ssl)
    : engine(engine),
      socket(bind_socket(engine.get_executor(), endpoint, is_server)),
      ssl(ssl),
      local_addr(this->socket.local_endpoint())
{
}

socket_impl::executor_type socket_impl::get_executor() const
{
  return engine.get_executor();
}

void socket_impl::listen(int backlog)
{
  auto lock = std::unique_lock{engine.mutex};
  incoming_connections.set_capacity(backlog);
  start_recv();
}

void socket_impl::connect(connection_impl& c,
                          const udp::endpoint& endpoint,
                          const char* hostname)
{
  assert(&c.socket == this);
  auto lock = std::unique_lock{engine.mutex};
  auto peer_ctx = this;
  auto cctx = reinterpret_cast<lsquic_conn_ctx_t*>(&c);
  ::lsquic_engine_connect(engine.handle.get(), N_LSQVER,
      local_addr.data(), endpoint.data(), peer_ctx, cctx,
      hostname, 0, nullptr, 0, nullptr, 0);
  // note, this assert triggers with some quic versions that don't allow
  // multiple connections on the same address, see lquic's hash_conns_by_addr()
  assert(connection_state::is_open(c.state));
  engine.process(lock);
  start_recv();
}

void socket_impl::on_connect(connection_impl& c, lsquic_conn_t* conn)
{
  connection_state::on_connect(c.state, conn);
  open_connections.push_back(c);
}

void socket_impl::accept(connection_impl& c, accept_operation& op)
{
  auto lock = std::unique_lock{engine.mutex};
  if (!incoming_connections.empty()) {
    auto incoming = std::move(incoming_connections.front());
    incoming_connections.pop_front();
    open_connections.push_back(c);
    // when we accepted this, we had to return nullptr for the conn ctx
    // because we didn't have this connection_impl yet. update the ctx
    auto ctx = reinterpret_cast<lsquic_conn_ctx_t*>(&c);
    ::lsquic_conn_set_ctx(incoming.handle, ctx);
    connection_state::accept_incoming(c.state, std::move(incoming));
    op.post(error_code{}); // success
    return;
  }
  connection_state::accept(c.state, op);
  accepting_connections.push_back(c);
  engine.process(lock);
}

connection_context* socket_impl::on_accept(lsquic_conn_t* conn)
{
  assert(conn);
  if (accepting_connections.empty()) {
    // not waiting on accept, try to queue this for later
    if (incoming_connections.full()) {
      ::lsquic_conn_close(conn);
      return nullptr;
    }
    incoming_connections.push_back({conn, engine.max_streams_per_connection});
    return &incoming_connections.back();
  }
  auto& c = accepting_connections.front();
  list_transfer(c, accepting_connections, open_connections);

  connection_state::on_accept(c.state, conn);
  return &c;
}

void socket_impl::abort_connections(error_code ec)
{
  // close incoming streams that we haven't accepted yet
  while (!incoming_connections.empty()) {
    auto& incoming = incoming_connections.front();
    ::lsquic_conn_close(incoming.handle); // also closes incoming_streams
    incoming_connections.pop_front();
  }
  // close open connections on this socket
  while (!open_connections.empty()) {
    auto& c = open_connections.front();
    open_connections.pop_front();
    connection_state::reset(c.state, ec);
  }
  // cancel connections pending accept
  while (!accepting_connections.empty()) {
    auto& c = accepting_connections.front();
    accepting_connections.pop_front();
    connection_state::reset(c.state, ec);
  }
}

void socket_impl::close()
{
  auto lock = std::unique_lock{engine.mutex};
  abort_connections(make_error_code(connection_error::aborted));
  // send any CONNECTION_CLOSE frames before closing the socket
  engine.process(lock);
  receiving = false;
  socket.close();
}

void socket_impl::start_recv()
{
  if (receiving) {
    return;
  }
  receiving = true;
  socket.async_wait(udp::socket::wait_read,
      [this] (error_code ec) {
        receiving = false;
        if (!ec) {
          on_readable();
        } // XXX: else fatal? retry?
      });
}

void socket_impl::on_readable()
{
  std::array<unsigned char, 4096> buffer;
  iovec iov;
  iov.iov_base = buffer.data();
  iov.iov_len = buffer.size();

  error_code ec;
  for (;;) {
    udp::endpoint peer;
    sockaddr_union self;
    int ecn = 0;

    const auto bytes = recv_packet(iov, peer, self, ecn, ec);
    if (ec) {
      if (ec == errc::resource_unavailable_try_again ||
          ec == errc::operation_would_block) {
        start_recv();
      } // XXX: else fatal? retry?
      return;
    }

    auto lock = std::unique_lock{engine.mutex};
    const auto peer_ctx = this;
    ::lsquic_engine_packet_in(engine.handle.get(), buffer.data(), bytes,
                              &self.addr, peer.data(), peer_ctx, ecn);
    engine.process(lock);
  }
}

void socket_impl::on_writeable()
{
  auto lock = std::scoped_lock{engine.mutex};
  ::lsquic_engine_send_unsent_packets(engine.handle.get());
}

auto socket_impl::send_packets(const lsquic_out_spec* begin,
                               const lsquic_out_spec* end,
                               error_code& ec)
  -> const lsquic_out_spec*
{
  msghdr msg;
  msg.msg_flags = 0;

  // send until we encounter a packet with a different peer_ctx
  auto p = begin;
  for (; p < end && p->peer_ctx == begin->peer_ctx; ++p) {
    msg.msg_name = const_cast<void*>(static_cast<const void*>(p->dest_sa));
    if (p->dest_sa->sa_family == AF_INET) {
      msg.msg_namelen = sizeof(struct sockaddr_in);
    } else {
      msg.msg_namelen = sizeof(struct sockaddr_in6);
    }

    msg.msg_iov = p->iov;
    msg.msg_iovlen = p->iovlen;

    constexpr size_t ecn_size = sizeof(int); // TODO: add DSTADDR
    constexpr size_t max_control_size = CMSG_SPACE(ecn_size);
    auto control = std::array<unsigned char, max_control_size>{};
    if (p->ecn) {
      msg.msg_control = control.data();
      msg.msg_controllen = control.size();

      cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
      if (p->dest_sa->sa_family == AF_INET) {
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_PKTINFO;
      } else {
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_TCLASS;
      }
      cmsg->cmsg_len = CMSG_LEN(ecn_size);
      ::memcpy(CMSG_DATA(cmsg), &p->ecn, ecn_size);
      msg.msg_controllen = CMSG_SPACE(ecn_size);
    } else {
      msg.msg_controllen = 0;
      msg.msg_control = nullptr;
    }

    // TODO: send all at once with sendmmsg()
    if (::sendmsg(socket.native_handle(), &msg, 0) == -1) {
      ec.assign(errno, system_category());
      if (ec == errc::resource_unavailable_try_again ||
          ec == errc::operation_would_block) {
        // lsquic won't call our send_packets() callback again until we call
        // lsquic_engine_send_unsent_packets()
        // wait for the socket to become writeable again, so we can call that
        socket.async_wait(udp::socket::wait_write,
            [this] (error_code ec) {
              if (!ec) {
                on_writeable();
              } // else fatal?
            });
        errno = ec.value(); // lsquic needs to see this errno
      }
      break;
    }
  }
  return p;
}

constexpr size_t ecn_size = sizeof(int);
#ifdef IP_RECVORIGDSTADDR
constexpr size_t dstaddr4_size = sizeof(sockaddr_in);
#else
constexpr size_t dstaddr4_size = sizeof(in_pktinfo)
#endif
constexpr size_t dstaddr_size = std::max(dstaddr4_size, sizeof(in6_pktinfo));
constexpr size_t max_control_size = CMSG_SPACE(ecn_size) + CMSG_SPACE(dstaddr_size);

size_t socket_impl::recv_packet(iovec iov, udp::endpoint& peer,
                                sockaddr_union& self, int& ecn,
                                error_code& ec)
{
  auto msg = msghdr{};

  msg.msg_name = peer.data();
  msg.msg_namelen = peer.size();

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  std::array<unsigned char, max_control_size> control;
  msg.msg_control = control.data();
  msg.msg_controllen = control.size();

  const auto bytes = ::recvmsg(socket.native_handle(), &msg, 0);
  if (bytes == -1) {
    ec.assign(errno, system_category());
    return 0;
  }

  if (local_addr.data()->sa_family == AF_INET6) {
    ::memcpy(&self.addr6, local_addr.data(), sizeof(sockaddr_in6));
  } else {
    ::memcpy(&self.addr4, local_addr.data(), sizeof(sockaddr_in));
  }

  for (auto cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == IPPROTO_IP) {
      if (cmsg->cmsg_type == IP_TOS) {
        auto value = reinterpret_cast<const int*>(CMSG_DATA(cmsg));
        ecn = IPTOS_ECN(*value);
#ifdef IP_RECVORIGDSTADDR
      } else if (cmsg->cmsg_type == IP_ORIGDSTADDR) {
        ::memcpy(&self.storage, CMSG_DATA(cmsg), sizeof(sockaddr_in));
#else
      } else if (cmsg->cmsg_type == IP_PKTINFO) {
        auto info = reinterpret_cast<const in_pktinfo*>(CMSG_DATA(cmsg));
        self.addr4.sin_addr = info->ipi_addr;
#endif
      }
    } else if (cmsg->cmsg_level == IPPROTO_IPV6) {
      if (cmsg->cmsg_type == IPV6_TCLASS) {
        auto value = reinterpret_cast<const int*>(CMSG_DATA(cmsg));
        ecn = IPTOS_ECN(*value);
      } else if (cmsg->cmsg_type == IPV6_PKTINFO) {
        auto info = reinterpret_cast<const in6_pktinfo*>(CMSG_DATA(cmsg));
        self.addr6.sin6_addr = info->ipi6_addr;
      }
    }
  }
  return bytes;
}

} // namespace detail
} // namespace nexus::quic
