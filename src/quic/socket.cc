#include <nexus/quic/socket.hpp>
#include <nexus/quic/detail/engine.hpp>
#include <nexus/quic/detail/socket.hpp>
#include <array>
#include <cstring>

//#include <netdb.h>
#include <lsquic.h>

namespace nexus::quic {

void prepare_socket(udp::socket& sock, bool is_server, error_code& ec)
{
  if (sock.non_blocking(true, ec); ec) {
    return;
  }
  if (sock.set_option(udp::receive_ecn{true}, ec); ec) {
    return;
  }
  if (is_server) {
    ec = udp::detail::set_options(sock, udp::receive_dstaddr{true},
                                  udp::socket::reuse_address{true});
  }
}

namespace detail {

static udp::socket bind_socket(const asio::any_io_executor& ex,
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

socket_state::socket_state(engine_state& engine, udp::socket&& socket,
                           ssl::context_ptr&& ssl)
    : engine(engine),
      socket(std::move(socket)),
      ssl(std::move(ssl)),
      local_addr(this->socket.local_endpoint())
{}

socket_state::socket_state(engine_state& engine, const udp::endpoint& endpoint,
                           bool is_server, ssl::context_ptr&& ssl)
    : engine(engine),
      socket(bind_socket(engine.get_executor(), endpoint, is_server)),
      ssl(std::move(ssl)),
      local_addr(this->socket.local_endpoint())
{
}

socket_state::executor_type socket_state::get_executor() const
{
  return engine.get_executor();
}

void socket_state::listen(int backlog)
{
  engine.listen(*this, backlog);
}

void socket_state::connect(connection_state& cstate,
                           const udp::endpoint& endpoint,
                           const char* hostname)
{
  engine.connect(cstate, endpoint, hostname);
}

void socket_state::accept(connection_state& cstate, accept_operation& op)
{
  engine.accept(cstate, op);
}

void socket_state::close(error_code& ec)
{
  engine.close(*this, ec);
}

auto socket_state::send_packets(const lsquic_out_spec* begin,
                                const lsquic_out_spec* end,
                                error_code& ec)
  -> const lsquic_out_spec*
{
  msghdr msg;
  msg.msg_flags = 0;

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
      break;
    }
  }
  return p;
}

} // namespace detail
} // namespace nexus::quic
