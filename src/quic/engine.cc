#include <chrono>
#include <vector>

#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>

#include <lsquic.h>
#include <lsxpack_header.h>

#include <nexus/quic/detail/connection.hpp>
#include <nexus/quic/detail/engine.hpp>
#include <nexus/quic/detail/stream.hpp>
#include <nexus/quic/socket.hpp>

namespace nexus {
namespace quic::detail {

void engine_deleter::operator()(lsquic_engine* e) const {
  ::lsquic_engine_destroy(e);
}

constexpr unsigned ring_queue_depth = 3; // timerfd + recvmsg + POLLOUT

engine_state::~engine_state()
{
  close();
}

asio::ip::udp::endpoint engine_state::local_endpoint() const
{
  return local_addr;
}

asio::ip::udp::endpoint engine_state::remote_endpoint(connection_state& cstate)
{
  auto remote = asio::ip::udp::endpoint{};
  auto lock = std::scoped_lock{mutex};
  if (cstate.handle) {
    const sockaddr* l = nullptr;
    const sockaddr* r = nullptr;
    lsquic_conn_get_sockaddr(cstate.handle, &l, &r);
    if (r->sa_family == AF_INET6) {
      ::memcpy(remote.data(), r, sizeof(sockaddr_in6));
    } else {
      ::memcpy(remote.data(), r, sizeof(sockaddr_in));
    }
  }
  return remote;
}

void engine_state::connect(connection_state& cstate, connect_request& req)
{
  auto lock = std::unique_lock{mutex};
  auto cctx = reinterpret_cast<lsquic_conn_ctx_t*>(&cstate);
  assert(!cstate.connect_);
  cstate.connect_ = &req;
  ::lsquic_engine_connect(handle.get(), N_LSQVER,
      local_addr.data(), req.endpoint->data(), this, cctx,
      req.hostname, 0, nullptr, 0, nullptr, 0);
}

void engine_state::on_connect(connection_state& cstate, lsquic_conn_t* conn)
{
  assert(cstate.connect_);
  assert(!cstate.handle);
  cstate.handle = conn;
  cstate.connect_->notify(error_code{}); // success
  cstate.connect_ = nullptr;
}

void engine_state::accept(connection_state& cstate, accept_request& req)
{
  auto lock = std::unique_lock{mutex};
  if (!incoming_connections.empty()) {
    cstate.handle = incoming_connections.front();
    incoming_connections.pop();
    req.ec.emplace(); // success
    return;
  }
  assert(!cstate.accept_);
  cstate.accept_ = &req;
  wait(lock, req);
}

connection_state* engine_state::on_accept(lsquic_conn_t* conn)
{
  if (accepting_connections.empty()) {
    incoming_connections.push(conn);
    return nullptr;
  }
  auto& cstate = accepting_connections.front();
  accepting_connections.pop_front();
  assert(cstate.accept_);
  assert(!cstate.handle);
  cstate.handle = conn;
  cstate.accept_->notify(error_code{}); // success
  cstate.accept_ = nullptr;
  return &cstate;
}

void engine_state::close(connection_state& cstate, close_request& req)
{
  auto lock = std::unique_lock{mutex};
  assert(!cstate.close_);
  cstate.close_ = &req;
  ::lsquic_conn_close(cstate.handle);
  wait(lock, req);
}

void engine_state::on_close(connection_state& cstate, lsquic_conn_t* conn)
{
  assert(cstate.handle == conn);
  if (cstate.close_) {
    cstate.close_->notify(error_code{}); // success
    cstate.close_ = nullptr;
  } else if (cstate.connect_) {
    cstate.connect_->notify(make_error_code(errc::connection_refused));
    cstate.connect_ = nullptr;
  } else {
    // remote closed? cancel other requests on this connection
  }
}

void engine_state::stream_connect(stream_state& sstate,
                                  stream_connect_request& req)
{
  auto lock = std::unique_lock{mutex};
  assert(!sstate.connect_);
  sstate.connect_ = &req;
  auto& cstate = sstate.conn;
  cstate.connecting_streams.push_back(sstate);
  ::lsquic_conn_make_stream(cstate.handle);
  wait(lock, req);
}

stream_state& engine_state::on_stream_connect(connection_state& cstate,
                                              lsquic_stream_t* stream)
{
  assert(!cstate.connecting_streams.empty());
  auto& sstate = cstate.connecting_streams.front();
  cstate.connecting_streams.pop_front();
  assert(!sstate.handle);
  sstate.handle = stream;
  assert(sstate.connect_);
  sstate.connect_->notify(error_code{}); // success
  sstate.connect_ = nullptr;
  return sstate;
}

void engine_state::stream_accept(stream_state& sstate,
                                 stream_accept_request& req)
{
  auto lock = std::unique_lock{mutex};
  auto& cstate = sstate.conn;
  if (!cstate.incoming_streams.empty()) {
    sstate.handle = cstate.incoming_streams.front();
    cstate.incoming_streams.pop();
    return;
  }
  assert(!sstate.accept_);
  sstate.accept_ = &req;
  cstate.accepting_streams.push_back(sstate);
  wait(lock, req);
}

void engine_state::stream_read(stream_state& sstate, stream_data_request& req)
{
  auto lock = std::unique_lock{mutex};
  assert(!sstate.in.header);
  assert(!sstate.in.data);
  if (::lsquic_stream_wantread(sstate.handle, 1) == -1) {
    req.ec.emplace(errno, system_category());
    return;
  }
  sstate.in.data = &req;
  wait(lock, req);
}

void engine_state::stream_read_headers(stream_state& sstate,
                                       stream_header_read_request& req)
{
  auto lock = std::unique_lock{mutex};
  assert(!sstate.in.data);
  assert(!sstate.in.header);
  if (::lsquic_stream_wantread(sstate.handle, 1) == -1) {
    req.ec.emplace(errno, system_category());
    return;
  }
  sstate.in.header = &req;
  wait(lock, req);
}

struct recv_header_set {
  http3::fields fields;
  int is_push_promise;
  lsxpack_header header;
  std::vector<char> buffer;

  recv_header_set(int is_push_promise) : is_push_promise(is_push_promise) {}
};

void engine_state::on_stream_read(stream_state& sstate)
{
  error_code ec;
  if (sstate.in.header) {
    auto& req = *std::exchange(sstate.in.header, nullptr);
    auto headers = std::unique_ptr<recv_header_set>(
        reinterpret_cast<recv_header_set*>(
            ::lsquic_stream_get_hset(sstate.handle)));
    (*req.fields) = std::move(headers->fields);
    req.notify(ec); // success
  } else if (sstate.in.data) {
    auto& req = *std::exchange(sstate.in.data, nullptr);
    auto bytes = ::lsquic_stream_readv(sstate.handle, req.iovs, req.num_iovs);
    if (bytes == -1) {
      bytes = 0;
      ec.assign(errno, system_category());
    } else if (bytes == 0) {
      ec = make_error_code(error::end_of_stream);
    }
    req.bytes = bytes;
    req.notify(ec);
  }
  ::lsquic_stream_wantread(sstate.handle, 0);
}

void engine_state::stream_write(stream_state& sstate, stream_data_request& req)
{
  auto lock = std::unique_lock{mutex};
  assert(!sstate.out.header);
  assert(!sstate.out.data);
  if (::lsquic_stream_wantwrite(sstate.handle, 1) == -1) {
    req.ec.emplace(errno, system_category());
    return;
  }
  sstate.out.data = &req;
  wait(lock, req);
}

void engine_state::stream_write_headers(stream_state& sstate,
                                        stream_header_write_request& req)
{
  auto lock = std::unique_lock{mutex};
  assert(!sstate.out.data);
  assert(!sstate.out.header);
  if (::lsquic_stream_wantwrite(sstate.handle, 1) == -1) {
    req.ec.emplace(errno, system_category());
    return;
  }
  sstate.out.header = &req;
  wait(lock, req);
}

static void do_write_headers(lsquic_stream_t* stream,
                             const http3::fields& fields, error_code& ec)
{
  // stack-allocate a lsxpack_header array
  auto array = reinterpret_cast<lsxpack_header*>(
      ::alloca(fields.size() * sizeof(lsxpack_header)));
  int num_headers = 0;
  for (auto f = fields.begin(); f != fields.end(); ++f, ++num_headers) {
    auto& header = array[num_headers];
    const char* buf = f->data();
    const size_t name_offset = std::distance(buf, f->name().data());
    const size_t name_len = f->name().size();
    const size_t val_offset = std::distance(buf, f->value().data());
    const size_t val_len = f->value().size();
    lsxpack_header_set_offset2(&header, buf, name_offset, name_len,
                               val_offset, val_len);
    header.indexed_type = static_cast<uint8_t>(f->index());
  }
  auto headers = lsquic_http_headers{num_headers, array};
  if (::lsquic_stream_send_headers(stream, &headers, 0) == -1) {
    ec.assign(errno, system_category());
  }
}

void engine_state::on_stream_write(stream_state& sstate)
{
  error_code ec;
  if (sstate.out.header) {
    auto& req = *std::exchange(sstate.out.header, nullptr);
    do_write_headers(sstate.handle, *req.fields, ec);
    req.notify(ec);
  } else if (sstate.out.data) {
    auto& req = *std::exchange(sstate.out.data, nullptr);
    auto bytes = ::lsquic_stream_writev(sstate.handle, req.iovs, req.num_iovs);
    if (bytes == -1) {
      bytes = 0;
      ec.assign(errno, system_category());
    }
    req.bytes = bytes;
    req.notify(ec);
  }
  ::lsquic_stream_wantwrite(sstate.handle, 0);
}

void engine_state::stream_flush(stream_state& sstate,
                                stream_flush_request& req)
{
  auto lock = std::unique_lock{mutex};
  if (::lsquic_stream_flush(sstate.handle) == -1) {
    req.ec.emplace(errno, system_category());
    return;
  }
  process();
  req.ec.emplace(); // success
}

void engine_state::stream_shutdown(stream_state& sstate,
                                   stream_shutdown_request& req)
{
  const bool shutdown_read = (req.how == 0 || req.how == 2);
  const bool shutdown_write = (req.how == 1 || req.how == 2);
  auto lock = std::unique_lock{mutex};
  if (::lsquic_stream_shutdown(sstate.handle, req.how) == -1) {
    req.ec.emplace(errno, system_category());
    return;
  }
  auto ec = make_error_code(errc::operation_canceled);
  if (shutdown_read) {
    if (sstate.in.header) {
      sstate.in.header->notify(ec);
      sstate.in.header = nullptr;
    }
    if (sstate.in.data) {
      sstate.in.data->notify(ec);
      sstate.in.data = nullptr;
    }
  }
  if (shutdown_write) {
    if (sstate.out.header) {
      sstate.out.header->notify(ec);
      sstate.out.header = nullptr;
    }
    if (sstate.out.data) {
      sstate.out.data->notify(ec);
      sstate.out.data = nullptr;
    }
  }
  process();
  req.ec.emplace(); // success
}

void engine_state::stream_close(stream_state& sstate,
                                stream_close_request& req)
{
  auto lock = std::unique_lock{mutex};
  assert(!sstate.close_);
  sstate.close_ = &req;
  ::lsquic_stream_close(sstate.handle);
  // cancel other stream requests now. otherwise on_stream_close() would
  // fail them with connection_reset
  auto ec = make_error_code(errc::operation_canceled);
  if (sstate.in.header) {
    sstate.in.header->notify(ec);
    sstate.in.header = nullptr;
  }
  if (sstate.in.data) {
    sstate.in.data->notify(ec);
    sstate.in.data = nullptr;
  }
  if (sstate.out.header) {
    sstate.out.header->notify(ec);
    sstate.out.header = nullptr;
  }
  if (sstate.out.data) {
    sstate.out.data->notify(ec);
    sstate.out.data = nullptr;
  }
  wait(lock, req);
}

void engine_state::on_stream_close(stream_state& sstate)
{
  if (sstate.close_) {
    sstate.close_->notify(error_code{}); // success
    sstate.close_ = nullptr;
  } else if (sstate.connect_) {
    // peer refused or handshake failed?
    sstate.connect_->notify(make_error_code(errc::connection_refused));
    sstate.connect_ = nullptr;
  } else {
    // remote closed? cancel other requests on this stream
    auto ec = make_error_code(errc::connection_reset);
    if (sstate.in.header) {
      sstate.in.header->notify(ec);
      sstate.in.header = nullptr;
    }
    if (sstate.in.data) {
      sstate.in.data->notify(ec);
      sstate.in.data = nullptr;
    }
    if (sstate.out.header) {
      sstate.out.header->notify(ec);
      sstate.out.header = nullptr;
    }
    if (sstate.out.data) {
      sstate.out.data->notify(ec);
      sstate.out.data = nullptr;
    }
  }
}

void engine_state::wait(std::unique_lock<std::mutex>& lock)
{
  lock.unlock(); // unlock during io_uring_wait_cqe()

  io_uring_cqe* cqe = nullptr;
  if (int r = ::io_uring_wait_cqe(&ring, &cqe); r == -1) {
    ::perror("io_uring_wait_cqe");
    abort(); // fatal error
    return;
  }
  const auto type = reinterpret_cast<intptr_t>(::io_uring_cqe_get_data(cqe));

  lock.lock(); // reacquire lock after io_uring_wait_cqe()
  switch (static_cast<request_type>(type)) {
    case request_type::timer: on_timer(); break;
    case request_type::recv: on_recv(cqe->res); break;
    case request_type::poll: on_writeable(); break;
  }
  ::io_uring_cqe_seen(&ring, cqe);
}

void engine_state::wait(std::unique_lock<std::mutex>& lock,
                        engine_request& req)
{
  if (waiting) {
    std::condition_variable cond;
    req.cond = &cond;
    cond.wait(lock, [&req] { return req.ec; });
  } else {
    waiting = true;
    ::lsquic_engine_process_conns(handle.get());
    while (!req.ec) {
      wait(lock);
    }
    // XXX: there may be other waiters; one of them needs to wake up and call
    // back into uring
    reschedule();
    waiting = false;
  }
}

void engine_state::close()
{
  ::lsquic_engine_cooldown(handle.get());
  ::io_uring_queue_exit(&ring);
  timerfd.close();
  socket.close();
}

void engine_state::process()
{
  ::lsquic_engine_process_conns(handle.get());
  reschedule();
}

void engine_state::reschedule()
{
  int micros = 0;
  if (!::lsquic_engine_earliest_adv_tick(handle.get(), &micros)) {
    return;
  }
  if (micros <= 0) {
    process();
    return;
  }
  using namespace std::chrono;
  const auto dur = microseconds{micros};
  const auto sec = duration_cast<seconds>(dur);
  const auto nsec = duration_cast<nanoseconds>(dur - sec);
  auto expires_in = itimerspec{};
  expires_in.it_value.tv_sec = sec.count();
  expires_in.it_value.tv_nsec = nsec.count();

  auto prev = itimerspec{};
  if (::timerfd_settime(*timerfd, 0, &expires_in, &prev) == -1) {
    ::perror("timerfd_settime");
    abort(); // fatal?
  }

  if (timer.armed) {
    return;
  }
  timer.armed = true;
  auto sqe = ::io_uring_get_sqe(&ring); assert(sqe);
  ::io_uring_prep_read(sqe, *timerfd, timer.buffer.data(),
                       timer.buffer.size(), 0);
  const auto type = static_cast<intptr_t>(request_type::timer);
  ::io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(type));
  ::io_uring_submit(&ring);
}

void engine_state::on_timer()
{
  timer.armed = false;
  process();
}

void engine_state::start_recv()
{
  ::memset(&recv.msg, 0, sizeof(recv.msg));

  recv.msg.msg_name = recv.addr.data();
  recv.msg.msg_namelen = recv.addr.size();

  recv.iov.iov_base = recv.buffer.data();
  recv.iov.iov_len = recv.buffer.size();
  recv.msg.msg_iov = &recv.iov;
  recv.msg.msg_iovlen = 1;

  recv.msg.msg_control = recv.control.data();
  recv.msg.msg_controllen = recv.control.size();

  auto sqe = ::io_uring_get_sqe(&ring); assert(sqe);
  ::io_uring_prep_recvmsg(sqe, socket.native_handle(), &recv.msg, 0);
  const auto type = static_cast<intptr_t>(request_type::recv);
  ::io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(type));
  ::io_uring_submit(&ring);
}

void engine_state::on_recv(int bytes)
{
  union sockaddr_union {
    sockaddr_storage storage;
    sockaddr addr;
    sockaddr_in addr4;
    sockaddr_in6 addr6;
  };
  sockaddr_union local;

  if (local_addr.data()->sa_family == AF_INET6) {
    ::memcpy(&local.addr6, local_addr.data(), sizeof(sockaddr_in6));
  } else {
    ::memcpy(&local.addr4, local_addr.data(), sizeof(sockaddr_in));
  }

  int ecn = 0;
  for (auto cmsg = CMSG_FIRSTHDR(&recv.msg); cmsg;
       cmsg = CMSG_NXTHDR(&recv.msg, cmsg)) {
    if (cmsg->cmsg_level == IPPROTO_IP) {
      if (cmsg->cmsg_type == IP_TOS) {
        auto value = reinterpret_cast<const int*>(CMSG_DATA(cmsg));
        ecn = IPTOS_ECN(*value);
#ifdef IP_RECVORIGDSTADDR
      } else if (cmsg->cmsg_type == IP_ORIGDSTADDR) {
        ::memcpy(&local.storage, CMSG_DATA(cmsg), sizeof(sockaddr_in));
#else
      } else if (cmsg->cmsg_type == IP_PKTINFO) {
        auto info = reinterpret_cast<const in_pktinfo*>(CMSG_DATA(cmsg));
        local.addr4.sin_addr = info->ipi_addr;
#endif
      }
    } else if (cmsg->cmsg_level == IPPROTO_IPV6) {
      if (cmsg->cmsg_type == IPV6_TCLASS) {
        auto value = reinterpret_cast<const int*>(CMSG_DATA(cmsg));
        ecn = IPTOS_ECN(*value);
      } else if (cmsg->cmsg_type == IPV6_PKTINFO) {
        auto info = reinterpret_cast<const in6_pktinfo*>(CMSG_DATA(cmsg));
        local.addr6.sin6_addr = info->ipi6_addr;
      }
    }
  }

  ::lsquic_engine_packet_in(handle.get(), recv.buffer.data(), bytes,
                            &local.addr, recv.addr.data(), this, ecn);
  start_recv();
  process();
}

void engine_state::on_writeable()
{
  ::lsquic_engine_send_unsent_packets(handle.get());
}

int engine_state::send_packets(const lsquic_out_spec* specs, unsigned n_specs)
{
  const int count = send_udp_packets(socket.native_handle(), specs, n_specs);
  if (count < n_specs) {
    const int error = errno;
    if (error == EAGAIN || error == EWOULDBLOCK) {
      // lsquic won't call our send_packets() callback again until we call
      // lsquic_engine_send_unsent_packets()
      // poll for the socket to become writeable again, so we can call that
      auto sqe = ::io_uring_get_sqe(&ring); assert(sqe);
      ::io_uring_prep_poll_add(sqe, socket.native_handle(), POLLOUT);
      const auto type = static_cast<intptr_t>(request_type::poll);
      ::io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(type));
      ::io_uring_submit(&ring);
      assert(errno == error); // make sure io_uring didn't change errno
    }
  }
  return count;
}


// stream api
static lsquic_conn_ctx_t* on_new_conn(void* ectx, lsquic_conn_t* conn)
{
  auto estate = static_cast<engine_state*>(ectx);
  auto cctx = ::lsquic_conn_get_ctx(conn);
  // outgoing connections will have a context set by lsquic_engine_connect()
  if (!cctx) {
    auto cstate = estate->on_accept(conn);
    return reinterpret_cast<lsquic_conn_ctx_t*>(cstate);
  }
  auto cstate = reinterpret_cast<connection_state*>(cctx);
  estate->on_connect(*cstate, conn);
  return cctx;
}

static lsquic_stream_ctx_t* on_new_stream(void* ectx, lsquic_stream_t* stream)
{
  auto estate = static_cast<engine_state*>(ectx);
  if (stream == nullptr) {
    return nullptr; // connection went away?
  }
  auto conn = ::lsquic_stream_conn(stream);
  auto cctx = ::lsquic_conn_get_ctx(conn);
  auto cstate = reinterpret_cast<connection_state*>(cctx);
  auto& sstate = estate->on_stream_connect(*cstate, stream);
  return reinterpret_cast<lsquic_stream_ctx_t*>(&sstate);
}

static void on_read(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
{
  auto sstate = reinterpret_cast<stream_state*>(sctx);
  sstate->conn.engine.on_stream_read(*sstate);
}

static void on_write(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
{
  auto sstate = reinterpret_cast<stream_state*>(sctx);
  sstate->conn.engine.on_stream_write(*sstate);
}

static void on_close(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
{
  auto sstate = reinterpret_cast<stream_state*>(sctx);
  if (sstate) {
    sstate->conn.engine.on_stream_close(*sstate);
  }
}

static void on_conn_closed(lsquic_conn_t* conn)
{
  auto cctx = ::lsquic_conn_get_ctx(conn);
  auto cstate = reinterpret_cast<connection_state*>(cctx);
  cstate->engine.on_close(*cstate, conn);
}

static constexpr lsquic_stream_if make_client_stream_api()
{
  lsquic_stream_if api = {};
  api.on_new_conn = on_new_conn;
  api.on_conn_closed = on_conn_closed;
  api.on_new_stream = on_new_stream;
  api.on_read = on_read;
  api.on_write = on_write;
  api.on_close = on_close;
  return api;
}


// header set api
static void* header_set_create(void* ctx, lsquic_stream_t* stream,
                               int is_push_promise)
{
  // TODO: store this in stream_state to avoid allocation?
  return new recv_header_set(is_push_promise);
}

static lsxpack_header* header_set_prepare(void* hset, lsxpack_header* hdr,
                                          size_t space)
{
  auto headers = reinterpret_cast<recv_header_set*>(hset);
  auto& header = headers->header;
  auto& buf = headers->buffer;
  buf.resize(space);
  if (hdr) { // existing header, just update the pointer and capacity
    header.buf = buf.data();
    header.val_len = space;
  } else { // initialize the entire header
    lsxpack_header_prepare_decode(&header, buf.data(), 0, space);
  }
  return &header;
}

static int header_set_process(void* hset, lsxpack_header* hdr)
{
  if (hdr) {
    auto headers = reinterpret_cast<recv_header_set*>(hset);
    auto name = std::string_view{hdr->buf + hdr->name_offset, hdr->name_len};
    auto value = std::string_view{hdr->buf + hdr->val_offset, hdr->val_len};
    auto index = static_cast<http3::should_index>(hdr->indexed_type);
    auto f = headers->fields.insert(name, value, index);
  }
  return 0;
}

static void header_set_discard(void* hset)
{
  delete reinterpret_cast<recv_header_set*>(hset);
}

static constexpr lsquic_hset_if make_client_header_api()
{
  lsquic_hset_if api = {};
  api.hsi_create_header_set  = header_set_create;
  api.hsi_prepare_decode = header_set_prepare;
  api.hsi_process_header = header_set_process;
  api.hsi_discard_header_set = header_set_discard;
  return api;
}

static int client_send_packets(void* ectx, const lsquic_out_spec *specs,
                        unsigned n_specs)
{
  auto estate = static_cast<engine_state*>(ectx);
  return estate->send_packets(specs, n_specs);
}

static udp::socket bind_socket(const asio::any_io_executor& ex,
                               const udp::endpoint& endpoint, unsigned flags)
{
  auto socket = udp::socket{ex, endpoint};
  error_code ec;
  prepare_socket(socket, flags & LSENG_SERVER, ec);
  if (ec) {
    throw system_error(ec);
  }
  return socket;
}

engine_state::engine_state(const asio::any_io_executor& ex,
                           const udp::endpoint& endpoint, unsigned flags)
  : engine_state(bind_socket(ex, endpoint, flags), flags)
{
}

engine_state::engine_state(udp::socket&& socket, unsigned flags)
  : socket(std::move(socket)), is_server(flags & LSENG_SERVER)
{
  error_code ec;

  timerfd = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
  if (!timerfd.is_open()) {
    ec.assign(errno, system_category());
    ::perror("timerfd_create");
    throw system_error(ec);
  }

  if (int r = ::io_uring_queue_init(ring_queue_depth, &ring, 0); r < 0) {
    ec.assign(-r, system_category());
    throw system_error(ec);
  }
  // TODO: register buffers with io_uring_register_buffers?

  lsquic_engine_settings settings;
  ::lsquic_engine_init_settings(&settings, flags);

  lsquic_engine_api api = {};
  api.ea_packets_out = client_send_packets;
  api.ea_packets_out_ctx = this;
  static const lsquic_stream_if stream_api = make_client_stream_api();
  api.ea_stream_if = &stream_api;
  api.ea_stream_if_ctx = this;
  if (flags & LSENG_HTTP) {
    static const lsquic_hset_if header_api = make_client_header_api();
    api.ea_hsi_if = &header_api;
    api.ea_hsi_ctx = this;
  }
  api.ea_settings = &settings;
  handle.reset(::lsquic_engine_new(flags, &api));

  start_recv();
}

asio::ip::udp::endpoint connection_state::remote_endpoint()
{
  return engine.remote_endpoint(*this);
}

void connection_state::connect(const asio::ip::udp::endpoint& endpoint,
                               const char* hostname, error_code& ec)
{
  connect_request req;
  req.endpoint = &endpoint;
  req.hostname = hostname;
  engine.connect(*this, req);
  ec = *req.ec;
}

void connection_state::accept(error_code& ec)
{
  accept_request req;
  engine.accept(*this, req);
  ec = *req.ec;
}

void connection_state::close(error_code& ec)
{
  close_request req;
  engine.close(*this, req);
  ec = *req.ec;
}

} // namespace quic::detail
} // namespace nexus
