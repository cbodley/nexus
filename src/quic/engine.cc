#include <chrono>
#include <cstring>

#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <unistd.h>

#include <lsquic.h>

#include <nexus/quic/detail/connection.hpp>
#include <nexus/quic/detail/engine.hpp>
#include <nexus/quic/detail/stream.hpp>

namespace nexus {
namespace quic::detail {

void engine_deleter::operator()(lsquic_engine* e) const {
  ::lsquic_engine_destroy(e);
}

constexpr unsigned ring_queue_depth = 3; // timerfd + recvmsg + POLLOUT

int setup_socket(sockaddr_union& local_addr, error_code& ec)
{
  addrinfo hints = {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

  addrinfo* res = nullptr;
  int r = ::getaddrinfo(0, "0", &hints, &res);
  if (r != 0) {
    // getaddrinfo() worth its own error category? nah
    ec = make_error_code(errc::invalid_argument);
    return -1;
  }
  using addrinfo_ptr = std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)>;
  auto res_cleanup = addrinfo_ptr{res, &::freeaddrinfo};

  // open the socket in non-blocking mode
  const int socket_flags = SOCK_NONBLOCK | SOCK_CLOEXEC;
  const int fd = ::socket(res->ai_family,
                          res->ai_socktype + socket_flags,
                          res->ai_protocol);
  if (fd == -1) {
    ec.assign(errno, system_category());
    ::perror("socket");
    return -1;
  }

  // enable SO_REUSEADDR
  const int on = 1;
  r = ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  if (r == -1) {
    ec.assign(errno, system_category());
    ::perror("setsockopt SO_REUSEADDR");
    ::close(fd);
    return -1;
  }
  // enable ECN
  if (res->ai_family == AF_INET) {
    r = ::setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &on, sizeof(on));
  } else {
    r = ::setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof(on));
  }
  if (r == -1) {
    ec.assign(errno, system_category());
    ::perror("setsockopt ECN");
    ::close(fd);
    return -1;
  }
#if 0 // only enable DSTADDR for server engine
  if (res->ai_family == AF_INET) {
#ifdef IP_RECVORIGDSTADDR
    const int option = IP_RECVORIGDSTADDR;
#else
    const int option = IP_PKTINFO;
#endif
    r = ::setsockopt(fd, IPPROTO_IP, option, &on, sizeof(on));
  } else {
    r = ::setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
  }
  if (r == -1) {
    ec.assign(errno, system_category());
    ::perror("setsockopt DSTADDR");
    ::close(fd);
    return -1;
  }
#endif
  // bind the socket
  r = ::bind(fd, res->ai_addr, res->ai_addrlen);
  if (r == -1) {
    ec.assign(errno, system_category());
    ::perror("bind");
    ::close(fd);
    return -1;
  }

  // read the bound address
  socklen_t addrlen = sizeof(local_addr);
  r = ::getsockname(fd, &local_addr.addr, &addrlen);
  if (r == -1) {
    ec.assign(errno, system_category());
    ::perror("getsockname");
    ::close(fd);
    return -1;
  }

  return fd;
}

engine_state::~engine_state()
{
  close();
}

void engine_state::connection_open(connection_state& cstate,
                                   conn_open_request& req)
{
  auto lock = std::unique_lock{mutex};
  auto cctx = reinterpret_cast<lsquic_conn_ctx_t*>(&cstate);
  assert(!cstate.open);
  cstate.open = &req;
  ::lsquic_engine_connect(handle.get(), N_LSQVER,
      &local_addr.addr, req.remote_endpoint, this, cctx,
      req.remote_hostname, 0, nullptr, 0, nullptr, 0);
}

void engine_state::on_connection_open(connection_state& cstate,
                                      lsquic_conn_t* conn)
{
  assert(cstate.open);
  assert(!cstate.handle);
  cstate.handle = conn;
  cstate.open->notify(error_code{}); // success
  cstate.open = nullptr;
}

void engine_state::connection_close(connection_state& cstate,
                                    conn_close_request& req)
{
  auto lock = std::unique_lock{mutex};
  assert(!cstate.close_);
  cstate.close_ = &req;
  ::lsquic_conn_close(cstate.handle);
  wait(lock, req);
}

void engine_state::on_connection_close(connection_state& cstate,
                                       lsquic_conn_t* conn)
{
  assert(cstate.handle == conn);
  if (cstate.close_) {
    cstate.close_->notify(error_code{}); // success
    cstate.close_ = nullptr;
  } else if (cstate.open) {
    cstate.open->notify(make_error_code(errc::connection_refused));
    cstate.open = nullptr;
  } else {
    // remote closed? cancel other requests on this connection
  }
}

void engine_state::stream_open(stream_state& sstate, stream_open_request& req)
{
  auto lock = std::unique_lock{mutex};
  assert(!sstate.open);
  sstate.open = &req;
  auto& cstate = sstate.conn;
  cstate.opening_streams.push_back(sstate);
  ::lsquic_conn_make_stream(cstate.handle);
  wait(lock, req);
}

stream_state& engine_state::on_stream_open(connection_state& cstate,
                                           lsquic_stream_t* stream)
{
  assert(!cstate.opening_streams.empty());
  auto& sstate = cstate.opening_streams.front();
  cstate.opening_streams.pop_front();
  assert(!sstate.handle);
  sstate.handle = stream;
  assert(sstate.open);
  sstate.open->notify(error_code{}); // success
  sstate.open = nullptr;
  return sstate;
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
                                       stream_header_request& req)
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

void engine_state::on_stream_read(stream_state& sstate)
{
  if (sstate.in.header) { // TODO
    auto& req = *std::exchange(sstate.in.header, nullptr);
    req.notify(make_error_code(errc::operation_not_supported));
  } else if (sstate.in.data) {
    auto& req = *std::exchange(sstate.in.data, nullptr);
    auto bytes = ::lsquic_stream_readv(sstate.handle, req.iovs, req.num_iovs);
    error_code ec;
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
                                        stream_header_request& req)
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

void engine_state::on_stream_write(stream_state& sstate)
{
  if (sstate.out.header) {
    auto& req = *std::exchange(sstate.out.header, nullptr);
    auto headers = lsquic_http_headers{req.num_headers, req.headers};
    error_code ec;
    if (::lsquic_stream_send_headers(sstate.handle, &headers, 0) == -1) {
      ec.assign(errno, system_category());
    }
    req.notify(ec);
  } else if (sstate.out.data) {
    auto& req = *std::exchange(sstate.out.data, nullptr);
    auto bytes = ::lsquic_stream_writev(sstate.handle, req.iovs, req.num_iovs);
    error_code ec;
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
  } else if (sstate.open) {
    // peer refused or handshake failed?
    sstate.open->notify(make_error_code(errc::connection_refused));
    sstate.open = nullptr;
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
    reschedule();
    waiting = false;
  }
}

void engine_state::close()
{
  ::lsquic_engine_cooldown(handle.get());
  ::io_uring_queue_exit(&ring);
  ::close(timerfd);
  timerfd = -1;
  ::close(sockfd);
  sockfd = -1;
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
  if (::timerfd_settime(timerfd, 0, &expires_in, &prev) == -1) {
    ::perror("timerfd_settime");
    abort(); // fatal?
  }

  if (timer.armed) {
    return;
  }
  timer.armed = true;
  auto sqe = ::io_uring_get_sqe(&ring); assert(sqe);
  ::io_uring_prep_read(sqe, timerfd, timer.buffer.data(),
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

  recv.msg.msg_name = &recv.addr.storage;
  recv.msg.msg_namelen = sizeof(recv.addr.storage);

  recv.iov.iov_base = recv.buffer.data();
  recv.iov.iov_len = recv.buffer.size();
  recv.msg.msg_iov = &recv.iov;
  recv.msg.msg_iovlen = 1;

  recv.msg.msg_control = recv.control.data();
  recv.msg.msg_controllen = recv.control.size();

  auto sqe = ::io_uring_get_sqe(&ring); assert(sqe);
  ::io_uring_prep_recvmsg(sqe, sockfd, &recv.msg, 0);
  const auto type = static_cast<intptr_t>(request_type::recv);
  ::io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(type));
  ::io_uring_submit(&ring);
}

void engine_state::on_recv(int bytes)
{
  int ecn = 0;
  sockaddr_union local;
  ::memcpy(&local.storage, &local_addr.storage, sizeof(local_addr.storage));

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
                            &local.addr, &recv.addr.addr, this, ecn);
  start_recv();
  process();
}

void engine_state::on_writeable()
{
  ::lsquic_engine_send_unsent_packets(handle.get());
}

int engine_state::send_packets(const lsquic_out_spec *specs, unsigned n_specs) {
  int num_sent = 0;

  msghdr msg;
  msg.msg_flags = 0;

  for (auto spec = specs; spec < specs + n_specs; ++spec) {
    msg.msg_name = (void*) spec->dest_sa;
    if (spec->dest_sa->sa_family == AF_INET) {
      msg.msg_namelen = sizeof(struct sockaddr_in);
    } else {
      msg.msg_namelen = sizeof(struct sockaddr_in6);
    }

    msg.msg_iov = spec->iov;
    msg.msg_iovlen = spec->iovlen;

    constexpr size_t ecn_size = sizeof(int);
    constexpr size_t max_control_size = CMSG_SPACE(ecn_size);
    auto control = std::array<unsigned char, max_control_size>{};
    if (spec->ecn) {
      msg.msg_control = control.data();
      msg.msg_controllen = control.size();

      cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
      if (spec->dest_sa->sa_family == AF_INET) {
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_PKTINFO;
      } else {
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_TCLASS;
      }
      cmsg->cmsg_len = CMSG_LEN(ecn_size);
      ::memcpy(CMSG_DATA(cmsg), &spec->ecn, ecn_size);
      msg.msg_controllen = CMSG_SPACE(ecn_size);
    } else {
      msg.msg_controllen = 0;
      msg.msg_control = nullptr;
    }

    // possible to use io_uring for these writes? would probably need to wait on
    // io_uring_wait_cqe() in this function while 'specs' are still valid, but
    // the timer's completion would recurse into lsquic_engine_process_conns()
    int ret = ::sendmsg(sockfd, &msg, 0);
    if (ret == -1) {
      const auto ec = error_code{errno, system_category()};
      if (ec == errc::resource_unavailable_try_again ||
          ec == errc::operation_would_block) {
        // lsquic won't call our send_packets() callback again until we call
        // lsquic_engine_send_unsent_packets()
        // poll for the socket to become writeable again, so we can call that
        auto sqe = ::io_uring_get_sqe(&ring); assert(sqe);
        ::io_uring_prep_poll_add(sqe, sockfd, POLLOUT);
        const auto type = static_cast<intptr_t>(request_type::poll);
        ::io_uring_sqe_set_data(sqe, reinterpret_cast<void*>(type));
        ::io_uring_submit(&ring);
      }
      break;
    }

    ++num_sent;
  }
  return num_sent > 0 ? num_sent : -1;
}


// stream api
static lsquic_conn_ctx_t* on_new_conn(void* ectx, lsquic_conn_t* conn)
{
  auto estate = static_cast<engine_state*>(ectx);
  auto cctx = ::lsquic_conn_get_ctx(conn);
  auto cstate = reinterpret_cast<connection_state*>(cctx);
  estate->on_connection_open(*cstate, conn);
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
  auto& sstate = estate->on_stream_open(*cstate, stream);
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
  sstate->conn.engine.on_stream_close(*sstate);
}

static void on_conn_closed(lsquic_conn_t* conn)
{
  auto cctx = ::lsquic_conn_get_ctx(conn);
  auto cstate = reinterpret_cast<connection_state*>(cctx);
  cstate->engine.on_connection_close(*cstate, conn);
}

constexpr lsquic_stream_if make_client_stream_api()
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

static int client_send_packets(void* ectx, const lsquic_out_spec *specs,
                        unsigned n_specs)
{
  auto estate = static_cast<engine_state*>(ectx);
  return estate->send_packets(specs, n_specs);
}

engine_state::engine_state(unsigned flags)
{
  error_code ec;
  sockfd = setup_socket(local_addr, ec);
  if (ec) {
    throw system_error(ec);
  }

  timerfd = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
  if (timerfd == -1) {
    ec.assign(errno, system_category());
    ::perror("timerfd_create");
    ::close(sockfd);
    throw system_error(ec);
  }

  if (int r = ::io_uring_queue_init(ring_queue_depth, &ring, 0); r < 0) {
    ec.assign(-r, system_category());
    ::close(sockfd);
    ::close(timerfd);
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
  api.ea_settings = &settings;
  handle.reset(::lsquic_engine_new(flags, &api));

  start_recv();
}

void connection_state::open_stream(stream_state& sstate, error_code& ec)
{
  stream_open_request req;
  engine.stream_open(sstate, req);
  ec = *req.ec;
}

void connection_state::close(error_code& ec)
{
  conn_close_request req;
  engine.connection_close(*this, req);
  ec = *req.ec;
}

} // namespace quic::detail
} // namespace nexus
