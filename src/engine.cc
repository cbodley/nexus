#include <lsquic.h>
#include <lsxpack_header.h>

#include <nexus/quic/detail/connection_impl.hpp>
#include <nexus/quic/detail/engine_impl.hpp>
#include <nexus/quic/detail/socket_impl.hpp>
#include <nexus/quic/detail/stream_impl.hpp>
#include <nexus/quic/socket.hpp>

#include "recv_header_set.hpp"

namespace nexus::quic::detail {

void engine_deleter::operator()(lsquic_engine* e) const {
  ::lsquic_engine_destroy(e);
}

engine_impl::~engine_impl()
{
  close();
}

udp::endpoint engine_impl::remote_endpoint(connection_impl& c)
{
  auto remote = udp::endpoint{};
  auto lock = std::scoped_lock{mutex};
  if (c.handle) {
    const sockaddr* l = nullptr;
    const sockaddr* r = nullptr;
    lsquic_conn_get_sockaddr(c.handle, &l, &r);
    if (r->sa_family == AF_INET6) {
      ::memcpy(remote.data(), r, sizeof(sockaddr_in6));
    } else {
      ::memcpy(remote.data(), r, sizeof(sockaddr_in));
    }
  }
  return remote;
}

void engine_impl::connect(connection_impl& c,
                          const udp::endpoint& endpoint,
                          const char* hostname)
{
  auto lock = std::unique_lock{mutex};
  auto peer_ctx = &c.socket;
  auto cctx = reinterpret_cast<lsquic_conn_ctx_t*>(&c);
  assert(!c.handle);
  ::lsquic_engine_connect(handle.get(), N_LSQVER,
      c.socket.local_addr.data(), endpoint.data(), peer_ctx, cctx,
      hostname, 0, nullptr, 0, nullptr, 0);
  // note, this assert triggers with some quic versions that don't allow
  // multiple connections on the same address, see lquic's hash_conns_by_addr()
  assert(c.handle); // lsquic_engine_connect() calls on_connect()
  process(lock);
  if (client) { // make sure we're listening
    start_recv(*client);
  }
}

void engine_impl::on_connect(connection_impl& c, lsquic_conn_t* conn)
{
  assert(!c.handle);
  c.handle = conn;
  c.socket.connected.push_back(c);
}

void engine_impl::on_handshake(connection_impl& c, int s)
{
  switch (s) {
    case LSQ_HSK_FAIL:
    case LSQ_HSK_RESUMED_FAIL:
      if (!c.err) {
        // set a generic connection handshake error. we may get a more specific
        // error from CONNECTION_CLOSE before the on_conn_closed() callback
        // delivers this error to the application
        c.err = make_error_code(connection_error::handshake_failed);
      }
      break;
  }
}

void engine_impl::accept(connection_impl& c, accept_operation& op)
{
  auto lock = std::unique_lock{mutex};
  if (!c.socket.incoming_connections.empty()) {
    c.handle = c.socket.incoming_connections.front();
    c.socket.incoming_connections.pop_front();
    c.socket.connected.push_back(c);
    auto ctx = reinterpret_cast<lsquic_conn_ctx_t*>(&c);
    ::lsquic_conn_set_ctx(c.handle, ctx);
    op.post(error_code{}); // success
    return;
  }
  assert(!c.accept_);
  c.accept_ = &op;
  c.socket.accepting_connections.push_back(c);
  process(lock);
}

connection_impl* engine_impl::on_accept(lsquic_conn_t* conn)
{
  const sockaddr* local = nullptr;
  const sockaddr* peer = nullptr;
  int r = ::lsquic_conn_get_sockaddr(conn, &local, &peer);
  if (r != 0) {
    return nullptr;
  }
  // get the peer_ctx from our call to lsquic_engine_packet_in()
  auto peer_ctx = ::lsquic_conn_get_peer_ctx(conn, local);
  assert(peer_ctx);
  auto& socket = *static_cast<socket_impl*>(peer_ctx);
  if (socket.accepting_connections.empty()) {
    // not waiting on accept, try to queue this for later
    if (socket.incoming_connections.full()) {
      ::lsquic_conn_close(conn);
    } else {
      socket.incoming_connections.push_back(conn);
    }
    return nullptr;
  }
  auto& c = socket.accepting_connections.front();
  socket.accepting_connections.pop_front();
  socket.connected.push_back(c);
  assert(!c.handle);
  c.handle = conn;
  assert(c.accept_);
  c.accept_->defer(error_code{}); // success
  c.accept_ = nullptr;
  return &c;
}

bool engine_impl::is_open(const connection_impl& c) const
{
  auto lock = std::scoped_lock{mutex};
  return c.handle;
}

void engine_impl::close(connection_impl& c, error_code& ec)
{
  auto lock = std::unique_lock{mutex};
  const auto aborted = make_error_code(connection_error::aborted);
  if (c.accept_) {
    assert(c.is_linked());
    auto& accepting = c.socket.accepting_connections;
    accepting.erase(accepting.iterator_to(c));
    auto op = std::exchange(c.accept_, nullptr);
    op->defer(aborted);
  }
  if (!c.handle) {
    ec = make_error_code(errc::not_connected);
    return;
  }

  cancel(c, aborted);

  ::lsquic_conn_close(c.handle);
  c.handle = nullptr;

  assert(c.is_linked());
  auto& connected = c.socket.connected;
  connected.erase(connected.iterator_to(c));

  process(lock);
}

int engine_impl::cancel(connection_impl& c, error_code ec)
{
  int canceled = 0;
  // close incoming streams that we haven't accepted yet
  while (!c.incoming_streams.empty()) {
    // take ownership of the stream and free on scope exit
    auto s = std::unique_ptr<stream_impl>{&c.incoming_streams.front()};
    c.incoming_streams.pop_front();
    assert(s->conn);
    s->conn = nullptr;
    [[maybe_unused]] auto t = stream_state::on_error(s->state, ec);
    assert(t == stream_state::transition::incoming_to_closed);
  }
  // cancel pending stream connect/accept
  while (!c.connecting_streams.empty()) {
    auto s = std::unique_ptr<stream_impl>{&c.connecting_streams.front()};
    c.connecting_streams.pop_front();
    assert(s->conn);
    s->conn = nullptr;
    [[maybe_unused]] auto t = stream_state::on_error(s->state, ec);
    assert(t == stream_state::transition::connecting_to_closed);
    canceled++;
  }
  while (!c.accepting_streams.empty()) {
    auto s = std::unique_ptr<stream_impl>{&c.accepting_streams.front()};
    c.accepting_streams.pop_front();
    assert(s->conn);
    s->conn = nullptr;
    [[maybe_unused]] auto t = stream_state::on_error(s->state, ec);
    assert(t == stream_state::transition::accepting_to_closed);
    canceled++;
  }
  // close connected streams
  while (!c.open_streams.empty()) {
    auto& s = c.open_streams.front();
    c.open_streams.pop_front();
    assert(s.conn);
    s.conn = nullptr;
    [[maybe_unused]] auto t = stream_state::on_error(s.state, ec);
    assert(t == stream_state::transition::open_to_closed ||
           t == stream_state::transition::open_to_error);
    canceled++;
  }
  // cancel closing streams
  while (!c.closing_streams.empty()) {
    auto& s = c.closing_streams.front();
    c.closing_streams.pop_front();
    assert(s.conn);
    s.conn = nullptr;
    [[maybe_unused]] auto t = stream_state::on_error(s.state, ec);
    assert(t == stream_state::transition::closing_to_closed);
    canceled++;
  }
  return canceled;
}

void engine_impl::on_close(connection_impl& c, lsquic_conn_t* conn)
{
  if (!c.handle) {
    return;
  }
  assert(c.handle == conn);
  c.handle = nullptr;

  assert(c.accept_ == nullptr);
  assert(c.is_linked());
  auto& connected = c.socket.connected;
  connected.erase(connected.iterator_to(c));

  // we may already have an error from on_handshake() or on_conncloseframe()
  error_code ec = c.err;
  if (!ec) {
    // use lsquic_conn_status() to choose the most relevant error code
    const auto status = ::lsquic_conn_status(conn, nullptr, 0);
    switch (status) {
      case LSCONN_ST_VERNEG_FAILURE:
      case LSCONN_ST_HSK_FAILURE:
        ec = make_error_code(connection_error::handshake_failed);
        break;
      case LSCONN_ST_TIMED_OUT:
        ec = make_error_code(connection_error::timed_out);
        break;
      case LSCONN_ST_PEER_GOING_AWAY:
        ec = make_error_code(connection_error::going_away);
        break;
      case LSCONN_ST_USER_ABORTED:
      case LSCONN_ST_CLOSED:
        ec = make_error_code(connection_error::aborted);
        break;
      case LSCONN_ST_ERROR:
      case LSCONN_ST_RESET:
      default:
        ec = make_error_code(connection_error::reset);
        break;
    }
  }

  const int canceled = cancel(c, ec);
  if (canceled) {
    // clear the connection error if we delivered it to the application
    c.err = error_code{};
  }
}

void engine_impl::on_conncloseframe(connection_impl& c,
                                    int app_error, uint64_t code)
{
  error_code ec;
  if (app_error == -1) {
    ec = make_error_code(connection_error::reset);
  } else if (app_error) {
    ec.assign(code, application_category());
  } else if ((code & 0xffff'ffff'ffff'ff00) == 0x0100) {
    // CRYPTO_ERROR 0x0100-0x01ff
    ec.assign(code & 0xff, tls_category());
  } else {
    ec.assign(code, transport_category());
  }

  c.err = ec;
}

stream_impl* engine_impl::on_new_stream(connection_impl& c,
                                        lsquic_stream_t* stream)
{
  // XXX: any way to decide between connect/accept without stream id?
  const auto id = ::lsquic_stream_id(stream);
  const int server = !client;
  if ((id & 1) == server) { // self-initiated
    return c.on_connect(stream);
  } else { // peer-initiated
    return c.on_accept(stream);
  }
}

void engine_impl::close()
{
  auto lock = std::unique_lock{mutex};
  ::lsquic_engine_cooldown(handle.get());
  process(lock);
}

void engine_impl::listen(socket_impl& socket, int backlog)
{
  auto lock = std::unique_lock{mutex};
  socket.incoming_connections.set_capacity(backlog);
  start_recv(socket);
}

void engine_impl::close(socket_impl& socket)
{
  auto lock = std::unique_lock{mutex};
  // close incoming streams that we haven't accepted yet
  while (!socket.incoming_connections.empty()) {
    auto conn = socket.incoming_connections.front();
    socket.incoming_connections.pop_front();
    ::lsquic_conn_close(conn);
  }
  const auto ecanceled = make_error_code(connection_error::aborted);
  // close connections on this socket
  while (!socket.connected.empty()) {
    auto& c = socket.connected.front();
    socket.connected.pop_front();

    ::lsquic_conn_close(c.handle);
    c.handle = nullptr;

    cancel(c, ecanceled);
  }
  // send any CONNECTION_CLOSE frames before closing the socket
  process(lock);
  // cancel connections pending accept
  while (!socket.accepting_connections.empty()) {
    auto& c = socket.accepting_connections.front();
    socket.accepting_connections.pop_front();
    assert(c.accept_);
    c.accept_->defer(ecanceled);
    c.accept_ = nullptr;
  }
  socket.receiving = false;
  socket.socket.close();
}

void engine_impl::process(std::unique_lock<std::mutex>& lock)
{
  ::lsquic_engine_process_conns(handle.get());
  reschedule(lock);
}

void engine_impl::reschedule(std::unique_lock<std::mutex>& lock)
{
  int micros = 0;
  if (!::lsquic_engine_earliest_adv_tick(handle.get(), &micros)) {
    // no connections to process. servers should keep listening for packets,
    // but clients can stop reading
    if (client && client->receiving) {
      client->receiving = false;
      client->socket.cancel();
    }
    timer.cancel();
    return;
  }
  if (micros <= 0) {
    process(lock);
    return;
  }
  const auto dur = std::chrono::microseconds{micros};
  timer.expires_after(dur);
  timer.async_wait([this] (error_code ec) {
        if (!ec) {
          on_timer();
        }
      });
}

void engine_impl::on_timer()
{
  auto lock = std::unique_lock{mutex};
  process(lock);
}

void engine_impl::start_recv(socket_impl& socket)
{
  if (socket.receiving) {
    return;
  }
  socket.receiving = true;
  socket.socket.async_wait(udp::socket::wait_read,
      [this, &socket] (error_code ec) {
        socket.receiving = false;
        if (!ec) {
          on_readable(socket);
        } // XXX: else fatal? retry?
      });
}

void engine_impl::on_readable(socket_impl& socket)
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

    const auto bytes = socket.recv_packet(iov, peer, self, ecn, ec);
    if (ec) {
      if (ec == errc::resource_unavailable_try_again ||
          ec == errc::operation_would_block) {
        start_recv(socket);
      } // XXX: else fatal? retry?
      return;
    }

    auto lock = std::unique_lock{mutex};
    ::lsquic_engine_packet_in(handle.get(), buffer.data(), bytes,
                              &self.addr, peer.data(), &socket, ecn);
    process(lock);
  }
}

void engine_impl::on_writeable(socket_impl&)
{
  auto lock = std::scoped_lock{mutex};
  ::lsquic_engine_send_unsent_packets(handle.get());
}

int engine_impl::send_packets(const lsquic_out_spec* specs, unsigned n_specs)
{
  auto p = specs;
  const auto end = std::next(p, n_specs);
  while (p < end) {
    socket_impl& socket = *static_cast<socket_impl*>(p->peer_ctx);
    error_code ec;
    p = socket.send_packets(p, end, ec);
    if (ec) {
      if (ec == errc::resource_unavailable_try_again ||
          ec == errc::operation_would_block) {
        // lsquic won't call our send_packets() callback again until we call
        // lsquic_engine_send_unsent_packets()
        // wait for the socket to become writeable again, so we can call that
        socket.socket.async_wait(udp::socket::wait_write,
            [this, &socket] (error_code ec) {
              if (!ec) {
                on_writeable(socket);
              } // else fatal?
            });
        errno = ec.value(); // lsquic needs to see this errno
      }
      break;
    }
  }
  return std::distance(specs, p);
}


// stream api
static lsquic_conn_ctx_t* on_new_conn(void* ectx, lsquic_conn_t* conn)
{
  auto estate = static_cast<engine_impl*>(ectx);
  auto cctx = ::lsquic_conn_get_ctx(conn);
  // outgoing connections will have a context set by lsquic_engine_connect()
  if (!cctx) {
    auto c = estate->on_accept(conn);
    return reinterpret_cast<lsquic_conn_ctx_t*>(c);
  }
  auto c = reinterpret_cast<connection_impl*>(cctx);
  estate->on_connect(*c, conn);
  return cctx;
}

static lsquic_stream_ctx_t* on_new_stream(void* ectx, lsquic_stream_t* stream)
{
  auto estate = static_cast<engine_impl*>(ectx);
  if (stream == nullptr) {
    return nullptr; // connection went away?
  }
  auto conn = ::lsquic_stream_conn(stream);
  auto cctx = ::lsquic_conn_get_ctx(conn);
  auto c = reinterpret_cast<connection_impl*>(cctx);
  auto s = estate->on_new_stream(*c, stream);
  return reinterpret_cast<lsquic_stream_ctx_t*>(s);
}

static void on_read(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
{
  auto s = reinterpret_cast<stream_impl*>(sctx);
  s->on_read();
}

static void on_write(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
{
  auto s = reinterpret_cast<stream_impl*>(sctx);
  s->on_write();
}

static void on_close(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
{
  auto s = reinterpret_cast<stream_impl*>(sctx);
  if (s) {
    s->on_close();
  }
}

static void on_conn_closed(lsquic_conn_t* conn)
{
  auto cctx = ::lsquic_conn_get_ctx(conn);
  if (!cctx) {
    return;
  }
  auto c = reinterpret_cast<connection_impl*>(cctx);
  c->socket.engine.on_close(*c, conn);
}

static void on_hsk_done(lsquic_conn_t* conn, lsquic_hsk_status s)
{
  auto cctx = ::lsquic_conn_get_ctx(conn);
  if (!cctx) {
    return;
  }
  auto c = reinterpret_cast<connection_impl*>(cctx);
  c->socket.engine.on_handshake(*c, s);
}

void on_conncloseframe_received(lsquic_conn_t* conn,
                                int app_error, uint64_t code,
                                const char* reason, int reason_len)
{
  auto cctx = ::lsquic_conn_get_ctx(conn);
  if (!cctx) {
    return;
  }
  auto c = reinterpret_cast<connection_impl*>(cctx);
  c->socket.engine.on_conncloseframe(*c, app_error, code);
}

static constexpr lsquic_stream_if make_stream_api()
{
  lsquic_stream_if api = {};
  api.on_new_conn = on_new_conn;
  api.on_conn_closed = on_conn_closed;
  api.on_new_stream = on_new_stream;
  api.on_read = on_read;
  api.on_write = on_write;
  api.on_close = on_close;
  api.on_hsk_done = on_hsk_done;
  api.on_conncloseframe_received = on_conncloseframe_received;
  return api;
}


// header set api
static void* header_set_create(void* ctx, lsquic_stream_t* stream,
                               int is_push_promise)
{
  // TODO: store this in stream_impl to avoid allocation?
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
    const bool never_index = hdr->flags & LSXPACK_NEVER_INDEX;
    auto f = headers->fields.insert(name, value, never_index);
  }
  return 0;
}

static void header_set_discard(void* hset)
{
  delete reinterpret_cast<recv_header_set*>(hset);
}

static constexpr lsquic_hset_if make_header_api()
{
  lsquic_hset_if api = {};
  api.hsi_create_header_set  = header_set_create;
  api.hsi_prepare_decode = header_set_prepare;
  api.hsi_process_header = header_set_process;
  api.hsi_discard_header_set = header_set_discard;
  return api;
}

static int api_send_packets(void* ectx, const lsquic_out_spec *specs,
                            unsigned n_specs)
{
  auto estate = static_cast<engine_impl*>(ectx);
  return estate->send_packets(specs, n_specs);
}

ssl_ctx_st* api_peer_ssl_ctx(void* peer_ctx, const sockaddr* local)
{
  auto& socket = *static_cast<socket_impl*>(peer_ctx);
  return socket.ssl.native_handle();
}

engine_impl::engine_impl(const asio::any_io_executor& ex,
                         socket_impl* client, const settings* s,
                         unsigned flags)
  : ex(ex), timer(ex), client(client)
{
  lsquic_engine_api api = {};
  api.ea_packets_out = api_send_packets;
  api.ea_packets_out_ctx = this;
  static const lsquic_stream_if stream_api = make_stream_api();
  api.ea_stream_if = &stream_api;
  api.ea_stream_if_ctx = this;
  api.ea_get_ssl_ctx = api_peer_ssl_ctx;
  if (flags & LSENG_HTTP) {
    static const lsquic_hset_if header_api = make_header_api();
    api.ea_hsi_if = &header_api;
    api.ea_hsi_ctx = this;
    is_http = true;
  }

  // apply and validate the settings
  lsquic_engine_settings es;
  ::lsquic_engine_init_settings(&es, flags);
  if (s) {
    write_settings(*s, es);
  }
  es.es_versions = (1 << LSQVER_I001); // RFC version only
  char errbuf[256];
  int r = ::lsquic_engine_check_settings(&es, flags, errbuf, sizeof(errbuf));
  if (r == -1) {
    throw bad_setting(errbuf);
  }
  es.es_delay_onclose = 1;
  api.ea_settings = &es;

  handle.reset(::lsquic_engine_new(flags, &api));
}

} // namespace nexus::quic::detail
