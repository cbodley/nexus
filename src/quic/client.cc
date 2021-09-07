#include <nexus/quic/detail/client.hpp>

namespace nexus::quic::detail {

client_connection_state::~client_connection_state()
{
  std::cerr << "~client_connection_state " << this << std::endl;
  if (handle) {
    lsquic_conn_set_ctx(handle, nullptr);
  }
  while (!opening_streams.empty()) {
    auto& stream = opening_streams.front();
    opening_streams.pop_front();
    // drop the stream_state reference from open()
    intrusive_ptr_release(&stream);
  }
}

auto client_connection_state::open_stream()
    -> boost::intrusive_ptr<stream_state>
{
  auto stream = boost::intrusive_ptr<stream_state>(new stream_state(engine));
  // hold an extra reference on the stream_state while it's in opening_streams
  intrusive_ptr_add_ref(stream.get());
  opening_streams.push_back(*stream);
  lsquic_conn_make_stream(handle);
  engine.reschedule();
  return stream;
}

void client_connection_state::close()
{
  std::cerr << "client_connection_state close " << this << std::endl;
  if (handle) {
    lsquic_conn_close(handle);
    engine.reschedule();
  }
}

void client_connection_state::on_open(lsquic_conn_t* conn)
{
  std::cerr << "client_connection_state on_open " << this << std::endl;
  handle = conn;
  for (const auto& s : opening_streams) {
    lsquic_conn_make_stream(handle);
  }
}

void client_connection_state::on_close()
{
  std::cerr << "client_connection_state on_close " << this << std::endl;
  while (!opening_streams.empty()) {
    auto& stream = opening_streams.front();
    opening_streams.pop_front();

    error_code ec_ignored;
    stream.close(ec_ignored);
    // drop the stream_state reference from open()
    intrusive_ptr_release(&stream);
  }
  handle = nullptr;
  engine.on_conn_close();
}

auto client_connection_state::on_new_stream(lsquic_stream_t* stream)
    -> boost::intrusive_ptr<stream_state>
{
  std::cerr << "client_connection_state on_new_stream " << this << std::endl;
  // XXX: what if the server initiates a stream?
  if (opening_streams.empty()) {
    return nullptr;
  }
  auto& s = opening_streams.front();
  opening_streams.pop_front();
  s.on_open(stream);
  // adopt the reference we took in open(), and return it to the stream api
  constexpr bool add_ref = false;
  return boost::intrusive_ptr<stream_state>{&s, add_ref};
}


// client stream api
static lsquic_conn_ctx_t* on_new_conn(void* ectx, lsquic_conn_t* conn)
{
  std::cerr << "client on_new_conn" << std::endl;
  auto estate = static_cast<client_engine_state*>(ectx);
  auto cctx = lsquic_conn_get_ctx(conn);
  if (!cctx) {
    return nullptr;
  }
  auto cstate = reinterpret_cast<client_connection_state*>(cctx);
  cstate->on_open(conn);
  return cctx;
}

static lsquic_stream_ctx_t* on_new_stream(void* ectx, lsquic_stream_t* stream)
{
  std::cerr << "client on_new_stream" << std::endl;
  auto estate = static_cast<client_engine_state*>(ectx);
  if (stream == nullptr) {
    return nullptr; // connection went away?
  }
  auto conn = lsquic_stream_conn(stream);
  auto cctx = lsquic_conn_get_ctx(conn);
  if (!cctx) {
    return nullptr;
  }
  auto cstate = reinterpret_cast<client_connection_state*>(cctx);
  auto sstate = cstate->on_new_stream(stream);
  // lsquic holds a pointer to stream_state in lsquic_stream_ctx_t, so we keep
  // this extra reference until on_close()
  return reinterpret_cast<lsquic_stream_ctx_t*>(sstate.detach());
}

static void on_read(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
{
  std::cerr << "client on_read" << std::endl;
  auto sstate = reinterpret_cast<stream_state*>(sctx);
  sstate->on_read();
}

static void on_write(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
{
  std::cerr << "client on_write" << std::endl;
  auto sstate = reinterpret_cast<stream_state*>(sctx);
  sstate->on_write();
}

static void on_close(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
{
  std::cerr << "client on_close" << std::endl;
  auto sstate = reinterpret_cast<stream_state*>(sctx);
  sstate->on_close();
  // lsquic is done with this lsquic_stream_ctx_t, so we can drop the
  // stream_state reference we took for it in on_new_stream()
  intrusive_ptr_release(sstate);
}

static void on_conn_closed(lsquic_conn_t* conn)
{
  std::cerr << "client on_conn_closed" << std::endl;
  if (auto cctx = lsquic_conn_get_ctx(conn); cctx) {
    auto cstate = reinterpret_cast<client_connection_state*>(cctx);
    cstate->on_close();
  }
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
  auto estate = static_cast<client_engine_state*>(ectx);
  return estate->send_packets(specs, n_specs);
}


// client_engine_state
auto client_engine_state::connect(const udp::endpoint& remote_endpoint,
             const char* remote_hostname)
    -> boost::intrusive_ptr<client_connection_state>
{
  auto conn = boost::intrusive_ptr<client_connection_state>{
      new client_connection_state(*this)};
  auto cctx = reinterpret_cast<lsquic_conn_ctx_t*>(conn.get());
  conn->handle = lsquic_engine_connect(handle.get(),
      N_LSQVER, local_endpoint.data(), remote_endpoint.data(),
      this, cctx, remote_hostname, 0, nullptr, 0, nullptr, 0);
  if (++num_connections == 1) {
    // first connection opened
    recv();
  }
  reschedule();
  return conn;
}

void client_engine_state::on_conn_close()
{
  if (--num_connections == 0) { // last connection closed
    // cancel pending async_wait() from recv()
    socket.cancel();
  }
}

auto client_engine_state::create(const boost::asio::executor& ex, unsigned flags)
    -> boost::intrusive_ptr<client_engine_state>
{
  auto state = boost::intrusive_ptr<client_engine_state>{
      new client_engine_state(ex)};
  {
    error_code ec_ignored;
    state->enable_tos(ec_ignored); // send and receive ECN
  }
  lsquic_engine_settings settings;
  lsquic_engine_init_settings(&settings, flags);

  lsquic_engine_api api = {};
  api.ea_packets_out = client_send_packets;
  api.ea_packets_out_ctx = state.get();
  static const lsquic_stream_if stream_api = make_client_stream_api();
  api.ea_stream_if = &stream_api;
  api.ea_stream_if_ctx = state.get();
  api.ea_settings = &settings;
  state->handle.reset(lsquic_engine_new(flags, &api));

  state->recv();
  state->reschedule();
  return state;
}

} // namespace nexus::quic::detail
