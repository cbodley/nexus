#include <nexus/quic/server.hpp>
#include <gtest/gtest.h>
#include <nexus/quic/stream.hpp>
#include <nexus/quic/global_context.hpp>

#include <lsquic.h>


namespace {
#if 0
// client stream api
struct test_client_engine {
  nexus::quic::detail::lsquic_engine_ptr handle;
  nexus::quic::sockaddr_union local_addr;
  nexus::quic::detail::file_descriptor fd;

  test_client_engine();

  void connect(const sockaddr* endpoint, const char* hostname) {
    ::lsquic_engine_connect(handle.get(), N_LSQVER,
        &local_addr.addr, endpoint, this, nullptr,
        hostname, 0, nullptr, 0, nullptr, 0);
  }
};

lsquic_conn_ctx_t* on_new_conn(void* ectx, lsquic_conn_t* conn)
{
  if (conn) {
    ::lsquic_conn_make_stream(conn);
  }
  return nullptr;
}

lsquic_stream_ctx_t* on_new_stream(void* ectx, lsquic_stream_t* stream)
{
  if (stream) {
    ::lsquic_stream_wantwrite(stream, 1);
  }
  return nullptr;
}

void on_read(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
{
  char buffer[64];
  ::lsquic_stream_read(stream, buffer, sizeof(buffer));
  ::lsquic_stream_close(stream);
}

void on_write(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
{
  constexpr auto message = std::string_view{"hello"};
  ::lsquic_stream_write(stream, message.data(), message.size());
  ::lsquic_stream_shutdown(stream, 1);
  ::lsquic_stream_wantread(stream, 1);
}

void on_close(lsquic_stream_t* stream, lsquic_stream_ctx_t* sctx)
{
  auto conn = ::lsquic_stream_conn(stream);
  ::lsquic_conn_close(conn);
}

void on_conn_closed(lsquic_conn_t* conn)
{
}

static constexpr lsquic_stream_if make_test_stream_api()
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

int test_send_packets(void* ectx, const lsquic_out_spec* specs, unsigned n_specs)
{
  auto engine = reinterpret_cast<test_client_engine*>(ectx);
  return nexus::quic::detail::send_udp_packets(*engine->fd, specs, n_specs);
}

test_client_engine::test_client_engine()
{
  lsquic_engine_api api = {};
  api.ea_packets_out = test_send_packets;
  static const lsquic_stream_if stream_api = make_test_stream_api();
  api.ea_stream_if = &stream_api;
  handle.reset(::lsquic_engine_new(0, &api));

  addrinfo hints = {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

  addrinfo* res = nullptr;
  int r = ::getaddrinfo(nullptr, "0", &hints, &res);
  if (r != 0) {
    // getaddrinfo() worth its own error category? nah
    ec = make_error_code(errc::invalid_argument);
    throw system_error(ec);
  }
  using addrinfo_ptr = std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)>;
  auto res_cleanup = addrinfo_ptr{res, &::freeaddrinfo};

  fd = nexus::quic::detail::bind_udp_socket(res, false, local_addr, ec);
  if (ec) {
    throw system_error(ec);
  }
}
#endif
} // anonymous namespace

TEST(server, accept_wait) // accept() before a connection is received
{
  auto global = nexus::quic::global::init_client_server();
  auto server = nexus::quic::server{nullptr, "0"};
  auto conn = nexus::quic::server_connection{server};
  conn.accept();
  auto stream = nexus::quic::stream{conn};
  stream.accept();
}

TEST(server, accept_ready) // accept() after a connection is received
{
}
