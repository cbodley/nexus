#include <nexus/h3/server.hpp>
#include <gtest/gtest.h>
#include <optional>
#include <lsquic.h>
#include <openssl/ssl.h>
#include <nexus/h3/client.hpp>
#include <nexus/h3/stream.hpp>
#include <nexus/global_init.hpp>

#include "certificate.hpp"

namespace nexus {

namespace {

const error_code ok;

auto capture(std::optional<error_code>& ec) {
  return [&] (error_code e, size_t = 0) { ec = e; };
}

} // anonymous namespace

// shutdown for 0, 1, or 2
// 
// shutdown before operation
// shutdown during pending operation
// remote shutdown before operation
// remote shutdown during pending operation
//
// read_some
// write_some
// read_headers
// write_headers
// flush
// shutdown
// close

// shutdown for read after read_some -> EBADF
// shutdown for write after read_some -> ok

class Stream : public testing::Test {
 public:
  static constexpr const char* alpn = "\02h3";

  asio::io_context context;
  global::context global;

  asio::ssl::context ssl;
  asio::ssl::context sslc;

  h3::server server;
  asio::ip::address localhost;
  h3::acceptor acceptor;
  h3::server_connection sconn;
  h3::stream sstream;

  h3::client client;
  h3::client_connection cconn;
  h3::stream cstream;

  Stream()
      : global(global::init_client_server()),
        ssl(test::init_server_context(alpn)),
        sslc(test::init_client_context(alpn)),
        server(context.get_executor()),
        localhost(asio::ip::make_address("127.0.0.1")),
        acceptor(server, udp::endpoint{localhost, 0}, ssl),
        sconn(acceptor),
        client(context.get_executor(), udp::endpoint{}, sslc),
        cconn(client, acceptor.local_endpoint(), "host")
  {}

  void SetUp() override
  {
    //global.log_to_stderr("debug");
    acceptor.listen(16);

    std::optional<error_code> accept_ec;
    acceptor.async_accept(sconn, capture(accept_ec));

    context.poll();
    ASSERT_FALSE(context.stopped());
    ASSERT_TRUE(accept_ec);
    EXPECT_EQ(ok, *accept_ec);

    std::optional<error_code> sstream_accept_ec;
    sconn.async_accept(sstream, capture(sstream_accept_ec));

    std::optional<error_code> cstream_connect_ec;
    cconn.async_connect(cstream, capture(cstream_connect_ec));

    context.poll();
    ASSERT_FALSE(context.stopped());
    ASSERT_TRUE(cstream_connect_ec);
    EXPECT_EQ(ok, *cstream_connect_ec);

    // the server won't see this stream until we write a packet for it
    std::optional<error_code> cstream_write_headers_ec;
    auto request = h3::fields{};
    request.insert("salad", "potato");
    cstream.async_write_headers(request, capture(cstream_write_headers_ec));
    cstream.flush(); // force the connection to send the HEADERS

    context.poll();
    ASSERT_FALSE(context.stopped());
    ASSERT_TRUE(cstream_write_headers_ec);
    EXPECT_EQ(ok, *cstream_write_headers_ec);
    ASSERT_TRUE(sstream_accept_ec);
    EXPECT_EQ(ok, *sstream_accept_ec);
  }
};

TEST_F(Stream, shutdown_pending_read_headers)
{
  auto fields = h3::fields{};
  std::optional<error_code> read_headers_ec;
  cstream.async_read_headers(fields, capture(read_headers_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_FALSE(read_headers_ec);

  cstream.shutdown(0);

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(read_headers_ec);
  EXPECT_EQ(errc::bad_file_descriptor, *read_headers_ec);
}

TEST_F(Stream, remote_shutdown_pending_read_headers)
{
  auto fields = h3::fields{};
  std::optional<error_code> read_headers_ec;
  cstream.async_read_headers(fields, capture(read_headers_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_FALSE(read_headers_ec);

  sstream.shutdown(1);

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(read_headers_ec);
  EXPECT_EQ(quic::error::stream_reset, *read_headers_ec);
}

TEST_F(Stream, shutdown_before_read_headers)
{
  cstream.shutdown(0);

  context.poll();
  ASSERT_FALSE(context.stopped());

  auto fields = h3::fields{};
  std::optional<error_code> read_headers_ec;
  cstream.async_read_headers(fields, capture(read_headers_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(read_headers_ec);
  EXPECT_EQ(errc::bad_file_descriptor, *read_headers_ec);
}


TEST_F(Stream, remote_shutdown_before_read_headers)
{
  sstream.shutdown(1);

  context.poll();
  ASSERT_FALSE(context.stopped());

  auto fields = h3::fields{};
  std::optional<error_code> read_headers_ec;
  cstream.async_read_headers(fields, capture(read_headers_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(read_headers_ec);
  EXPECT_EQ(errc::bad_file_descriptor, *read_headers_ec);
}

TEST_F(Stream, shutdown_pending_read)
{
  auto data = std::array<char, 16>{};
  std::optional<error_code> cstream_read_ec;
  cstream.async_read_some(asio::buffer(data), capture(cstream_read_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_FALSE(cstream_read_ec);

  cstream.shutdown(0);

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(cstream_read_ec);
  EXPECT_EQ(errc::bad_file_descriptor, *cstream_read_ec);
}

TEST_F(Stream, shutdown_before_read)
{
  cstream.shutdown(0);

  context.poll();
  ASSERT_FALSE(context.stopped());

  auto data = std::array<char, 16>{};
  std::optional<error_code> cstream_read_ec;
  cstream.async_read_some(asio::buffer(data), capture(cstream_read_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(cstream_read_ec);
  EXPECT_EQ(errc::bad_file_descriptor, *cstream_read_ec);
}

TEST_F(Stream, shutdown_pending_write)
{
  const auto data = std::array<char, 65536>{};
  std::optional<error_code> cstream_write_ec;
  // async_write_some() won't block as long as the stream is writeable. keep
  // writing until we fill the flow control window and block
  do {
    cstream_write_ec = std::nullopt;
    cstream.async_write_some(asio::buffer(data), capture(cstream_write_ec));
    context.poll();
    ASSERT_FALSE(context.stopped());
  } while (cstream_write_ec);

  cstream.shutdown(1);
  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(cstream_write_ec);
  EXPECT_EQ(errc::bad_file_descriptor, *cstream_write_ec);
}

TEST_F(Stream, shutdown_before_write)
{
  cstream.shutdown(1);

  const auto data = std::array<char, 16>{};
  std::optional<error_code> cstream_write_ec;
  cstream.async_write_some(asio::buffer(data), capture(cstream_write_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(cstream_write_ec);
  EXPECT_EQ(errc::bad_file_descriptor, *cstream_write_ec);
}

TEST_F(Stream, shutdown_after_close)
{
  cstream.close();

  error_code shutdown_ec;
  cstream.shutdown(0, shutdown_ec);
  EXPECT_EQ(errc::bad_file_descriptor, shutdown_ec);
}

TEST_F(Stream, shutdown_after_remote_shutdown)
{
  sstream.shutdown(1);

  context.poll();
  ASSERT_FALSE(context.stopped());

  error_code shutdown_ec;
  cstream.shutdown(0, shutdown_ec);
  EXPECT_EQ(ok, shutdown_ec);
}

TEST_F(Stream, shutdown_after_remote_close)
{
  sstream.close();

  context.poll();
  ASSERT_FALSE(context.stopped());

  error_code shutdown_ec;
  cstream.shutdown(0, shutdown_ec);
  EXPECT_EQ(ok, shutdown_ec);
}

} // namespace nexus
