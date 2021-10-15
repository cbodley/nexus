#include <nexus/h3/server.hpp>
#include <gtest/gtest.h>
#include <optional>
#include <nexus/h3/client.hpp>
#include <nexus/h3/stream.hpp>
#include <nexus/global_init.hpp>
#include <lsquic.h>

#include "certificate.hpp"

namespace nexus {

namespace {

const error_code ok;

auto capture(std::optional<error_code>& ec) {
  return [&] (error_code e, size_t = 0) { ec = e; };
}

} // anonymous namespace

class Stream : public testing::Test {
 public:
  static constexpr const char* alpn = "\02h3";

  static quic::settings server_settings()
  {
    auto settings = quic::default_server_settings();
    settings.max_streams_per_connection = 2;
    settings.connection_flow_control_window = LSQUIC_MIN_FCW;
    settings.incoming_stream_flow_control_window = LSQUIC_MIN_FCW;
    return settings;
  }

  asio::io_context context;
  global::context global = global::init_client_server();

  asio::ssl::context ssl = test::init_server_context(alpn);
  asio::ssl::context sslc = test::init_client_context(alpn);

  h3::server server{context.get_executor(), server_settings()};
  asio::ip::address localhost = asio::ip::make_address("127.0.0.1");
  h3::acceptor acceptor{server, udp::endpoint{localhost, 0}, ssl};
  h3::server_connection sconn{acceptor};
  h3::stream sstream{sconn};

  h3::client client{context.get_executor(), udp::endpoint{}, sslc};
  h3::client_connection cconn{client, acceptor.local_endpoint(), "host"};
  h3::stream cstream{cconn};

  void SetUp() override
  {
    acceptor.listen(16);

    std::optional<error_code> cstream_connect_ec;
    cconn.async_connect(cstream, capture(cstream_connect_ec));

    context.poll();
    ASSERT_FALSE(context.stopped());
    ASSERT_TRUE(cstream_connect_ec);
    EXPECT_EQ(ok, *cstream_connect_ec);

    std::optional<error_code> accept_ec;
    acceptor.async_accept(sconn, capture(accept_ec));

    context.poll();
    ASSERT_FALSE(context.stopped());
    ASSERT_TRUE(accept_ec);
    EXPECT_EQ(ok, *accept_ec);

    std::optional<error_code> sstream_accept_ec;
    sconn.async_accept(sstream, capture(sstream_accept_ec));

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
  EXPECT_EQ(quic::stream_error::aborted, *read_headers_ec);
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
  EXPECT_EQ(quic::stream_error::eof, *read_headers_ec);
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

  auto f2 = h3::fields{};
  std::optional<error_code> read_headers2_ec;
  cstream.async_read_headers(f2, capture(read_headers2_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(read_headers2_ec);
  EXPECT_EQ(quic::stream_error::eof, *read_headers2_ec);
}

TEST_F(Stream, shutdown_pending_read)
{
  // must read headers before body
  auto f = h3::fields{};
  std::optional<error_code> read_headers_ec;
  sstream.async_read_headers(f, capture(read_headers_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(read_headers_ec);
  EXPECT_EQ(ok, *read_headers_ec);

  auto data = std::array<char, 16>{};
  std::optional<error_code> read_ec;
  sstream.async_read_some(asio::buffer(data), capture(read_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_FALSE(read_ec);

  sstream.shutdown(0);

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(read_ec);
  EXPECT_EQ(quic::stream_error::aborted, *read_ec);
}

TEST_F(Stream, shutdown_before_read)
{
  // must read headers before body
  auto f = h3::fields{};
  std::optional<error_code> read_headers_ec;
  sstream.async_read_headers(f, capture(read_headers_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(read_headers_ec);
  EXPECT_EQ(ok, *read_headers_ec);

  sstream.shutdown(0);

  context.poll();
  ASSERT_FALSE(context.stopped());

  auto data = std::array<char, 16>{};
  std::optional<error_code> read_ec;
  sstream.async_read_some(asio::buffer(data), capture(read_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(read_ec);
  EXPECT_EQ(errc::bad_file_descriptor, *read_ec);
}

TEST_F(Stream, shutdown_pending_write)
{
  // async_write_some() won't block as long as the stream is writeable. fill
  // the flow control window to make the second call block
  const auto data = std::array<char, LSQUIC_MIN_FCW>{};
  std::optional<error_code> cstream_write1_ec;
  cstream.async_write_some(asio::buffer(data), capture(cstream_write1_ec));
  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(cstream_write1_ec);
  EXPECT_EQ(ok, *cstream_write1_ec);

  std::optional<error_code> cstream_write2_ec;
  cstream.async_write_some(asio::buffer(data), capture(cstream_write2_ec));
  context.poll();
  ASSERT_FALSE(context.stopped());
  EXPECT_FALSE(cstream_write2_ec);

  cstream.shutdown(1);
  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(cstream_write2_ec);
  EXPECT_EQ(quic::stream_error::aborted, *cstream_write2_ec);
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

TEST_F(Stream, shutdown_pending_write_headers)
{
  // use cstream to fill the connection's write window
  const auto data = std::array<char, LSQUIC_MIN_FCW>{};
  std::optional<error_code> cstream_write_ec;
  cstream.async_write_some(asio::buffer(data), capture(cstream_write_ec));
  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(cstream_write_ec);
  EXPECT_EQ(ok, *cstream_write_ec);

  // open another stream to block on async_write_headers()
  std::optional<error_code> cstream2_connect_ec;
  auto cstream2 = h3::stream{cconn};
  cconn.async_connect(cstream2, capture(cstream2_connect_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(cstream2_connect_ec);
  EXPECT_EQ(ok, cstream2_connect_ec);

  auto fields = h3::fields{};
  std::optional<error_code> write_headers_ec;
  cstream2.async_write_headers(fields, capture(write_headers_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_FALSE(write_headers_ec);

  cstream2.shutdown(1);

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(write_headers_ec);
  EXPECT_EQ(quic::stream_error::aborted, *write_headers_ec);
}

TEST_F(Stream, shutdown_before_write_headers)
{
  sstream.shutdown(1);

  context.poll();
  ASSERT_FALSE(context.stopped());

  auto fields = h3::fields{};
  std::optional<error_code> write_headers_ec;
  sstream.async_write_headers(fields, capture(write_headers_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(write_headers_ec);
  EXPECT_EQ(errc::bad_file_descriptor, *write_headers_ec);
}

TEST_F(Stream, remote_shutdown_before_write_headers)
{
  cstream.shutdown(0);

  context.poll();
  ASSERT_FALSE(context.stopped());

  auto fields = h3::fields{};
  std::optional<error_code> write_headers_ec;
  sstream.async_write_headers(fields, capture(write_headers_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(write_headers_ec);
  EXPECT_EQ(ok, *write_headers_ec);
}

TEST_F(Stream, shutdown_after_close)
{
  std::optional<error_code> close_ec;
  cstream.async_close(capture(close_ec));

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
  std::optional<error_code> close_ec;
  sstream.async_close(capture(close_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());

  error_code shutdown_ec;
  cstream.shutdown(0, shutdown_ec);
  EXPECT_EQ(ok, shutdown_ec);
}

} // namespace nexus
