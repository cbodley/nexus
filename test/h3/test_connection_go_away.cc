#include <nexus/h3/client.hpp>
#include <gtest/gtest.h>
#include <nexus/h3/server.hpp>
#include <nexus/h3/stream.hpp>
#include <nexus/global_init.hpp>

#include "certificate.hpp"

namespace nexus {

namespace {

static constexpr const char* alpn = "\02h3";

const error_code ok;

auto capture(std::optional<error_code>& ec) {
  return [&] (error_code e, size_t = 0) { ec = e; };
}

} // anonymous namespace

TEST(Client, go_away_closed)
{
  boost::asio::io_context context;
  auto global = global::init_client();
  auto sslc = test::init_client_context(alpn);
  auto client = h3::client{context.get_executor(), udp::endpoint{}, sslc};
  auto cconn = h3::client_connection{client};

  // go_away() before the connection is open
  error_code goaway_ec;
  cconn.go_away(goaway_ec);
  EXPECT_EQ(errc::not_connected, goaway_ec);
}

TEST(Client, go_away_before_connect)
{
  boost::asio::io_context context;
  auto global = global::init_client();
  auto sslc = test::init_client_context(alpn);
  auto client = h3::client{context.get_executor(), udp::endpoint{}, sslc};
  boost::asio::ip::address localhost = boost::asio::ip::make_address("127.0.0.1");
  auto cconn = h3::client_connection{client, udp::endpoint{udp::v4(), 1}, "host"};

  context.poll();
  EXPECT_TRUE(cconn.is_open());

  error_code goaway_ec;
  cconn.go_away(goaway_ec);
  EXPECT_EQ(ok, goaway_ec);

  auto cstream = h3::stream{cconn};
  std::optional<error_code> connect_ec;
  cconn.async_connect(cstream, capture(connect_ec));

  context.poll();
  ASSERT_TRUE(connect_ec);
  EXPECT_EQ(quic::connection_error::going_away, *connect_ec);
}

class Connection : public ::testing::Test {
 protected:
  static constexpr const char* alpn = "\02h3";

  static quic::settings server_settings()
  {
    auto settings = quic::default_server_settings();
    settings.max_streams_per_connection = 2;
    return settings;
  }

  boost::asio::io_context context;
  global::context global = global::init_client_server();

  ssl::context ssl = test::init_server_context(alpn);
  ssl::context sslc = test::init_client_context(alpn);

  h3::server server{context.get_executor(), server_settings()};
  boost::asio::ip::address localhost = boost::asio::ip::make_address("127.0.0.1");
  h3::acceptor acceptor{server, udp::endpoint{localhost, 0}, ssl};
  h3::server_connection sconn{acceptor};
  h3::stream sstream{sconn};

  h3::client client{context.get_executor(), udp::endpoint{}, sslc};
  h3::client_connection cconn{client, acceptor.local_endpoint(), "host"};
  h3::stream cstream{cconn};

  void SetUp() override
  {
    global.log_to_stderr("debug");
    acceptor.listen(16);

    std::optional<error_code> accept_ec;
    acceptor.async_accept(sconn, capture(accept_ec));

    std::optional<error_code> connect_ec;
    cconn.async_connect(cstream, capture(connect_ec));

    context.poll();
    ASSERT_TRUE(accept_ec);
    EXPECT_EQ(ok, *accept_ec);
    ASSERT_TRUE(connect_ec);
    EXPECT_EQ(ok, *connect_ec);

    std::optional<error_code> sstream_accept_ec;
    sconn.async_accept(sstream, capture(sstream_accept_ec));

    // the server won't see this stream until we write a packet for it
    auto request = h3::fields{};
    request.insert("salad", "potato");
    std::optional<error_code> write_headers_ec;
    cstream.async_write_headers(request, capture(write_headers_ec));

    context.poll();
    ASSERT_TRUE(write_headers_ec);
    EXPECT_EQ(ok, *write_headers_ec);
    cstream.flush(); // force the connection to send the HEADERS

    context.poll();
    ASSERT_TRUE(sstream_accept_ec);
    EXPECT_EQ(ok, *sstream_accept_ec);
  }
};

TEST_F(Connection, go_away_during_connect)
{
  auto cstream2 = h3::stream{cconn};
  std::optional<error_code> connect2_ec;
  cconn.async_connect(cstream2, capture(connect2_ec));

  context.poll();
  ASSERT_TRUE(cconn.is_open());
  ASSERT_TRUE(connect2_ec);
  EXPECT_EQ(ok, *connect2_ec);

  auto cstream3 = h3::stream{cconn};
  std::optional<error_code> connect3_ec;
  cconn.async_connect(cstream3, capture(connect3_ec));

  context.poll();
  ASSERT_TRUE(cconn.is_open());
  ASSERT_FALSE(connect3_ec);

  error_code goaway_ec;
  cconn.go_away(goaway_ec);
  EXPECT_EQ(ok, goaway_ec);

  context.poll();
  ASSERT_TRUE(connect3_ec);
  EXPECT_EQ(quic::connection_error::going_away, *connect3_ec);
}

TEST_F(Connection, remote_go_away_before_connect)
{
  error_code goaway_ec;
  sconn.go_away(goaway_ec);
  EXPECT_EQ(ok, goaway_ec);

  context.poll();

  auto cstream2 = h3::stream{cconn};
  std::optional<error_code> connect2_ec;
  cconn.async_connect(cstream2, capture(connect2_ec));

  context.poll();
  ASSERT_TRUE(connect2_ec);
  EXPECT_EQ(quic::connection_error::going_away, *connect2_ec);
}

TEST_F(Connection, remote_go_away_during_connect)
{
  auto cstream2 = h3::stream{cconn};
  std::optional<error_code> connect2_ec;
  cconn.async_connect(cstream2, capture(connect2_ec));

  context.poll();
  ASSERT_TRUE(cconn.is_open());
  ASSERT_TRUE(connect2_ec);
  EXPECT_EQ(ok, *connect2_ec);

  auto cstream3 = h3::stream{cconn};
  std::optional<error_code> connect3_ec;
  cconn.async_connect(cstream3, capture(connect3_ec));

  context.poll();
  ASSERT_TRUE(cconn.is_open());
  ASSERT_FALSE(connect3_ec);

  error_code goaway_ec;
  sconn.go_away(goaway_ec);
  EXPECT_EQ(ok, goaway_ec);

  context.poll();
  ASSERT_TRUE(connect3_ec);
  EXPECT_EQ(quic::connection_error::peer_going_away, *connect3_ec);
}

TEST_F(Connection, go_away_before_accept)
{
  error_code goaway_ec;
  sconn.go_away(goaway_ec);
  EXPECT_EQ(ok, goaway_ec);

  auto sstream2 = h3::stream{sconn};
  std::optional<error_code> accept_ec;
  sconn.async_accept(sstream2, capture(accept_ec));

  context.poll();
  ASSERT_TRUE(accept_ec);
  EXPECT_EQ(quic::connection_error::going_away, *accept_ec);
}

TEST_F(Connection, go_away_during_accept)
{
  auto sstream2 = h3::stream{sconn};
  std::optional<error_code> accept_ec;
  sconn.async_accept(sstream2, capture(accept_ec));

  context.poll();
  ASSERT_FALSE(accept_ec);

  error_code goaway_ec;
  sconn.go_away(goaway_ec);
  EXPECT_EQ(ok, goaway_ec);

  context.poll();
  ASSERT_TRUE(accept_ec);
  EXPECT_EQ(quic::connection_error::going_away, *accept_ec);
}

#if 0 // XXX: can't get client connection to send GOAWAY without seeing a PUSH_PROMISE from the server?
TEST_F(Connection, remote_go_away_before_accept)
{
  error_code goaway_ec;
  cconn.go_away(goaway_ec);
  EXPECT_EQ(ok, goaway_ec);

  context.poll();

  auto sstream2 = h3::stream{sconn};
  std::optional<error_code> accept_ec;
  sconn.async_accept(sstream2, capture(accept_ec));

  context.poll();
  ASSERT_TRUE(accept_ec);
  EXPECT_EQ(quic::connection_error::going_away, *accept_ec);
}

TEST_F(Connection, remote_go_away_during_accept)
{
  auto sstream2 = h3::stream{sconn};
  std::optional<error_code> accept_ec;
  sconn.async_accept(sstream2, capture(accept_ec));

  context.poll();
  ASSERT_FALSE(accept_ec);

  error_code goaway_ec;
  cconn.go_away(goaway_ec);
  EXPECT_EQ(ok, goaway_ec);

  context.poll();
  ASSERT_TRUE(accept_ec);
  EXPECT_EQ(quic::connection_error::going_away, *accept_ec);
}
#endif
TEST_F(Connection, go_away_before_write)
{
  error_code goaway_ec;
  cconn.go_away(goaway_ec);
  EXPECT_EQ(ok, goaway_ec);

  auto data = std::array<char, 16>{};
  std::optional<error_code> write_ec;
  cstream.async_write_some(boost::asio::buffer(data), capture(write_ec));

  context.poll();
  ASSERT_TRUE(write_ec);
  EXPECT_EQ(ok, *write_ec);
}

} // namespace nexus
