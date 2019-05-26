#include <nexus/http/connection_pool.hpp>
#include <server_certificate.hpp>
#include <optional>
#include <thread>
#include <gtest/gtest.h>

namespace nexus::http {

static const boost::system::error_code ok;
using tcp = boost::asio::ip::tcp;

tcp::acceptor start_listener(boost::asio::io_context& ioctx)
{
  tcp::acceptor acceptor(ioctx);
  tcp::endpoint endpoint(tcp::v4(), 0);
  acceptor.open(endpoint.protocol());
  acceptor.bind(endpoint);
  acceptor.listen();
  return acceptor;
}

TEST(ConnectionPool, get_put)
{
  boost::asio::io_context ioctx;
  auto acceptor = start_listener(ioctx);
  const auto port = std::to_string(acceptor.local_endpoint().port());
  const bool secure = false;

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_pool pool{ioctx, ssl, "127.0.0.1", port, secure, 10};
  boost::system::error_code ec;
  auto conn = pool.get(ec);
  EXPECT_EQ(ok, ec);
  pool.put(std::move(conn), ec);
}

TEST(ConnectionPool, get_destruct)
{
  boost::asio::io_context ioctx;
  auto acceptor = start_listener(ioctx);
  const auto port = std::to_string(acceptor.local_endpoint().port());
  const bool secure = false;

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_pool pool{ioctx, ssl, "127.0.0.1", port, secure, 10};
  boost::system::error_code ec;
  auto conn = pool.get(ec);
  EXPECT_EQ(ok, ec);
}

TEST(ConnectionPool, shutdown_outstanding)
{
  boost::asio::io_context ioctx;
  auto acceptor = start_listener(ioctx);
  const auto port = std::to_string(acceptor.local_endpoint().port());
  const bool secure = false;

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_pool pool{ioctx, ssl, "127.0.0.1", port, secure, 10};
  boost::system::error_code ec;
  auto conn = pool.get(ec);
  EXPECT_EQ(ok, ec);

  pool.shutdown();

  EXPECT_EQ(0, conn.available(ec));
  EXPECT_EQ(boost::asio::error::bad_descriptor, ec);

  pool.put(std::move(conn), {});
}

TEST(ConnectionPool, get_idle)
{
  boost::asio::io_context ioctx;
  auto acceptor = start_listener(ioctx);
  const auto port = std::to_string(acceptor.local_endpoint().port());
  const bool secure = false;

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_pool pool{ioctx, ssl, "127.0.0.1", port, secure, 10};
  boost::system::error_code ec;
  auto conn = pool.get(ec);
  EXPECT_EQ(ok, ec);
  pool.put(std::move(conn), ec);
  conn = pool.get(ec);
  EXPECT_EQ(ok, ec);
}

TEST(ConnectionPool, shutdown_idle)
{
  boost::asio::io_context ioctx;
  auto acceptor = start_listener(ioctx);
  const auto port = std::to_string(acceptor.local_endpoint().port());
  const bool secure = false;

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_pool pool{ioctx, ssl, "127.0.0.1", port, secure, 10};
  boost::system::error_code ec;
  auto conn = pool.get(ec);
  EXPECT_EQ(ok, ec);
  pool.put(std::move(conn), ec);
  pool.shutdown();
}

TEST(ConnectionPool, ssl_get_put)
{
  boost::asio::io_context ioctx;
  auto acceptor = start_listener(ioctx);
  const auto port = std::to_string(acceptor.local_endpoint().port());
  const bool secure = true;

  std::thread server{[&] {
    boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
    http2::detail::test::use_server_certificate(ssl);
    boost::asio::ssl::stream<tcp::socket> stream(ioctx, ssl);
    boost::system::error_code ec;
    acceptor.accept(stream.next_layer(), ec);
    ASSERT_EQ(ok, ec);
    stream.handshake(boost::asio::ssl::stream_base::server, ec);
    ASSERT_EQ(ok, ec);
    stream.next_layer().shutdown(tcp::socket::shutdown_both, ec);
  }};

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_pool pool{ioctx, ssl, "127.0.0.1", port, secure, 10};
  boost::system::error_code ec;
  auto conn = pool.get(ec);
  EXPECT_EQ(ok, ec);
  pool.put(std::move(conn), ec);

  server.join();
}

auto capture(std::optional<boost::system::error_code>& ec,
             std::optional<connection>& conn) {
  return [&] (boost::system::error_code e, connection c) {
    ec = e;
    conn = std::move(c);
  };
}

TEST(ConnectionPool, async_get)
{
  boost::asio::io_context ioctx;
  auto acceptor = start_listener(ioctx);
  const auto port = std::to_string(acceptor.local_endpoint().port());
  const bool secure = false;

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_pool pool{ioctx, ssl, "127.0.0.1", port, secure, 10};

  std::optional<boost::system::error_code> ec;
  std::optional<connection> conn;
  pool.async_get(capture(ec, conn));

  EXPECT_EQ(2, ioctx.run()); // resolve, connect
  EXPECT_TRUE(ec);
  EXPECT_EQ(ok, *ec);
}

TEST(ConnectionPool, async_get_idle)
{
  boost::asio::io_context ioctx;
  auto acceptor = start_listener(ioctx);
  const auto port = std::to_string(acceptor.local_endpoint().port());
  const bool secure = false;

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_pool pool{ioctx, ssl, "127.0.0.1", port, secure, 10};
  {
    boost::system::error_code ec;
    auto conn = pool.get(ec);
    ASSERT_EQ(ok, ec);
    pool.put(std::move(conn), ec);
  }
  std::optional<boost::system::error_code> ec;
  std::optional<connection> conn;
  pool.async_get(capture(ec, conn));

  EXPECT_EQ(1, ioctx.run()); // pop_idle()
  EXPECT_TRUE(ec);
  EXPECT_EQ(ok, *ec);
}

TEST(ConnectionPool, async_get_ssl_shutdown)
{
  boost::asio::io_context ioctx;
  auto acceptor = start_listener(ioctx);
  const auto port = std::to_string(acceptor.local_endpoint().port());
  const bool secure = true;

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_pool pool{ioctx, ssl, "127.0.0.1", port, secure, 10};

  std::optional<boost::system::error_code> ec;
  std::optional<connection> conn;
  pool.async_get(capture(ec, conn));

  EXPECT_EQ(1, ioctx.run_one()); // resolve
  EXPECT_EQ(1, ioctx.run_one()); // connect
  EXPECT_FALSE(ioctx.stopped());
  ASSERT_FALSE(ec);

  pool.shutdown();

  EXPECT_EQ(4, ioctx.poll());

  ASSERT_TRUE(ec);
  EXPECT_EQ(boost::asio::error::operation_aborted, *ec);
}

TEST(ConnectionPool, async_get_ssl_destruct)
{
  boost::asio::io_context ioctx;
  auto acceptor = start_listener(ioctx);
  const auto port = std::to_string(acceptor.local_endpoint().port());
  const bool secure = true;

  std::optional<boost::system::error_code> ec;
  std::optional<connection> conn;

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  {
    connection_pool pool{ioctx, ssl, "127.0.0.1", port, secure, 10};
    pool.async_get(capture(ec, conn));

    EXPECT_EQ(1, ioctx.run_one()); // resolve
    EXPECT_EQ(1, ioctx.run_one()); // connect
    EXPECT_FALSE(ioctx.stopped());
    ASSERT_FALSE(ec);

    pool.shutdown();
  }
  EXPECT_EQ(3, ioctx.run());

  ASSERT_TRUE(ec);
  EXPECT_EQ(boost::asio::error::operation_aborted, *ec);
}

} // namespace nexus::http
