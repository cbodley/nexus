#include <nexus/http/detail/connection_impl.hpp>
#include <server_certificate.hpp>
#include <optional>
#include <thread>
#include <gtest/gtest.h>

namespace nexus::http::detail {

static const boost::system::error_code ok;
using tcp = boost::asio::ip::tcp;
using namespace std::chrono_literals;

tcp::acceptor start_listener(boost::asio::io_context& ioctx)
{
  tcp::acceptor acceptor(ioctx);
  tcp::endpoint endpoint(tcp::v4(), 0);
  acceptor.open(endpoint.protocol());
  acceptor.bind(endpoint);
  acceptor.listen();
  return acceptor;
}

TEST(ConnectionImpl, connect_shutdown)
{
  boost::asio::io_context ioctx;
  auto acceptor = start_listener(ioctx);
  const auto port = std::to_string(acceptor.local_endpoint().port());

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_impl impl{ioctx, ioctx.get_executor(), ssl};
  boost::system::error_code ec;
  impl.connect("127.0.0.1", port, ec);
  EXPECT_EQ(ok, ec);
  impl.shutdown(ec);
  EXPECT_EQ(ok, ec);
}

TEST(ConnectionImpl, connect_destruct)
{
  boost::asio::io_context ioctx;
  auto acceptor = start_listener(ioctx);
  const auto port = std::to_string(acceptor.local_endpoint().port());

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_impl impl{ioctx, ioctx.get_executor(), ssl};
  boost::system::error_code ec;
  impl.connect("127.0.0.1", port, ec);
  EXPECT_EQ(ok, ec);
}

TEST(ConnectionImpl, connect_refused)
{
  boost::asio::io_context ioctx;
  tcp::acceptor acceptor(ioctx);
  tcp::endpoint endpoint(tcp::v4(), 0);
  acceptor.open(endpoint.protocol());
  acceptor.bind(endpoint); // bind but don't listen
  const auto port = std::to_string(acceptor.local_endpoint().port());

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_impl impl{ioctx, ioctx.get_executor(), ssl};
  boost::system::error_code ec;
  impl.connect("127.0.0.1", port, ec);
  EXPECT_EQ(boost::asio::error::connection_refused, ec);
}

TEST(ConnectionImpl, connect_ssl_shutdown)
{
  boost::asio::io_context ioctx;
  auto acceptor = start_listener(ioctx);
  const auto port = std::to_string(acceptor.local_endpoint().port());

  std::thread server{[&] {
    boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
    http2::detail::test::use_server_certificate(ssl);
    boost::asio::ssl::stream<tcp::socket> stream(ioctx, ssl);
    boost::system::error_code ec;
    acceptor.accept(stream.next_layer(), ec);
    ASSERT_EQ(ok, ec);
    stream.handshake(stream.server, ec);
    ASSERT_EQ(ok, ec);
    stream.shutdown(ec);
    stream.next_layer().shutdown(tcp::socket::shutdown_both, ec);
  }};

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_impl impl{ioctx, ioctx.get_executor(), ssl};
  boost::system::error_code ec;
  impl.connect_ssl("127.0.0.1", port, ec);
  EXPECT_EQ(ok, ec);
  impl.shutdown(ec);

  server.join();
}

TEST(ConnectionImpl, connect_ssl_refused)
{
  boost::asio::io_context ioctx;
  tcp::acceptor acceptor(ioctx);
  tcp::endpoint endpoint(tcp::v4(), 0);
  acceptor.open(endpoint.protocol());
  acceptor.bind(endpoint); // bind but don't listen
  const auto port = std::to_string(acceptor.local_endpoint().port());

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_impl impl{ioctx, ioctx.get_executor(), ssl};
  boost::system::error_code ec;
  impl.connect_ssl("127.0.0.1", port, ec);
  EXPECT_EQ(boost::asio::error::connection_refused, ec);
}

auto capture(std::optional<boost::system::error_code>& ec) {
  return [&] (boost::system::error_code e) { ec = e; };
}

TEST(ConnectionImpl, async_resolve_cancel)
{
  boost::asio::io_context ioctx;
  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_impl impl{ioctx, ioctx.get_executor(), ssl};

  std::optional<boost::system::error_code> ec;
  impl.async_connect("127.0.0.1", "0", std::nullopt, capture(ec));

  impl.cancel(); // cancel before running resolve handler

  EXPECT_EQ(1, ioctx.run()); // resolve
  ASSERT_TRUE(ec);
  EXPECT_EQ(boost::asio::error::operation_aborted, *ec);
}

TEST(ConnectionImpl, async_connect_cancel)
{
  boost::asio::io_context ioctx;
  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_impl impl{ioctx, ioctx.get_executor(), ssl};

  std::optional<boost::system::error_code> ec;
  // blocks trying to connect
  impl.async_connect("1.1.1.1", "0", std::nullopt, capture(ec));

  EXPECT_EQ(1, ioctx.run_for(10ms)); // resolve
  ASSERT_FALSE(ec);

  impl.cancel();

  EXPECT_EQ(1, ioctx.run()); // connect
  ASSERT_TRUE(ec);
  EXPECT_EQ(boost::asio::error::operation_aborted, *ec);
}

TEST(ConnectionImpl, async_connect)
{
  boost::asio::io_context ioctx;
  auto acceptor = start_listener(ioctx);
  const auto port = std::to_string(acceptor.local_endpoint().port());

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_impl impl{ioctx, ioctx.get_executor(), ssl};

  std::optional<boost::system::error_code> ec;
  impl.async_connect("127.0.0.1", port, std::nullopt, capture(ec));

  EXPECT_LT(1, ioctx.run()); // resolve, connect
  ASSERT_TRUE(ec);
  EXPECT_EQ(ok, *ec);
}

TEST(ConnectionImpl, async_connect_refused)
{
  boost::asio::io_context ioctx;
  tcp::acceptor acceptor(ioctx);
  tcp::endpoint endpoint(tcp::v4(), 0);
  acceptor.open(endpoint.protocol());
  acceptor.bind(endpoint); // bind but don't listen
  const auto port = std::to_string(acceptor.local_endpoint().port());

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_impl impl{ioctx, ioctx.get_executor(), ssl};

  std::optional<boost::system::error_code> ec;
  impl.async_connect("127.0.0.1", port, std::nullopt, capture(ec));

  EXPECT_LT(1, ioctx.run()); // resolve, connect
  ASSERT_TRUE(ec);
  EXPECT_EQ(boost::asio::error::connection_refused, *ec);
}

TEST(ConnectionImpl, async_connect_ssl)
{
  boost::asio::io_context ioctx;
  auto acceptor = start_listener(ioctx);
  const auto port = std::to_string(acceptor.local_endpoint().port());

  std::thread server{[&] {
    boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
    http2::detail::test::use_server_certificate(ssl);
    boost::asio::ssl::stream<tcp::socket> stream(ioctx, ssl);
    boost::system::error_code ec;
    acceptor.accept(stream.next_layer(), ec);
    ASSERT_EQ(ok, ec);
    stream.handshake(stream.server, ec);
    ASSERT_EQ(ok, ec);
    stream.shutdown(ec);
    stream.next_layer().shutdown(tcp::socket::shutdown_both, ec);
  }};

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_impl impl{ioctx, ioctx.get_executor(), ssl};

  std::optional<boost::system::error_code> ec;
  impl.async_connect_ssl("127.0.0.1", port, std::nullopt, capture(ec));

  EXPECT_LT(2, ioctx.run()); // resolve, connect, handshake
  ASSERT_TRUE(ec);
  EXPECT_EQ(ok, *ec);

  impl.shutdown(*ec);
  EXPECT_EQ(ok, *ec);

  server.join();
}

TEST(ConnectionImpl, async_resolve_ssl_cancel)
{
  boost::asio::io_context ioctx;
  auto acceptor = start_listener(ioctx);
  const auto port = std::to_string(acceptor.local_endpoint().port());

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_impl impl{ioctx, ioctx.get_executor(), ssl};

  std::optional<boost::system::error_code> ec;
  impl.async_connect_ssl("1.1.1.1", port, std::nullopt, capture(ec));

  impl.cancel(); // cancel before running resolve handler

  EXPECT_EQ(1, ioctx.run());
  ASSERT_TRUE(ec);
  EXPECT_EQ(boost::asio::error::operation_aborted, *ec);
}

TEST(ConnectionImpl, async_connect_ssl_cancel)
{
  boost::asio::io_context ioctx;
  auto acceptor = start_listener(ioctx);
  const auto port = std::to_string(acceptor.local_endpoint().port());

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_impl impl{ioctx, ioctx.get_executor(), ssl};

  std::optional<boost::system::error_code> ec;
  impl.async_connect_ssl("1.1.1.1", port, std::nullopt, capture(ec));

  EXPECT_EQ(1, ioctx.run_for(10ms)); // resolve
  ASSERT_FALSE(ec);

  impl.cancel();

  EXPECT_EQ(1, ioctx.run());
  ASSERT_TRUE(ec);
  EXPECT_EQ(boost::asio::error::operation_aborted, *ec);
}

TEST(ConnectionImpl, async_connect_ssl_handshake_cancel)
{
  boost::asio::io_context ioctx;
  auto acceptor = start_listener(ioctx);
  const auto port = std::to_string(acceptor.local_endpoint().port());

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_impl impl{ioctx, ioctx.get_executor(), ssl};

  std::optional<boost::system::error_code> ec;
  impl.async_connect_ssl("127.0.0.1", port, std::nullopt, capture(ec));

  EXPECT_LT(2, ioctx.run_for(10ms)); // resolve, connect, handshake
  ASSERT_FALSE(ec);

  impl.cancel();

  EXPECT_EQ(1, ioctx.run());
  ASSERT_TRUE(ec);
  EXPECT_EQ(boost::asio::error::operation_aborted, *ec);
}

TEST(ConnectionImpl, async_connect_ssl_truncated)
{
  boost::asio::io_context ioctx;
  auto acceptor = start_listener(ioctx);
  const auto port = std::to_string(acceptor.local_endpoint().port());

  std::thread server{[&] {
    boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
    http2::detail::test::use_server_certificate(ssl);
    boost::asio::ssl::stream<tcp::socket> stream(ioctx, ssl);
    boost::system::error_code ec;
    acceptor.accept(stream.next_layer(), ec);
    ASSERT_EQ(ok, ec);
    // shut down without handshake
    stream.next_layer().shutdown(tcp::socket::shutdown_both, ec);
  }};

  boost::asio::ssl::context ssl{boost::asio::ssl::context::tls};
  connection_impl impl{ioctx, ioctx.get_executor(), ssl};

  std::optional<boost::system::error_code> ec;
  impl.async_connect_ssl("127.0.0.1", port, std::nullopt, capture(ec));

  EXPECT_LT(2, ioctx.run()); // resolve, connect, handshake
  ASSERT_TRUE(ec);
  EXPECT_EQ(boost::asio::ssl::error::stream_truncated, *ec);

  server.join();
}

} // namespace nexus::http::detail
