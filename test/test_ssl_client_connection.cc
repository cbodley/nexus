#include <nexus/http2/ssl/client_connection.hpp>
#include "server_certificate.hpp"
#include <thread>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <gtest/gtest.h>

namespace nexus::http2 {

static const boost::system::error_code ok;

using boost::asio::ip::tcp;
tcp::acceptor start_listener(boost::asio::io_context& ioctx)
{
  tcp::acceptor acceptor(ioctx);
  tcp::endpoint endpoint(tcp::v4(), 0);
  acceptor.open(endpoint.protocol());
  acceptor.bind(endpoint);
  acceptor.listen();
  return acceptor;
}

TEST(SslClientConnection, handshake)
{
  boost::asio::io_context ioctx;

  auto acceptor = start_listener(ioctx);
  auto port = acceptor.local_endpoint().port();

  // client
  std::thread thread([&] {
      boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
      using ssl_stream = boost::asio::ssl::stream<tcp::socket>;
      ssl::client_connection<ssl_stream> client{protocol::default_settings,
                                                ioctx, ctx};

      boost::system::error_code ec;
      auto addr = boost::asio::ip::make_address("127.0.0.1");
      client.lowest_layer().connect(tcp::endpoint(addr, port), ec);
      ASSERT_EQ(ok, ec);

      client.handshake(ec);
      ASSERT_EQ(ok, ec);
      EXPECT_EQ("h2", ssl::get_alpn_selected(client.next_layer()));

      client.next_layer().shutdown(ec);
      client.lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
    });
  // server
  {
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    detail::test::use_server_certificate(ctx);
    auto protocols = ssl::alpn::make_protocol_list("h2");
    ssl::accept_protocols(ctx, protocols);

    boost::asio::ssl::stream<tcp::socket> server{ioctx, ctx};

    boost::system::error_code ec;
    acceptor.accept(server.next_layer(), ec);
    ASSERT_EQ(ok, ec);

    server.handshake(boost::asio::ssl::stream_base::server, ec);
    ASSERT_EQ(ok, ec);
    EXPECT_EQ("h2", ssl::get_alpn_selected(server));

    // read preface
    std::string preface(protocol::client_connection_preface.size(), '\0');
    boost::asio::read(server, boost::asio::buffer(preface), ec);
    ASSERT_EQ(ok, ec);
    EXPECT_EQ(protocol::client_connection_preface, preface);
    // read SETTINGS
    std::string settings(9, '\0');
    boost::asio::read(server, boost::asio::buffer(settings), ec);
    ASSERT_EQ(ok, ec);
    EXPECT_EQ(std::string_view("\0\0\0\x4\0\0\0\0\0", 9), settings);

    server.shutdown(ec);
    server.next_layer().shutdown(tcp::socket::shutdown_both, ec);
  }

  ioctx.run();
  thread.join();
}

TEST(SslClientConnection, handshake_no_alpn)
{
  boost::asio::io_context ioctx;

  auto acceptor = start_listener(ioctx);
  auto port = acceptor.local_endpoint().port();

  // client
  std::thread thread([&] {
      boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
      using ssl_stream = boost::asio::ssl::stream<tcp::socket>;
      ssl::client_connection<ssl_stream> client{protocol::default_settings,
                                                ioctx, ctx};

      boost::system::error_code ec;
      auto addr = boost::asio::ip::make_address("127.0.0.1");
      client.lowest_layer().connect(tcp::endpoint(addr, port), ec);
      ASSERT_EQ(ok, ec);

      client.handshake(ec);
      EXPECT_EQ(http2::protocol::error::http_1_1_required, ec);
      EXPECT_EQ("", ssl::get_alpn_selected(client.next_layer()));

      client.next_layer().shutdown(ec);
      client.lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
    });
  // server
  {
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    detail::test::use_server_certificate(ctx);

    boost::asio::ssl::stream<tcp::socket> server{ioctx, ctx};

    boost::system::error_code ec;
    acceptor.accept(server.next_layer(), ec);
    ASSERT_EQ(ok, ec);

    server.handshake(boost::asio::ssl::stream_base::server, ec);
    ASSERT_EQ(ok, ec);
    EXPECT_EQ("", ssl::get_alpn_selected(server));

    server.shutdown(ec);
    server.next_layer().shutdown(tcp::socket::shutdown_both, ec);
  }

  ioctx.run();
  thread.join();
}

} // namespace nexus::http2
