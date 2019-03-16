#include <http2/ssl/client_connection.hpp>
#include "server_certificate.hpp"
#include <thread>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <gtest/gtest.h>

namespace http2 {

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

      boost::system::error_code connect_ec;
      auto addr = boost::asio::ip::make_address("127.0.0.1");
      client.lowest_layer().connect(tcp::endpoint(addr, port), connect_ec);
      ASSERT_EQ(ok, connect_ec);

      boost::system::error_code handshake_ec;
      client.handshake(handshake_ec);
      ASSERT_EQ(ok, handshake_ec);
      EXPECT_EQ("h2", ssl::get_alpn_selected(client.next_layer()));

      boost::system::error_code shutdown_ec;
      client.next_layer().shutdown(shutdown_ec);
      client.lowest_layer().shutdown(tcp::socket::shutdown_both, shutdown_ec);
    });
  // server
  {
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    detail::test::use_server_certificate(ctx);
    auto protocols = ssl::alpn::make_protocol_list("h2");
    ssl::accept_protocols(ctx, protocols);

    boost::asio::ssl::stream<tcp::socket> server{ioctx, ctx};

    boost::system::error_code accept_ec;
    acceptor.accept(server.next_layer(), accept_ec);
    ASSERT_EQ(ok, accept_ec);

    boost::system::error_code handshake_ec;
    server.handshake(boost::asio::ssl::stream_base::server, handshake_ec);
    ASSERT_EQ(ok, handshake_ec);
    EXPECT_EQ("h2", ssl::get_alpn_selected(server));

    // read preface
    std::string preface(protocol::client_connection_preface.size(), '\0');
    boost::system::error_code preface_ec;
    boost::asio::read(server, boost::asio::buffer(preface), preface_ec);
    ASSERT_EQ(ok, preface_ec);
    EXPECT_EQ(protocol::client_connection_preface, preface);

    boost::system::error_code shutdown_ec;
    server.shutdown(shutdown_ec);
    server.next_layer().shutdown(tcp::socket::shutdown_both, shutdown_ec);
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

      boost::system::error_code connect_ec;
      auto addr = boost::asio::ip::make_address("127.0.0.1");
      client.lowest_layer().connect(tcp::endpoint(addr, port), connect_ec);
      ASSERT_EQ(ok, connect_ec);

      boost::system::error_code handshake_ec;
      client.handshake(handshake_ec);
      EXPECT_EQ(http2::protocol::error::http_1_1_required, handshake_ec);
      EXPECT_EQ("", ssl::get_alpn_selected(client.next_layer()));

      boost::system::error_code shutdown_ec;
      client.next_layer().shutdown(shutdown_ec);
      client.lowest_layer().shutdown(tcp::socket::shutdown_both, shutdown_ec);
    });
  // server
  {
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    detail::test::use_server_certificate(ctx);

    boost::asio::ssl::stream<tcp::socket> server{ioctx, ctx};

    boost::system::error_code accept_ec;
    acceptor.accept(server.next_layer(), accept_ec);
    ASSERT_EQ(ok, accept_ec);

    boost::system::error_code handshake_ec;
    server.handshake(boost::asio::ssl::stream_base::server, handshake_ec);
    ASSERT_EQ(ok, handshake_ec);
    EXPECT_EQ("", ssl::get_alpn_selected(server));

    boost::system::error_code shutdown_ec;
    server.shutdown(shutdown_ec);
    server.next_layer().shutdown(tcp::socket::shutdown_both, shutdown_ec);
  }

  ioctx.run();
  thread.join();
}

} // namespace http2
