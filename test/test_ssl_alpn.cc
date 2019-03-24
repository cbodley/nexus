#include <http2/ssl/alpn.hpp>
#include "server_certificate.hpp"
#include <thread>
#include <boost/asio/ip/tcp.hpp>
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

TEST(SslAlpn, make_protocol_list)
{
  auto protocols = ssl::alpn::make_protocol_list("h2", "http/1.1");
  EXPECT_EQ("\x2h2\x8http/1.1", protocols);
}

TEST(SslAlpn, start)
{
  boost::asio::io_context ioctx;

  auto acceptor = start_listener(ioctx);
  auto port = acceptor.local_endpoint().port();

  // client
  std::thread thread([&] {
      boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);

      boost::asio::ssl::stream<tcp::socket> client{ioctx, ctx};
      auto protocols = ssl::alpn::make_protocol_list("h2", "http/1.1");
      boost::system::error_code protos_ec;
      ssl::set_alpn_protos(client, protocols, protos_ec);
      ASSERT_EQ(ok, protos_ec);

      boost::system::error_code connect_ec;
      auto addr = boost::asio::ip::make_address("127.0.0.1");
      client.next_layer().connect(tcp::endpoint(addr, port), connect_ec);
      ASSERT_EQ(ok, connect_ec);

      boost::system::error_code handshake_ec;
      client.handshake(boost::asio::ssl::stream_base::client, handshake_ec);
      ASSERT_EQ(ok, handshake_ec);
      EXPECT_EQ("h2", ssl::get_alpn_selected(client));

      boost::system::error_code shutdown_ec;
      client.shutdown(shutdown_ec);
      client.next_layer().shutdown(tcp::socket::shutdown_both, shutdown_ec);
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

    boost::system::error_code shutdown_ec;
    server.shutdown(shutdown_ec);
    server.next_layer().shutdown(tcp::socket::shutdown_both, shutdown_ec);
  }

  ioctx.run();
  thread.join();
}

} // namespace nexus::http2
