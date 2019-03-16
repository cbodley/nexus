#include <http2/server_connection.hpp>
#include <thread>
#include <boost/asio/ip/tcp.hpp>

#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/write.hpp>

#include <gtest/gtest.h>

namespace http = boost::beast::http;

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

TEST(ServerConnection, upgrade)
{
  boost::asio::io_context ioctx;

  auto acceptor = start_listener(ioctx);
  auto port = acceptor.local_endpoint().port();

  std::thread thread([&] {
      // server
      server_connection<tcp::socket> server{protocol::default_settings, ioctx};

      boost::system::error_code accept_ec;
      acceptor.accept(server.next_layer(), accept_ec);
      ASSERT_EQ(ok, accept_ec);

      boost::system::error_code upgrade_ec;
      server.upgrade("", upgrade_ec);
      ASSERT_EQ(ok, upgrade_ec);

      boost::system::error_code shutdown_ec;
      server.next_layer().shutdown(tcp::socket::shutdown_both, shutdown_ec);
    });
  {
    // client
    tcp::socket client{ioctx};

    boost::system::error_code connect_ec;
    auto addr = boost::asio::ip::make_address("127.0.0.1");
    client.connect(tcp::endpoint(addr, port), connect_ec);
    ASSERT_EQ(ok, connect_ec);
    {
      // read the 101 Switching Protocols response
      boost::beast::flat_buffer buffer;
      http::response<http::empty_body> res;
      boost::system::error_code read_ec;
      http::read(client, buffer, res, read_ec);
      ASSERT_EQ(ok, read_ec);
      EXPECT_EQ(http::status::switching_protocols, res.result());
      EXPECT_EQ(11, res.version());
    }
    {
      // send the client connection preface
      auto buffer = boost::asio::buffer(protocol::client_connection_preface.data(),
                                        protocol::client_connection_preface.size());
      boost::system::error_code preface_ec;
      boost::asio::write(client, buffer, preface_ec);
      ASSERT_EQ(ok, preface_ec);
    }
    // send a SETTINGS frame
    // read server SETTINGS frame

    boost::system::error_code shutdown_ec;
    client.shutdown(tcp::socket::shutdown_both, shutdown_ec);
  }
  ioctx.run();
  thread.join();
}

} // namespace http2
