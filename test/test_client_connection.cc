#include <http2/client_connection.hpp>
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

TEST(ClientConnection, upgrade)
{
  boost::asio::io_context ioctx;

  auto acceptor = start_listener(ioctx);
  auto port = acceptor.local_endpoint().port();

  // client_connection
  std::thread thread([&] {
      client_connection<tcp::socket> client{protocol::default_settings, ioctx};
      auto addr = boost::asio::ip::make_address("127.0.0.1");
      boost::system::error_code ec;
      client.next_layer().connect(tcp::endpoint(addr, port), ec);
      ASSERT_EQ(ok, ec);

      client.upgrade("127.0.0.1", "/", ec);
      ASSERT_EQ(ok, ec);

      client.next_layer().shutdown(tcp::socket::shutdown_both, ec);
    });
  // raw server
  {
    tcp::socket server{ioctx};

    boost::system::error_code ec;
    acceptor.accept(server, ec);
    ASSERT_EQ(ok, ec);

    namespace http = boost::beast::http;
    // read the upgrade request
    boost::beast::flat_buffer buffer;
    http::request<http::empty_body> req;
    http::read(server, buffer, req, ec);
    ASSERT_EQ(ok, ec);
    // send the response
    http::response<http::empty_body> res{http::status::switching_protocols, req.version()};
    http::write(server, res, ec);
    ASSERT_EQ(ok, ec);
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

    server.shutdown(tcp::socket::shutdown_both, ec);
  }

  ioctx.run();
  thread.join();
}

} // namespace http2
