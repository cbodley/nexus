#include <http2/client_connection.hpp>
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

TEST(ClientConnection, upgrade)
{
  boost::asio::io_context ioctx;

  auto acceptor = start_listener(ioctx);
  auto port = acceptor.local_endpoint().port();

  // client_connection
  std::thread thread([&] {
      protocol::setting_values settings;
      settings.max_concurrent_streams = 4;
      client_connection<tcp::socket> client{settings, ioctx};
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
    ASSERT_NE(req.end(), req.find("host"));
    ASSERT_EQ(boost::string_view("127.0.0.1"), req.find("host")->value());
    ASSERT_NE(req.end(), req.find("upgrade"));
    ASSERT_EQ(boost::string_view("h2c"), req.find("upgrade")->value());
    ASSERT_NE(req.end(), req.find("connection"));
    ASSERT_EQ(boost::string_view("HTTP2-Settings"), req.find("connection")->value());
    ASSERT_NE(req.end(), req.find("HTTP2-Settings"));
    ASSERT_EQ(boost::string_view("AAMAAAAE"), req.find("HTTP2-Settings")->value());
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

} // namespace nexus::http2
