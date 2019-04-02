#include <nexus/http2/client_connection.hpp>
#include <echo_stream.hpp>
#include <joined_stream.hpp>
#include <thread>
#include <boost/asio/io_context.hpp>
#include <boost/asio/read.hpp>
#include <gtest/gtest.h>

namespace nexus::http2 {

static const boost::system::error_code ok;

TEST(ClientConnection, upgrade)
{
  boost::asio::io_context ioctx;
  test::echo_stream in{ioctx.get_executor()};
  test::echo_stream out{ioctx.get_executor()};
  using joined_stream = test::joined_stream<decltype(in), decltype(out)>;

  // client_connection
  std::thread thread([&] {
      protocol::setting_values settings;
      settings.max_concurrent_streams = 4;
      client_connection<joined_stream> client{settings, in, out};
      boost::system::error_code ec;
      client.upgrade("127.0.0.1", "/", ec);
      ASSERT_EQ(ok, ec);
    });
  // raw server
  {
    auto server = test::join_streams(out, in);

    namespace http = boost::beast::http;
    // read the upgrade request
    boost::beast::flat_buffer buffer;
    http::request<http::empty_body> req;
    boost::system::error_code ec;
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
  }

  ioctx.run();
  thread.join();
}

} // namespace nexus::http2
