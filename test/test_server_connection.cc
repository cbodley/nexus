#include <nexus/http2/server_connection.hpp>
#include <echo_stream.hpp>
#include <joined_stream.hpp>
#include <thread>
#include <boost/asio/io_context.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/write.hpp>

#include <gtest/gtest.h>

namespace http = boost::beast::http;

namespace nexus::http2 {

static const boost::system::error_code ok;

TEST(ServerConnection, upgrade)
{
  boost::asio::io_context ioctx;
  test::echo_stream in{ioctx.get_executor()};
  test::echo_stream out{ioctx.get_executor()};
  using joined_stream = test::joined_stream<decltype(in), decltype(out)>;

  std::thread thread([&] {
      // server
      server_connection<joined_stream> server{protocol::default_settings, in, out};

      boost::system::error_code ec;
      server.upgrade("", ec);
      ASSERT_EQ(ok, ec);
    });
  {
    // client
    auto client = test::join_streams(out, in);

    boost::system::error_code ec;
    {
      // read the 101 Switching Protocols response
      boost::beast::flat_buffer buffer;
      http::response<http::empty_body> res;
      http::read(client, buffer, res, ec);
      ASSERT_EQ(ok, ec);
      EXPECT_EQ(http::status::switching_protocols, res.result());
      EXPECT_EQ(11, res.version());
      ASSERT_NE(res.end(), res.find("upgrade"));
      EXPECT_EQ(boost::string_view("h2c"), res.find("upgrade")->value());
      ASSERT_NE(res.end(), res.find("connection"));
      EXPECT_EQ(boost::string_view("Upgrade"), res.find("connection")->value());
    }
    {
      // send the client connection preface
      auto buffer = boost::asio::buffer(protocol::client_connection_preface.data(),
                                        protocol::client_connection_preface.size());
      boost::asio::write(client, buffer, ec);
      ASSERT_EQ(ok, ec);
    }
    // send a SETTINGS frame
    constexpr auto type = protocol::frame_type::settings;
    constexpr auto flags = 0;
    constexpr protocol::stream_identifier stream_id = 0;
    auto payload = boost::asio::const_buffer(); // empty
    detail::write_frame(client, type, flags, stream_id, payload, ec);
    ASSERT_EQ(ok, ec);
    // read server SETTINGS frame
    protocol::frame_header header;
    detail::read_frame_header(client, header, ec);
    ASSERT_EQ(ok, ec);
  }
  ioctx.run();
  thread.join();
}

} // namespace nexus::http2
