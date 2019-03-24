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

      boost::system::error_code ec;
      acceptor.accept(server.next_layer(), ec);
      ASSERT_EQ(ok, ec);

      server.upgrade("", ec);
      ASSERT_EQ(ok, ec);

      server.next_layer().shutdown(tcp::socket::shutdown_both, ec);
    });
  {
    // client
    tcp::socket client{ioctx};

    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address("127.0.0.1");
    client.connect(tcp::endpoint(addr, port), ec);
    ASSERT_EQ(ok, ec);
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

    client.shutdown(tcp::socket::shutdown_both, ec);
  }
  ioctx.run();
  thread.join();
}

} // namespace http2
