#include <nexus/http2/ssl/client_connection.hpp>
#include <echo_stream.hpp>
#include <joined_stream.hpp>
#include <server_certificate.hpp>
#include <thread>
#include <boost/asio/io_context.hpp>
#include <boost/asio/read.hpp>
#include <gtest/gtest.h>

namespace nexus::http2 {

static const boost::system::error_code ok;

TEST(SslClientConnection, handshake)
{
  boost::asio::io_context ioctx;
  test::echo_stream in{ioctx.get_executor()};
  test::echo_stream out{ioctx.get_executor()};
  using joined_stream = test::joined_stream<decltype(in), decltype(out)>;

  // client
  std::thread thread([&] {
      boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
      joined_stream stream{in, out};
      using ssl_stream = boost::asio::ssl::stream<joined_stream&>;
      ssl::client_connection<ssl_stream> client{protocol::default_settings,
                                                stream, ctx};

      boost::system::error_code ec;
      client.handshake(ec);
      ASSERT_EQ(ok, ec);
      EXPECT_EQ("h2", ssl::get_alpn_selected(client.next_layer()));

      client.next_layer().shutdown(ec);
    });
  // server
  {
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    detail::test::use_server_certificate(ctx);
    auto protocols = ssl::alpn::make_protocol_list("h2");
    ssl::accept_protocols(ctx, protocols);

    joined_stream stream{out, in};
    boost::asio::ssl::stream<joined_stream&> server{stream, ctx};

    boost::system::error_code ec;
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
  }

  ioctx.run();
  thread.join();
}

TEST(SslClientConnection, handshake_no_alpn)
{
  boost::asio::io_context ioctx;
  test::echo_stream in{ioctx.get_executor()};
  test::echo_stream out{ioctx.get_executor()};
  using joined_stream = test::joined_stream<decltype(in), decltype(out)>;

  // client
  std::thread thread([&] {
      boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
      joined_stream stream{in, out};
      using ssl_stream = boost::asio::ssl::stream<joined_stream&>;
      ssl::client_connection<ssl_stream> client{protocol::default_settings,
                                                stream, ctx};

      boost::system::error_code ec;
      client.handshake(ec);
      EXPECT_EQ(http2::protocol::error::http_1_1_required, ec);
      EXPECT_EQ("", ssl::get_alpn_selected(client.next_layer()));

      client.next_layer().shutdown(ec);
    });
  // server
  {
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    detail::test::use_server_certificate(ctx);

    joined_stream stream{out, in};
    boost::asio::ssl::stream<joined_stream&> server{stream, ctx};

    boost::system::error_code ec;
    server.handshake(boost::asio::ssl::stream_base::server, ec);
    ASSERT_EQ(ok, ec);
    EXPECT_EQ("", ssl::get_alpn_selected(server));

    server.shutdown(ec);
  }

  ioctx.run();
  thread.join();
}

} // namespace nexus::http2
