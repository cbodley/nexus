#include <nexus/http2/ssl/alpn.hpp>
#include <echo_stream.hpp>
#include <joined_stream.hpp>
#include "server_certificate.hpp"
#include <thread>
#include <gtest/gtest.h>

namespace nexus::http2 {

static const boost::system::error_code ok;

TEST(SslAlpn, make_protocol_list)
{
  auto protocols = ssl::alpn::make_protocol_list("h2", "http/1.1");
  EXPECT_EQ("\x2h2\x8http/1.1", protocols);
}

TEST(SslAlpn, start)
{
  boost::asio::io_context ioctx;
  test::echo_stream in{ioctx.get_executor()};
  test::echo_stream out{ioctx.get_executor()};
  using joined_stream = test::joined_stream<decltype(in), decltype(out)>;

  // client
  std::thread thread([&] {
      boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);

      test::joined_stream stream{in, out};
      boost::asio::ssl::stream<joined_stream&> client{stream, ctx};

      auto protocols = ssl::alpn::make_protocol_list("h2", "http/1.1");
      boost::system::error_code ec;
      ssl::set_alpn_protos(client, protocols, ec);
      ASSERT_EQ(ok, ec);

      client.handshake(boost::asio::ssl::stream_base::client, ec);
      ASSERT_EQ(ok, ec);
      EXPECT_EQ("h2", ssl::get_alpn_selected(client));

      client.shutdown(ec);
    });
  // server
  {
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    detail::test::use_server_certificate(ctx);
    auto protocols = ssl::alpn::make_protocol_list("h2");
    ssl::accept_protocols(ctx, protocols);

    test::joined_stream stream{out, in};
    boost::asio::ssl::stream<joined_stream&> server{stream, ctx};

    boost::system::error_code ec;
    server.handshake(boost::asio::ssl::stream_base::server, ec);
    ASSERT_EQ(ok, ec);
    EXPECT_EQ("h2", ssl::get_alpn_selected(server));

    server.shutdown(ec);
  }

  ioctx.run();
  thread.join();
}

} // namespace nexus::http2
