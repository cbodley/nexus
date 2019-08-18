#include <nexus/tls/alpn.hpp>
#include <echo_stream.hpp>
#include <joined_stream.hpp>
#include <server_certificate.hpp>
#include <thread>
#include <gtest/gtest.h>

namespace nexus::tls {

static const boost::system::error_code ok;

TEST(tls, make_alpn_protocol_list)
{
  auto protocols = alpn::make_protocol_list("h2", "http/1.1");
  EXPECT_EQ("\x2h2\x8http/1.1", protocols);
}

TEST(tls, start_alpn)
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

      auto protocols = tls::alpn::make_protocol_list("h2", "http/1.1");
      boost::system::error_code ec;
      tls::set_alpn_protos(client, protocols, ec);
      ASSERT_EQ(ok, ec);

      client.handshake(boost::asio::ssl::stream_base::client, ec);
      ASSERT_EQ(ok, ec);
      EXPECT_EQ("h2", tls::get_alpn_selected(client));

      client.shutdown(ec);
    });
  // server
  {
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    test::use_server_certificate(ctx);
    auto protocols = tls::alpn::make_protocol_list("h2");
    tls::accept_protocols(ctx, protocols);

    test::joined_stream stream{out, in};
    boost::asio::ssl::stream<joined_stream&> server{stream, ctx};

    boost::system::error_code ec;
    server.handshake(boost::asio::ssl::stream_base::server, ec);
    ASSERT_EQ(ok, ec);
    EXPECT_EQ("h2", tls::get_alpn_selected(server));

    server.shutdown(ec);
  }

  ioctx.run();
  thread.join();
}

} // namespace nexus::tls
