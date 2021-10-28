#include <nexus/quic/server.hpp>
#include <gtest/gtest.h>
#include <optional>
#include <lsquic.h>
#include <openssl/ssl.h>
#include <nexus/quic/client.hpp>
#include <nexus/quic/connection.hpp>
#include <nexus/quic/stream.hpp>
#include <nexus/global_init.hpp>

#include "certificate.hpp"

namespace nexus {

namespace {

const error_code ok;

auto capture(std::optional<error_code>& out) {
  return [&] (error_code ec, size_t bytes = 0) { out = ec; };
}

} // anonymous namespace

TEST(server, connect_stream)
{
  auto context = boost::asio::io_context{};
  auto ex = context.get_executor();
  auto global = global::init_client_server();

  const char* alpn = "\04test";
  auto ssl = test::init_server_context(alpn);
  auto sslc = test::init_client_context(alpn);

  auto server = quic::server{ex};
  const auto localhost = boost::asio::ip::make_address("127.0.0.1");
  auto acceptor = quic::acceptor{server, udp::endpoint{localhost, 0}, ssl};
  const auto endpoint = acceptor.local_endpoint();
  acceptor.listen(16);

  std::optional<error_code> accept_ec;
  auto sconn = quic::connection{acceptor};
  acceptor.async_accept(sconn, capture(accept_ec));

  auto client = quic::client{ex, udp::endpoint{}, sslc};
  auto cconn = quic::connection{client, endpoint, "host"};

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(accept_ec);
  EXPECT_EQ(ok, *accept_ec);

  std::optional<error_code> sstream_connect_ec;
  auto sstream = quic::stream{sconn};
  sconn.async_connect(sstream, capture(sstream_connect_ec));

  std::optional<error_code> cistream_accept_ec;
  auto cistream = quic::stream{cconn};
  cconn.async_accept(cistream, capture(cistream_accept_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(sstream_connect_ec);
  EXPECT_EQ(ok, *sstream_connect_ec);
  {
    const auto data = std::string_view{"1234"};
    std::optional<error_code> sstream_write_ec;
    sstream.async_write_some(boost::asio::buffer(data), capture(sstream_write_ec));
    sstream.shutdown(1);
    context.poll();
    ASSERT_FALSE(context.stopped());
    ASSERT_TRUE(sstream_write_ec);
    EXPECT_EQ(ok, *sstream_write_ec);
  }
  ASSERT_TRUE(cistream_accept_ec);
  EXPECT_EQ(ok, *cistream_accept_ec);
  {
    auto data = std::array<char, 5>{};
    std::optional<error_code> cistream_read_ec;
    cistream.async_read_some(boost::asio::buffer(data), capture(cistream_read_ec));
    context.poll();
    ASSERT_FALSE(context.stopped());
    ASSERT_TRUE(cistream_read_ec);
    EXPECT_EQ(ok, *cistream_read_ec);
    EXPECT_STREQ(data.data(), "1234");
  }
}

} // namespace nexus
