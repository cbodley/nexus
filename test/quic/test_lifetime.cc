#include <nexus/quic/server.hpp>
#include <gtest/gtest.h>
#include <optional>
#include <nexus/quic/client.hpp>
#include <nexus/quic/connection.hpp>
#include <nexus/quic/stream.hpp>
#include <nexus/global_init.hpp>

#include "certificate.hpp"

namespace nexus {

namespace {

const error_code ok;

auto capture(std::optional<error_code>& ec) {
  return [&] (error_code e, size_t = 0) { ec = e; };
}

} // anonymous namespace

// establish a connection between client and server
class Lifetime : public testing::Test {
 protected:
  static constexpr const char* alpn = "\04quic";
  asio::io_context context;
  global::context global = global::init_client_server();
  asio::ssl::context ssl = test::init_server_context(alpn);
  asio::ssl::context sslc = test::init_client_context(alpn);
  quic::server server = quic::server{context.get_executor()};
  asio::ip::address localhost = asio::ip::make_address("127.0.0.1");
  quic::acceptor acceptor{server, udp::endpoint{localhost, 0}, ssl};
  quic::client client{context.get_executor(), udp::endpoint{}, sslc};
  quic::connection cconn{client, acceptor.local_endpoint(), "host"};

  void SetUp() override {
    //global.log_to_stderr("debug");
    acceptor.listen(16);
  }
};

TEST_F(Lifetime, stream_in_accept_handler)
{
  // allocate a stream and transfer ownership to the accept handler
  auto stream = std::make_unique<quic::stream>();
  auto &ref = *stream;
  std::optional<error_code> accept_ec;
  cconn.async_accept(ref, [&accept_ec, s=std::move(stream)] (error_code ec) {
      accept_ec = ec;
    });
}

TEST_F(Lifetime, stream_in_read_handler)
{
  // allocate a stream and transfer ownership to the accept handler
  auto stream = std::make_unique<quic::stream>();
  auto &ref = *stream;
  std::optional<error_code> connect_ec;
  cconn.async_connect(ref, capture(connect_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(connect_ec);
  EXPECT_EQ(ok, *connect_ec);

  auto data = std::array<char, 16>{};
  std::optional<error_code> read_ec;
  ref.async_read_some(asio::buffer(data),
    [&read_ec, s=std::move(stream)] (error_code ec, size_t) {
      read_ec = ec;
    });
}

} // namespace nexus
