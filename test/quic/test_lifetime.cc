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
auto capture(std::optional<error_code>& ec, quic::stream& stream) {
  return [&] (error_code e, quic::stream&& s) {
    ec = e;
    stream = std::move(s);
  };
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

  void SetUp() override {
    //global.log_to_stderr("debug");
    acceptor.listen(16);
  }
};

TEST_F(Lifetime, connection_in_accept_handler)
{
  // allocate a server connection and move it into the accept handler
  auto sconn = std::make_unique<quic::connection>(acceptor);
  auto &ref = *sconn;
  std::optional<error_code> accept_ec;
  acceptor.async_accept(ref, [&accept_ec, c=std::move(sconn)] (error_code ec) {
      accept_ec = ec;
    });
  ASSERT_FALSE(accept_ec);
}

TEST_F(Lifetime, stream_in_connect_handler)
{
  quic::connection cconn{client, acceptor.local_endpoint(), "host"};

  std::optional<error_code> connect_ec;
  quic::stream stream;
  cconn.async_connect(capture(connect_ec, stream));
  ASSERT_FALSE(connect_ec);
  // don't run the completion handler
}

TEST_F(Lifetime, stream_in_read_handler)
{
  quic::connection cconn{client, acceptor.local_endpoint(), "host"};

  std::optional<error_code> connect_ec;
  quic::stream stream;
  cconn.async_connect(capture(connect_ec, stream));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(connect_ec);
  EXPECT_EQ(ok, *connect_ec);

  // move the stream into a unique_ptr and transfer it into the read handler
  auto pstream = std::make_unique<quic::stream>(std::move(stream));
  auto &ref = *pstream;
  auto data = std::array<char, 16>{};
  std::optional<error_code> read_ec;
  ref.async_read_some(asio::buffer(data),
    [&read_ec, s=std::move(pstream)] (error_code ec, size_t) {
      read_ec = ec;
    });
  ASSERT_FALSE(read_ec);
}

} // namespace nexus
