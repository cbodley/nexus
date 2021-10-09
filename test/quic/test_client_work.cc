#include <nexus/quic/server.hpp>
#include <gtest/gtest.h>
#include <optional>
#include <nexus/quic/client.hpp>
#include <nexus/quic/connection.hpp>
#include <nexus/global_init.hpp>

#include "certificate.hpp"

namespace nexus {

// constuct a client and server on different io_contexts
class Client : public testing::Test {
 protected:
  static constexpr const char* alpn = "\04quic";
  global::context global = global::init_client_server();
  asio::ssl::context ssl = test::init_server_context(alpn);
  asio::ssl::context sslc = test::init_client_context(alpn);
  asio::io_context scontext;
  quic::server server = quic::server{scontext.get_executor()};
  asio::ip::address localhost = asio::ip::make_address("127.0.0.1");
  quic::acceptor acceptor{server, udp::endpoint{localhost, 0}, ssl};
  asio::io_context ccontext;
  quic::client client{ccontext.get_executor(), udp::endpoint{}, sslc};
};

TEST_F(Client, connection_work)
{
  auto conn = quic::connection{client, acceptor.local_endpoint(), "host"};

  ccontext.poll();
  ASSERT_FALSE(ccontext.stopped()); // connection maintains work

  conn.close();

  ccontext.poll();
  ASSERT_TRUE(ccontext.stopped()); // close stops work
}

TEST_F(Client, two_connection_work)
{
  auto conn1 = quic::connection{client, acceptor.local_endpoint(), "host"};

  ccontext.poll();
  ASSERT_FALSE(ccontext.stopped());

  auto conn2 = quic::connection{client, acceptor.local_endpoint(), "host"};

  ccontext.poll();
  ASSERT_FALSE(ccontext.stopped());

  conn1.close();

  ccontext.poll();
  ASSERT_FALSE(ccontext.stopped());

  conn2.close();

  ccontext.poll();
  ASSERT_TRUE(ccontext.stopped());
}

} // namespace nexus
