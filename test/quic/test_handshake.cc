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

void test_stream_connect_during_handshake(asio::io_context& context,
                                          quic::connection& cconn,
                                          error_code expected_ec)
{
  // start a pending async_connect() before the handshake initiates, and test
  // that the handshake error is delivered to the pending operation
  std::optional<error_code> connect1_ec;
  auto cstream1 = quic::stream{cconn};
  cconn.async_connect(cstream1, capture(connect1_ec));

  // TODO: assert connection handshake has not finished
  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(connect1_ec);
  EXPECT_EQ(expected_ec, *connect1_ec);

  // the handshake error was already delivered; test that another
  // async_connect() call does not see it
  std::optional<error_code> connect2_ec;
  auto cstream2 = quic::stream{cconn};
  cconn.async_connect(cstream2, capture(connect2_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(connect2_ec);
  EXPECT_EQ(errc::bad_file_descriptor, *connect2_ec);
}

void test_stream_connect_after_handshake(asio::io_context& context,
                                         quic::connection& cconn,
                                         error_code expected_ec)
{
  // run the handshake while there are no pending operations, so it has nowhere
  // to deliver the handshake error
  context.poll();
  ASSERT_FALSE(context.stopped());
  // TODO: assert connection handshake finished

  // test that the stored handshake error gets delivered to async_connect()
  std::optional<error_code> connect1_ec;
  auto cstream1 = quic::stream{cconn};
  cconn.async_connect(cstream1, capture(connect1_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(connect1_ec);
  EXPECT_EQ(expected_ec, *connect1_ec);

  // the handshake error was already delivered; test that another
  // async_connect() call does not see it
  std::optional<error_code> connect2_ec;
  auto cstream2 = quic::stream{cconn};
  cconn.async_connect(cstream2, capture(connect2_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(connect2_ec);
  EXPECT_EQ(errc::bad_file_descriptor, *connect2_ec);
}

void test_stream_accept_during_handshake(asio::io_context& context,
                                         quic::connection& cconn,
                                         error_code expected_ec)
{
  // start a pending async_accept() before the handshake initiates, and test
  // that the handshake error is delivered to the pending operation
  std::optional<error_code> accept1_ec;
  auto cstream1 = quic::stream{cconn};
  cconn.async_accept(cstream1, capture(accept1_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(accept1_ec);
  EXPECT_EQ(expected_ec, *accept1_ec);

  // the handshake error was already delivered; test that another
  // async_accept() call does not see it
  std::optional<error_code> accept2_ec;
  auto cstream2 = quic::stream{cconn};
  cconn.async_accept(cstream2, capture(accept2_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(accept2_ec);
  EXPECT_EQ(errc::bad_file_descriptor, *accept2_ec);
}

void test_stream_accept_after_handshake(asio::io_context& context,
                                        quic::connection& cconn,
                                        error_code expected_ec)
{
  // run the handshake while there are no pending operations, so it has nowhere
  // to deliver the handshake error
  context.poll();
  ASSERT_FALSE(context.stopped());
  // TODO: assert connection handshake finished

  // test that the stored handshake error gets delivered to async_accept()
  std::optional<error_code> accept1_ec;
  auto cstream1 = quic::stream{cconn};
  cconn.async_accept(cstream1, capture(accept1_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(accept1_ec);
  EXPECT_EQ(expected_ec, *accept1_ec);

  // the handshake error was already delivered; test that another
  // async_accept() call does not see it
  std::optional<error_code> accept2_ec;
  auto cstream2 = quic::stream{cconn};
  cconn.async_accept(cstream2, capture(accept2_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(accept2_ec);
  EXPECT_EQ(errc::bad_file_descriptor, *accept2_ec);
}

void test_server_accept_not_ready(asio::io_context& context,
                                  quic::acceptor& acceptor,
                                  quic::connection& sconn)
{
  // test that async_accept() never sees this connection attempt
  std::optional<error_code> accept_ec;
  acceptor.async_accept(sconn, capture(accept_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_FALSE(accept_ec);
}

} // anonymous namespace

// try to connect a client and server with incompatible protocol names
class BadALPN : public testing::Test {
 protected:
  asio::io_context context;
  global::context global = global::init_client_server();
  asio::ssl::context ssl = test::init_server_context("\04quic");
  asio::ssl::context sslc = test::init_client_context("\02j5");
  quic::server server = quic::server{context.get_executor()};
  asio::ip::address localhost = asio::ip::make_address("127.0.0.1");
  quic::acceptor acceptor{server, udp::endpoint{localhost, 0}, ssl};
  quic::connection sconn{acceptor};
  quic::client client{context.get_executor(), udp::endpoint{}, sslc};
  quic::connection cconn{client, acceptor.local_endpoint(), "host"};

  void SetUp() override {
    acceptor.listen(16);
  }
};

TEST_F(BadALPN, stream_connect_during_handshake)
{
  auto expected = make_error_code(quic::tls_alert::no_application_protocol);
  test_stream_connect_during_handshake(context, cconn, expected);
  test_server_accept_not_ready(context, acceptor, sconn);
}
TEST_F(BadALPN, stream_connect_after_handshake)
{
  auto expected = make_error_code(quic::tls_alert::no_application_protocol);
  test_stream_connect_after_handshake(context, cconn, expected);
  test_server_accept_not_ready(context, acceptor, sconn);
}
TEST_F(BadALPN, stream_accept_during_handshake)
{
  auto expected = make_error_code(quic::tls_alert::no_application_protocol);
  test_stream_accept_during_handshake(context, cconn, expected);
  test_server_accept_not_ready(context, acceptor, sconn);
}
TEST_F(BadALPN, stream_accept_after_handshake)
{
  auto expected = make_error_code(quic::tls_alert::no_application_protocol);
  test_stream_accept_after_handshake(context, cconn, expected);
  test_server_accept_not_ready(context, acceptor, sconn);
}

// try to connect a client with certificate verification to a server using a
// self-signed certificate
class BadVerifyServer : public testing::Test {
 protected:
  static constexpr const char* alpn = "\04quic";
  static asio::ssl::context verifying_client_context() {
    auto ssl = test::init_client_context(alpn);
    ssl.set_verify_mode(asio::ssl::verify_peer);
    return ssl;
  }
  asio::io_context context;
  global::context global = global::init_client_server();
  asio::ssl::context ssl = test::init_server_context(alpn);
  asio::ssl::context sslc = verifying_client_context();
  quic::server server = quic::server{context.get_executor()};
  asio::ip::address localhost = asio::ip::make_address("127.0.0.1");
  quic::acceptor acceptor{server, udp::endpoint{localhost, 0}, ssl};
  quic::connection sconn{acceptor};
  quic::client client{context.get_executor(), udp::endpoint{}, sslc};
  quic::connection cconn{client, acceptor.local_endpoint(), "host"};

  void SetUp() override {
    acceptor.listen(16);
  }
};

TEST_F(BadVerifyServer, stream_connect_during_handshake)
{
  auto expected = make_error_code(quic::connection_error::handshake_failed);
  test_stream_connect_during_handshake(context, cconn, expected);
  test_server_accept_not_ready(context, acceptor, sconn);
}
TEST_F(BadVerifyServer, stream_connect_after_handshake)
{
  auto expected = make_error_code(quic::connection_error::handshake_failed);
  test_stream_connect_after_handshake(context, cconn, expected);
  test_server_accept_not_ready(context, acceptor, sconn);
}
TEST_F(BadVerifyServer, stream_accept_during_handshake)
{
  auto expected = make_error_code(quic::connection_error::handshake_failed);
  test_stream_accept_during_handshake(context, cconn, expected);
  test_server_accept_not_ready(context, acceptor, sconn);
}
TEST_F(BadVerifyServer, stream_accept_after_handshake)
{
  auto expected = make_error_code(quic::connection_error::handshake_failed);
  test_stream_accept_after_handshake(context, cconn, expected);
  test_server_accept_not_ready(context, acceptor, sconn);
}

// try to connect a client to a server that wants to verify client
class BadVerifyClient : public testing::Test {
 protected:
  static constexpr const char* alpn = "\04quic";
  static asio::ssl::context verifying_server_context() {
    auto ssl = test::init_server_context(alpn);
    ssl.set_verify_mode(asio::ssl::verify_peer |
                        asio::ssl::verify_fail_if_no_peer_cert);
    return ssl;
  }
  asio::io_context context;
  global::context global = global::init_client_server();
  asio::ssl::context ssl = verifying_server_context();
  asio::ssl::context sslc = test::init_client_context(alpn);
  quic::server server = quic::server{context.get_executor()};
  asio::ip::address localhost = asio::ip::make_address("127.0.0.1");
  quic::acceptor acceptor{server, udp::endpoint{localhost, 0}, ssl};
  quic::connection sconn{acceptor};
  quic::client client{context.get_executor(), udp::endpoint{}, sslc};
  quic::connection cconn{client, acceptor.local_endpoint(), "host"};

  void SetUp() override {
    //global.log_to_stderr("debug");
    acceptor.listen(16);
  }
};

TEST_F(BadVerifyClient, stream_connect_during_handshake)
{
  std::optional<error_code> connect_ec;
  auto cstream = quic::stream{cconn};
  cconn.async_connect(cstream, capture(connect_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(connect_ec);
  // XXX: the client actually sees the handshake succeed here. lsquic
  // calls on_hsk_done(LSQ_HSK_OK) and on_new_stream(), then later gets
  // on_conncloseframe_received() with tls alert 'certificate required'
  EXPECT_EQ(ok, *connect_ec);

  auto data = std::array<char, 16>{};
  std::optional<error_code> write1_ec;
  cstream.async_write_some(asio::buffer(data), capture(write1_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(write1_ec);
  EXPECT_EQ(quic::tls_alert::certificate_required, *write1_ec);

  std::optional<error_code> write2_ec;
  cstream.async_write_some(asio::buffer(data), capture(write2_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(write2_ec);
  EXPECT_EQ(errc::bad_file_descriptor, *write2_ec);

  test_server_accept_not_ready(context, acceptor, sconn);
}
TEST_F(BadVerifyClient, stream_connect_after_handshake)
{
  auto expected = make_error_code(quic::tls_alert::certificate_required);
  test_stream_connect_after_handshake(context, cconn, expected);
  test_server_accept_not_ready(context, acceptor, sconn);
}
TEST_F(BadVerifyClient, stream_accept_during_handshake)
{
  auto expected = make_error_code(quic::tls_alert::certificate_required);
  test_stream_accept_during_handshake(context, cconn, expected);
  test_server_accept_not_ready(context, acceptor, sconn);
}
TEST_F(BadVerifyClient, stream_accept_after_handshake)
{
  auto expected = make_error_code(quic::tls_alert::certificate_required);
  test_stream_accept_after_handshake(context, cconn, expected);
  test_server_accept_not_ready(context, acceptor, sconn);
}

} // namespace nexus
