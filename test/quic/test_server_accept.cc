#include <nexus/quic/server.hpp>
#include <gtest/gtest.h>
#include <optional>
#include <lsquic.h>
#include <openssl/ssl.h>
#include <nexus/quic/client.hpp>
#include <nexus/quic/stream.hpp>
#include <nexus/quic/ssl_certificate_map.hpp>
#include <nexus/quic/global_context.hpp>

#include "certificate.hpp"

namespace nexus {

namespace {

const error_code ok;

auto capture(std::optional<error_code>& out) {
  return [&out] (error_code ec) { out = ec; };
}

int alpn_select_cb(SSL* ssl, const unsigned char** out, unsigned char* outlen,
                   const unsigned char* in, unsigned int inlen, void* arg)
{
  const unsigned char alpn[] = {2, 'h', '3'};
  int r = SSL_select_next_proto(const_cast<unsigned char**>(out), outlen,
                                const_cast<unsigned char*>(in), inlen,
                                alpn, sizeof(alpn));
  if (r == OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_OK;
  } else {
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }
}

quic::ssl::context_ptr init_context()
{
  auto ctx = quic::ssl::context_create(::TLS_method());
  if (ctx) {
    ::SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION);
    ::SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION);
    ::SSL_CTX_set_default_verify_paths(ctx.get());
    ::SSL_CTX_set_alpn_select_cb(ctx.get(), alpn_select_cb, nullptr);

    auto key = test::generate_rsa_key(2048);
    auto cert = test::self_sign_certificate("US", "Nexus", "host", key,
                                            std::chrono::hours(24));
    if (::SSL_CTX_use_certificate(ctx.get(), cert.get()) != 1) {
      std::cerr << "SSL_CTX_use_certificate failed: "
          << ERR_error_string(ERR_get_error(), nullptr) << '\n';
      return nullptr;
    }
    if (::SSL_CTX_use_PrivateKey(ctx.get(), key.detach()) != 1) {
      std::cerr << "SSL_CTX_use_PrivateKey failed: "
          << ERR_error_string(ERR_get_error(), nullptr) << '\n';
      return nullptr;
    }
  }
  return ctx;
}

} // anonymous namespace

TEST(server, accept_wait) // accept() before a connection is received
{
  auto context = asio::io_context{};
  auto ex = context.get_executor();
  auto global = quic::global::init_client_server();

  auto ssl = init_context();

  auto certs = quic::ssl::certificate_map{};
  certs.insert("host", ssl);

  auto server = quic::server{ex, &certs};
  const auto localhost = asio::ip::make_address("127.0.0.1");
  auto acceptor = quic::acceptor{server, udp::endpoint{localhost, 0}, ssl};
  const auto endpoint = acceptor.local_endpoint();
  acceptor.listen(16);

  std::optional<error_code> accept_ec;
  auto sconn = quic::server_connection{acceptor};
  acceptor.async_accept(sconn, capture(accept_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  EXPECT_FALSE(accept_ec);

  auto client = quic::client{ex, udp::endpoint{}, "h3"};
  auto cconn = quic::client_connection{client, endpoint, "host"};

  std::optional<error_code> stream_connect_ec;
  auto cstream = quic::stream{cconn};
  cconn.async_connect(cstream, capture(stream_connect_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(accept_ec);
  EXPECT_EQ(ok, *accept_ec);
}

TEST(server, accept_ready) // accept() after a connection is received
{
  auto context = asio::io_context{};
  auto ex = context.get_executor();
  auto global = quic::global::init_client_server();

  auto ssl = init_context();

  auto certs = quic::ssl::certificate_map{};
  certs.insert("host", ssl);

  auto server = quic::server{ex, &certs};
  const auto localhost = asio::ip::make_address("127.0.0.1");
  auto acceptor = quic::acceptor{server, udp::endpoint{localhost, 0}, ssl};
  const auto endpoint = acceptor.local_endpoint();
  acceptor.listen(16);

  auto client = quic::client{ex, udp::endpoint{}, "h3"};
  auto cconn = quic::client_connection{client, endpoint, "host"};

  std::optional<error_code> stream_connect_ec;
  auto cstream = quic::stream{cconn};
  cconn.async_connect(cstream, capture(stream_connect_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  EXPECT_TRUE(stream_connect_ec);

  std::optional<error_code> accept_ec;
  auto sconn = quic::server_connection{acceptor};
  acceptor.async_accept(sconn, capture(accept_ec));

  context.poll();
  ASSERT_FALSE(context.stopped());
  ASSERT_TRUE(accept_ec);
  EXPECT_EQ(ok, *accept_ec);
}

} // namespace nexus
