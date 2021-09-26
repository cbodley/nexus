#pragma once

#include <string_view>

#include <asio/ssl.hpp>

namespace nexus::quic::ssl {

/// certificate provider interface used with SSL_set_cert_cb(), allowing the
/// server to select different SSL certificates for each requested hostname
class certificate_provider {
 public:
  virtual ~certificate_provider() = default;

  /// when a client connects to the given server name, return an SSL_CTX to use
  /// for its handshake. return nullptr to reject the client's handshake
  virtual SSL_CTX* get_certificate_for_name(std::string_view sni) = 0;
};

} // namespace nexus::quic::ssl
