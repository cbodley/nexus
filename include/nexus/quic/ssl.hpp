#pragma once

#include <string_view>

#include <boost/intrusive_ptr.hpp>

#include <nexus/error_code.hpp>

struct ssl_ctx_st; // SSL_CTX from openssl/ssl.h
struct ssl_method_st; // SSL_METHOD

void intrusive_ptr_add_ref(ssl_ctx_st* ctx); // calls SSL_CTX_up_ref()
void intrusive_ptr_release(ssl_ctx_st* ctx); // calls SSL_CTX_free()

namespace nexus::quic::ssl {

/// a reference-counted smart pointer for SSL_CTX
using context_ptr = boost::intrusive_ptr<ssl_ctx_st>;

/// create a SSL_CTX with SSL_CTX_new()
context_ptr context_create(const ssl_method_st* method);


/// certificate provider interface used with SSL_set_cert_cb(), allowing the
/// server to select different SSL certificates for each requested hostname
class certificate_provider {
 public:
  virtual ~certificate_provider() = default;

  /// when a client connects to the given server name, return an SSL_CTX to use
  /// for its handshake. return nullptr to reject the client's handshake
  virtual ssl_ctx_st* get_certificate_for_name(std::string_view sni) = 0;
};

} // namespace nexus::quic::ssl
