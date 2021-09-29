#include <memory>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <boost/intrusive_ptr.hpp>
#include "certificate.hpp"

void intrusive_ptr_add_ref(EVP_PKEY* pkey)
{
  ::EVP_PKEY_up_ref(pkey);
}
void intrusive_ptr_release(EVP_PKEY* pkey)
{
  ::EVP_PKEY_free(pkey);
}

namespace nexus::test {

using evp_pkey_ptr = boost::intrusive_ptr<evp_pkey_st>;

struct x509_deleter { void operator()(x509_st* p) { ::X509_free(p); } };
using x509_ptr = std::unique_ptr<x509_st, x509_deleter>;

struct evp_pkey_ctx_deleter {
  void operator()(EVP_PKEY_CTX* p) { ::EVP_PKEY_CTX_free(p); };
};
using evp_pkey_ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, evp_pkey_ctx_deleter>;


evp_pkey_ptr generate_rsa_key(int bits, error_code& ec)
{
  auto ctx = evp_pkey_ctx_ptr{::EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr)};
  if (!ctx) {
    ec.assign(ERR_get_error(), asio::error::get_ssl_category());
    return nullptr;
  }
  if (::EVP_PKEY_keygen_init(ctx.get()) != 1) {
    ec.assign(ERR_get_error(), asio::error::get_ssl_category());
    return nullptr;
  }
  if (::EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) != 1) {
    ec.assign(ERR_get_error(), asio::error::get_ssl_category());
    return nullptr;
  }
  EVP_PKEY *pkey = nullptr;
  if (::EVP_PKEY_keygen(ctx.get(), &pkey) != 1) {
    ec.assign(ERR_get_error(), asio::error::get_ssl_category());
    return nullptr;
  }
  constexpr bool add_ref = false; // EVP_PKEY_generate() starts with 1 ref
  return {pkey, add_ref};
}

int add_name_entry(X509_NAME* name, const char* field, std::string_view value)
{
  auto bytes = reinterpret_cast<const unsigned char*>(value.data());
  return ::X509_NAME_add_entry_by_txt(name, field, MBSTRING_ASC,
                                      bytes, value.size(), -1, 0);
}

x509_ptr self_sign_certificate(evp_pkey_ptr key,
                               std::string_view country,
                               std::string_view organization,
                               std::string_view common_name,
                               std::chrono::seconds duration,
                               error_code& ec)
{
  auto cert = x509_ptr{::X509_new()};
  if (!cert) {
    ec.assign(ERR_get_error(), asio::error::get_ssl_category());
    return nullptr;
  }
  if (::X509_set_version(cert.get(), 2) != 1) {
    ec.assign(ERR_get_error(), asio::error::get_ssl_category());
    return nullptr;
  }
  if (::ASN1_INTEGER_set(::X509_get_serialNumber(cert.get()), 1) != 1) {
    ec.assign(ERR_get_error(), asio::error::get_ssl_category());
    return nullptr;
  }
  if (::X509_set_pubkey(cert.get(), key.get()) != 1) {
    ec.assign(ERR_get_error(), asio::error::get_ssl_category());
    return nullptr;
  }
  if (!::X509_gmtime_adj(::X509_get_notBefore(cert.get()), 0)) {
    ec.assign(ERR_get_error(), asio::error::get_ssl_category());
    return nullptr;
  }
  if (!::X509_gmtime_adj(::X509_get_notAfter(cert.get()), duration.count())) {
    ec.assign(ERR_get_error(), asio::error::get_ssl_category());
    return nullptr;
  }
  auto name = ::X509_get_subject_name(cert.get());
  if (add_name_entry(name, "C", country) != 1) {
    ec.assign(ERR_get_error(), asio::error::get_ssl_category());
    return nullptr;
  }
  if (add_name_entry(name, "O", organization) != 1) {
    ec.assign(ERR_get_error(), asio::error::get_ssl_category());
    return nullptr;
  }
  if (add_name_entry(name, "CN", common_name) != 1) {
    ec.assign(ERR_get_error(), asio::error::get_ssl_category());
    return nullptr;
  }
  if (::X509_set_issuer_name(cert.get(), name) != 1) {
    ec.assign(ERR_get_error(), asio::error::get_ssl_category());
    return nullptr;
  }
  if (::X509_sign(cert.get(), key.get(), ::EVP_sha256()) == 0) {
    ec.assign(ERR_get_error(), asio::error::get_ssl_category());
    return nullptr;
  }
  return cert;
}

void self_sign_certificate(asio::ssl::context& ctx,
                           std::string_view country,
                           std::string_view organization,
                           std::string_view common_name,
                           std::chrono::seconds duration,
                           error_code& ec)
{
  auto key = test::generate_rsa_key(2048, ec);
  if (ec) {
    return;
  }
  auto cert = test::self_sign_certificate(key, country, organization,
                                          common_name, duration, ec);
  if (ec) {
    return;
  }
  if (::SSL_CTX_use_certificate(ctx.native_handle(), cert.get()) != 1) {
    ec.assign(ERR_get_error(), asio::error::get_ssl_category());
    return;
  }
  if (::SSL_CTX_use_PrivateKey(ctx.native_handle(), key.get()) != 1) {
    ec.assign(ERR_get_error(), asio::error::get_ssl_category());
    return;
  }
}

void self_sign_certificate(asio::ssl::context& ctx,
                           std::string_view country,
                           std::string_view organization,
                           std::string_view common_name,
                           std::chrono::seconds duration)
{
  error_code ec;
  self_sign_certificate(ctx, country, organization, common_name, duration, ec);
  if (ec) {
    throw system_error(ec);
  }
}

int alpn_select_cb(SSL* ssl, const unsigned char** out, unsigned char* outlen,
                   const unsigned char* in, unsigned int inlen, void* arg)
{
  auto alpn = static_cast<const char*>(arg);
  int r = ::SSL_select_next_proto(const_cast<unsigned char**>(out), outlen,
                                  const_cast<unsigned char*>(in), inlen,
                                  reinterpret_cast<const unsigned char*>(alpn),
                                  strlen(alpn));
  if (r == OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_OK;
  } else {
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }
}

asio::ssl::context init_client_context(const char* alpn)
{
  auto ctx = asio::ssl::context{asio::ssl::context::tlsv13};
  ::SSL_CTX_set_min_proto_version(ctx.native_handle(), TLS1_3_VERSION);
  ::SSL_CTX_set_max_proto_version(ctx.native_handle(), TLS1_3_VERSION);
  ::SSL_CTX_set_alpn_protos(ctx.native_handle(),
                            reinterpret_cast<const unsigned char*>(alpn),
                            strlen(alpn));
  return ctx;
}

asio::ssl::context init_server_context(const char* alpn)
{
  auto ctx = asio::ssl::context{asio::ssl::context::tlsv13};
  ::SSL_CTX_set_min_proto_version(ctx.native_handle(), TLS1_3_VERSION);
  ::SSL_CTX_set_max_proto_version(ctx.native_handle(), TLS1_3_VERSION);
  ::SSL_CTX_set_alpn_select_cb(ctx.native_handle(), alpn_select_cb,
                               const_cast<char*>(alpn));
  self_sign_certificate(ctx, "US", "Nexus", "host", std::chrono::hours(24));
  return ctx;
}

} // namespace nexus::test
