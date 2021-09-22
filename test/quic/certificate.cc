#include <iostream>
#include "certificate.hpp"
#include <openssl/rsa.h>
#include <openssl/x509.h>

void intrusive_ptr_add_ref(EVP_PKEY* pkey)
{
  ::EVP_PKEY_up_ref(pkey);
}
void intrusive_ptr_release(EVP_PKEY* pkey)
{
  ::EVP_PKEY_free(pkey);
}

namespace nexus::test {

void x509_deleter::operator()(X509* p) { ::X509_free(p); }

struct evp_pkey_ctx_deleter {
  void operator()(EVP_PKEY_CTX* p) { ::EVP_PKEY_CTX_free(p); };
};
using evp_pkey_ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, evp_pkey_ctx_deleter>;

struct x509_extension_deleter {
  void operator()(X509_EXTENSION* p) { ::X509_EXTENSION_free(p); };
};
using x509_extension_ptr = std::unique_ptr<X509_EXTENSION, x509_extension_deleter>;


evp_pkey_ptr generate_rsa_key(int bits)
{
  auto ctx = evp_pkey_ctx_ptr{::EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr)};
  if (!ctx) {
    std::cerr << "EVP_PKEY_CTX_new_id returned null: "
        << ERR_error_string(ERR_get_error(), nullptr) << '\n';
    return nullptr;
  }
  if (::EVP_PKEY_keygen_init(ctx.get()) != 1) {
    std::cerr << "EVP_PKEY_keygen_init failed: "
        << ERR_error_string(ERR_get_error(), nullptr) << '\n';
    return nullptr;
  }
  if (::EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) != 1) {
    std::cerr << "EVP_PKEY_CTX_set_rsa_keygen_bits failed: "
        << ERR_error_string(ERR_get_error(), nullptr) << '\n';
    return nullptr;
  }
  EVP_PKEY *pkey = nullptr;
  if (::EVP_PKEY_keygen(ctx.get(), &pkey) != 1) {
    std::cerr << "EVP_PKEY_keygen failed: "
        << ERR_error_string(ERR_get_error(), nullptr) << '\n';
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

x509_ptr self_sign_certificate(std::string_view country,
                               std::string_view organization,
                               std::string_view common_name,
                               evp_pkey_ptr key,
                               std::chrono::seconds duration)
{
  auto cert = x509_ptr{::X509_new()};
  if (!cert) {
    std::cerr << "X509_new returned null: "
        << ERR_error_string(ERR_get_error(), nullptr) << '\n';
    return nullptr;
  }
  if (::X509_set_version(cert.get(), 2) != 1) {
    std::cerr << "X509_set_version failed: "
        << ERR_error_string(ERR_get_error(), nullptr) << '\n';
    return nullptr;
  }
  if (::ASN1_INTEGER_set(::X509_get_serialNumber(cert.get()), 1) != 1) {
    std::cerr << "ASN1_INTEGER_set failed: "
        << ERR_error_string(ERR_get_error(), nullptr) << '\n';
    return nullptr;
  }
  if (::X509_set_pubkey(cert.get(), key.get()) != 1) {
    std::cerr << "X509_set_pubkey failed: "
        << ERR_error_string(ERR_get_error(), nullptr) << '\n';
    return nullptr;
  }
  if (!::X509_gmtime_adj(::X509_get_notBefore(cert.get()), 0)) {
    std::cerr << "X509_gmtime_adj failed: "
        << ERR_error_string(ERR_get_error(), nullptr) << '\n';
    return nullptr;
  }
  if (!::X509_gmtime_adj(::X509_get_notAfter(cert.get()), duration.count())) {
    std::cerr << "X509_gmtime_adj failed: "
        << ERR_error_string(ERR_get_error(), nullptr) << '\n';
    return nullptr;
  }
  auto name = ::X509_get_subject_name(cert.get());
  if (add_name_entry(name, "C", country) != 1) {
    std::cerr << "X509_NAME_add_entry_by_txt failed: "
        << ERR_error_string(ERR_get_error(), nullptr) << '\n';
    return nullptr;
  }
  if (add_name_entry(name, "O", organization) != 1) {
    std::cerr << "X509_NAME_add_entry_by_txt failed: "
        << ERR_error_string(ERR_get_error(), nullptr) << '\n';
    return nullptr;
  }
  if (add_name_entry(name, "CN", common_name) != 1) {
    std::cerr << "X509_NAME_add_entry_by_txt failed: "
        << ERR_error_string(ERR_get_error(), nullptr) << '\n';
    return nullptr;
  }
  if (::X509_set_issuer_name(cert.get(), name) != 1) {
    std::cerr << "X509_set_issuer_name failed: "
        << ERR_error_string(ERR_get_error(), nullptr) << '\n';
    return nullptr;
  }
  if (::X509_sign(cert.get(), key.get(), ::EVP_sha256()) == 0) {
    std::cerr << "X509_sign failed: "
        << ERR_error_string(ERR_get_error(), nullptr) << '\n';
    return nullptr;
  }
  return cert;
}

} // namespace nexus::test
