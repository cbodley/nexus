#pragma once

#include <chrono>
#include <memory>
#include <string_view>
#include <boost/intrusive_ptr.hpp>

struct evp_pkey_st; //  EVP_PKEY
struct x509_st; // X509

void intrusive_ptr_add_ref(evp_pkey_st* pkey);
void intrusive_ptr_release(evp_pkey_st* pkey);

namespace nexus::test {

using evp_pkey_ptr = boost::intrusive_ptr<evp_pkey_st>;

evp_pkey_ptr generate_rsa_key(int bits);

struct x509_deleter { void operator()(x509_st* p); };
using x509_ptr = std::unique_ptr<x509_st, x509_deleter>;

x509_ptr self_sign_certificate(std::string_view country,
                               std::string_view organization,
                               std::string_view common_name,
                               evp_pkey_ptr key,
                               std::chrono::seconds duration);

} // namespace nexus::test
