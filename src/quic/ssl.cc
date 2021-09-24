#include <nexus/quic/ssl.hpp>
#include <nexus/quic/ssl_certificate_map.hpp>
#include <openssl/ssl.h>

void intrusive_ptr_add_ref(SSL_CTX* ctx)
{
  ::SSL_CTX_up_ref(ctx);
}
void intrusive_ptr_release(SSL_CTX* ctx)
{
  ::SSL_CTX_free(ctx);
}

namespace nexus::quic::ssl {

context_ptr context_create(const SSL_METHOD* method)
{
  constexpr bool add_ref = false; // SSL_CTX_new() starts with 1 ref
  return {::SSL_CTX_new(method), add_ref};
}

void certificate_map::insert(std::string_view sni, context_ptr ctx)
{
  certs.emplace(sni, std::move(ctx));
}

ssl_ctx_st* certificate_map::get_certificate_for_name(std::string_view sni)
{
  auto i = certs.find(sni);
  if (i != certs.end()) {
    return i->second.get();
  }
  return nullptr;
}

} // namespace nexus::quic::ssl
