#include <nexus/quic/ssl.hpp>
#include <nexus/quic/ssl_certificate_map.hpp>
#include <openssl/ssl.h>

namespace nexus::quic::ssl {

void certificate_map::insert(std::string_view sni, asio::ssl::context&& ctx)
{
  certs.emplace(sni, std::move(ctx));
}

ssl_ctx_st* certificate_map::get_certificate_for_name(std::string_view sni)
{
  auto i = certs.find(sni);
  if (i != certs.end()) {
    return i->second.native_handle();
  }
  return nullptr;
}

} // namespace nexus::quic::ssl
