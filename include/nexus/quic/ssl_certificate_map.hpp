#pragma once

#include <map>
#include <string>
#include <nexus/quic/ssl.hpp>

namespace nexus::quic::ssl {

class certificate_map : public cert_lookup {
  using transparent_less = std::less<>; // enable lookup by string_view
  std::map<std::string, context_ptr, transparent_less> certs;
 public:
  void insert(std::string_view sni, context_ptr ctx);

  ssl_ctx_st* lookup_cert(std::string_view sni) override;
};

} // namespace nexus::quic::ssl
