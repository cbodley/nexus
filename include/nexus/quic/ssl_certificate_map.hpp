#pragma once

#include <map>
#include <string>
#include <nexus/quic/ssl.hpp>

namespace nexus::quic::ssl {

class certificate_map : public certificate_provider {
  using transparent_less = std::less<>; // enable lookup by string_view
  std::map<std::string, asio::ssl::context, transparent_less> certs;
 public:
  void insert(std::string_view sni, asio::ssl::context&& ctx);

  ssl_ctx_st* get_certificate_for_name(std::string_view sni) override;
};

} // namespace nexus::quic::ssl
