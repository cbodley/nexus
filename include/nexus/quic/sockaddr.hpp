#pragma once

#include <netinet/ip.h> // sockaddr

namespace nexus::quic {

union sockaddr_union {
  sockaddr_storage storage;
  sockaddr addr;
  sockaddr_in addr4;
  sockaddr_in6 addr6;
};

} // namespace nexus::quic
