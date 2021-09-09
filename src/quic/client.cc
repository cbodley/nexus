#include <nexus/quic/http3/client.hpp>
#include <lsquic.h>

namespace nexus::quic::http3 {

// this is here just to hide LSENG_HTTP from the header
client::client() : state(LSENG_HTTP) {}

} // namespace nexus::quic::http3
