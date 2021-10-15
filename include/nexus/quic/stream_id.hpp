#pragma once

#include <cstdint>

namespace nexus::quic {

/// stream identifier that is unique to a connection
using stream_id = uint64_t;


/// return true if the stream id was initiated by the client
inline bool client_initiated(stream_id id)
{
  return (id & 0x1) == 0;
}

/// return true if the stream id was initiated by the server
inline bool server_initiated(stream_id id)
{
  return (id & 0x1);
}

} // namespace nexus::quic
