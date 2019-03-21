#pragma once

#include <http2/protocol.hpp>

namespace http2::protocol::detail {

template <typename OutputIterator>
OutputIterator encode_priority(const stream_priority& prio, OutputIterator pos)
{
  uint8_t excl = prio.exclusive ? 0x80 : 0;
  *pos++ = excl | (0x7f & (prio.dependency >> 24));
  *pos++ = prio.dependency >> 16;
  *pos++ = prio.dependency >> 8;
  *pos++ = prio.dependency;
  *pos++ = prio.weight;
  return pos;
}

template <typename InputIterator>
InputIterator decode_priority(InputIterator pos, stream_priority& prio)
{
  auto p = static_cast<uint8_t>(*pos++);
  prio.exclusive = (p & 0x80) != 0;
  prio.dependency = (p & 0x7f) << 24;
  prio.dependency |= static_cast<protocol::stream_identifier>(*pos++) << 16;
  prio.dependency |= static_cast<protocol::stream_identifier>(*pos++) << 8;
  prio.dependency |= static_cast<protocol::stream_identifier>(*pos++);
  prio.weight = static_cast<uint8_t>(*pos++);
  return pos;
}

} // namespace http::protocol::detail
