#pragma once

#include <cstdint>
#include <nexus/detail/log2.hpp>

namespace nexus::quic::detail {

using nexus::detail::log2_nonzero;

using varint_t = uint64_t;

constexpr unsigned int varint_max_bits = 62; // 2 bits for length prefix
constexpr varint_t varint_max = (1llu << varint_max_bits) - 1;

inline unsigned int varint_length(varint_t x)
{
  if (x < 0x40) { // avoid undefined clz(0) for bits and bytes
    return 1;
  }
  unsigned int bits = 2 + log2_nonzero(x); // 2 extra bits for length prefix
  return 2u << log2_nonzero(bits / 8); // bytes rounded up to powers of 2
}

inline unsigned int varint_length_mask(unsigned int length)
{
  return log2_nonzero(length);
}

inline unsigned int varint_length_from_mask(unsigned int mask)
{
  return 1u << mask;
}

} // namespace nexus::quic::detail
