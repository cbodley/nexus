#pragma once

#include <nexus/detail/encoding/network_order.hpp>
#include <nexus/quic/detail/varint.hpp>

namespace nexus::quic::detail {

using nexus::detail::network_order_encoder;
using nexus::detail::network_order_decoder;

struct varint_encoder {
  varint_t value;
  uint8_t length;
  varint_encoder(varint_t value) noexcept
    : value(value), length(varint_length(value)) {}
  varint_encoder(varint_t value, uint8_t length) noexcept
    : value(value), length(length) {}
};

size_t encoded_size(const varint_encoder& varint)
{
  return varint.length;
}

template <typename OutputIterator>
void encode(OutputIterator& out, const varint_encoder& e)
{
  varint_t mask = varint_length_mask(e.length);
  mask <<= 8 * e.length - 2;
  encode(out, network_order_encoder{mask | e.value, e.length});
}

struct varint_decoder {
  varint_t& value;
  varint_decoder(varint_t& value) noexcept : value(value) {}
};

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, varint_decoder&& d)
{
  if (remaining < 1) {
    return false;
  }
  const auto length = varint_length_from_mask(*in >> 6);
  if (!decode(in, remaining, network_order_decoder{d.value, length})) {
    return false;
  }
  // clear the length-prefix bits
  const auto bits = 8 * length - 2;
  d.value &= (1ull << bits) - 1;
  return true;
}

} // namespace nexus::quic::detail
