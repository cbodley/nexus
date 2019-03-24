#pragma once

#include <cstdint>
#include <cstddef>
#include <limits>

#include <boost/asio/buffer.hpp>
#include <boost/asio/buffers_iterator.hpp>

namespace nexus::http2::detail::hpack {

template <typename T> struct numeric_traits : std::numeric_limits<T> {};

template <size_t PrefixN, typename IntegerT, typename DynamicBuffer>
size_t encode_integer(IntegerT value, uint8_t padding, DynamicBuffer& buffer)
{
  using numeric_traits = numeric_traits<IntegerT>;

  static_assert(PrefixN >= 1 && PrefixN <= 8);
  static_assert(numeric_traits::is_integer);
  static_assert(!numeric_traits::is_signed);

  constexpr uint8_t prefix_mask = (1 << PrefixN) - 1;
  constexpr int max_octets = 1 + (numeric_traits::digits + 6) / 7;
  uint8_t buf[max_octets];
  size_t count = 0;

  if (value < prefix_mask) {
    if constexpr (PrefixN == 8) {
      // encode the value in the prefix bits
      buf[count++] = value;
    } else {
      // encode the value in the prefix bits, leaving padding intact
      buf[count++] = (padding & ~prefix_mask) | value;
    }
  } else {
    // set all prefix bits to 1
    if constexpr (PrefixN == 8) {
      buf[count++] = prefix_mask;
    } else {
      buf[count++] = padding | prefix_mask;
    }
    value -= prefix_mask;
    while (value >= 128u) {
      buf[count++] = value % 128 + 128;
      value = value / 128;
    }
    buf[count++] = value;
  }

  boost::asio::buffer_copy(buffer.prepare(count),
                           boost::asio::buffer(buf, count));
  buffer.commit(count);
  return count;
}

template <size_t PrefixN, typename ConstBufferSequence, typename IntegerT>
bool decode_integer(boost::asio::buffers_iterator<ConstBufferSequence>& pos,
                    boost::asio::buffers_iterator<ConstBufferSequence> end,
                    IntegerT& value, uint8_t& padding)
{
  using numeric_traits = numeric_traits<IntegerT>;

  static_assert(PrefixN >= 1 && PrefixN <= 8);
  static_assert(numeric_traits::is_integer);
  static_assert(!numeric_traits::is_signed);

  constexpr uint8_t prefix_mask = (1 << PrefixN) - 1;

  if (pos == end) {
    // TODO: throw on error and return iterator pos
    return false;
  }
  uint8_t byte = *pos++;
  value = byte & prefix_mask;
  padding = byte & ~prefix_mask;

  if (value < prefix_mask) {
    return true;
  }

  uint8_t shift = 0;
  do {
    if (shift > numeric_traits::digits) {
      return false;
    }
    if (pos == end) {
      return false;
    }
    byte = *pos++;

    if (shift) {
      const IntegerT shift_mask = 127ull << (numeric_traits::digits - shift);
      if (byte & 127 & shift_mask) {
        return false;
      }
    }
    const IntegerT i = (byte & 127ull) << shift;
    // check overflow on addition
    if (value > numeric_traits::max() - i) {
      return false;
    }

    value += i;
    shift += 7;
  } while ((byte & 128) == 128); // high bit set

  return true;
}

} // namespace nexus::http2::detail::hpack
