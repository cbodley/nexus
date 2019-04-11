#pragma once

#include <cstdint>
#include <cstddef>
#include <limits>

#include <nexus/http2/detail/buffer.hpp>
#include <nexus/http2/detail/hpack/error.hpp>

namespace nexus::http2::detail::hpack {

template <typename T> struct numeric_traits : std::numeric_limits<T> {};

template <size_t PrefixN, typename Integer, typename DynamicBuffer>
auto encode_integer(Integer value, uint8_t padding, DynamicBuffer& buffer)
  -> std::enable_if_t<is_dynamic_buffer_v<DynamicBuffer>, size_t>
{
  using numeric_traits = numeric_traits<Integer>;

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

namespace integer {

template <size_t PrefixN, typename Integer, typename State>
State decode_prefix(uint8_t octet, Integer& value, uint8_t& padding,
                    State suffix, State done)
{
  static_assert(PrefixN >= 1 && PrefixN <= 8);
  static constexpr uint8_t prefix_mask = (1 << PrefixN) - 1;

  using traits = numeric_traits<Integer>;
  static_assert(traits::is_integer);
  static_assert(!traits::is_signed);

  value = octet & prefix_mask;
  padding = octet & ~prefix_mask;
  if (value < prefix_mask) {
    return done;
  }
  return suffix;
}

template <typename InputIterator, typename Integer, typename State>
State decode_suffix(InputIterator& pos, InputIterator end,
                    Integer& value, uint8_t& shift,
                    State self, State done,
                    boost::system::error_code& ec)
{
  using traits = numeric_traits<Integer>;
  static_assert(traits::is_integer);
  static_assert(!traits::is_signed);

  uint8_t byte;
  do {
    if (shift > traits::digits) {
      ec = make_error_code(error::decode_integer_overflow);
      return self;
    }
    if (pos == end) {
      return self;
    }
    byte = *pos++;

    if (shift) {
      const Integer shift_mask = 127ull << (traits::digits - shift);
      if (byte & 127 & shift_mask) {
        ec = make_error_code(error::decode_integer_overflow);
        return self;
      }
    }
    const Integer i = (byte & 127ull) << shift;
    // check overflow on addition
    if (value > traits::max() - i) {
      ec = make_error_code(error::decode_integer_overflow);
      return self;
    }

    value += i;
    shift += 7;
  } while ((byte & 128) == 128); // high bit set

  return done;
}

} // namespace integer

template <size_t PrefixN, typename InputIterator, typename Integer>
bool decode_integer(InputIterator& pos, InputIterator end,
                    Integer& value, uint8_t& padding)
{
  enum class state { suffix, done };
  if (pos == end) {
    return false;
  }
  auto s = integer::decode_prefix<PrefixN>(*pos++, value, padding,
                                           state::suffix, state::done);
  if (s == state::suffix) {
    uint8_t shift = 0;
    boost::system::error_code ec;
    s = integer::decode_suffix(pos, end, value, shift,
                               state::suffix, state::done, ec);
    if (ec) {
      return false;
    }
  }
  return s == state::done;
}

} // namespace nexus::http2::detail::hpack
