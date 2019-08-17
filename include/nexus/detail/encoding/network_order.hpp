#pragma once

#include <algorithm>
#include <endian.h>

namespace nexus::detail {

template <typename InputIterator, typename OutputIterator>
auto encode_network_order(OutputIterator& out, InputIterator in, size_t count)
  -> std::enable_if_t<!std::is_unsigned_v<InputIterator>>
{
#if _BYTE_ORDER == _LITTLE_ENDIAN
  // copy in reverse
  auto last = std::next(in, count);
  out = std::copy_n(std::reverse_iterator(last), count, out);
#else
  out = std::copy_n(first, count, out);
#endif
}

template <typename Unsigned>
struct network_order_encoder {
  static_assert(std::is_unsigned_v<Unsigned>);
  Unsigned value;
  size_t count;
  network_order_encoder(Unsigned value, size_t count = sizeof(Unsigned))
    : value(value), count(count) {}
};

template <typename Unsigned>
size_t encoded_size(const network_order_encoder<Unsigned>& e)
{
  return e.count;
}

template <typename OutputIterator, typename Unsigned>
void encode(OutputIterator& out, const network_order_encoder<Unsigned>& e)
{
  encode_network_order(out, reinterpret_cast<const char*>(&e.value), e.count);
}

template <typename Unsigned>
struct network_order_decoder {
  static_assert(std::is_unsigned_v<Unsigned>);
  Unsigned& value;
  size_t count;
  network_order_decoder(Unsigned& value, size_t count = sizeof(Unsigned))
    : value(value), count(count) {}
};

template <typename InputIterator, typename Unsigned>
bool decode(InputIterator& in, size_t& remaining,
            network_order_decoder<Unsigned>&& d)
{
  if (remaining < d.count) {
    return false;
  }
  d.value = 0;
  auto out = reinterpret_cast<char*>(&d.value);
  encode_network_order(out, in, d.count);
  std::advance(in, d.count);
  remaining -= d.count;
  return true;
}

} // namespace nexus::detail
