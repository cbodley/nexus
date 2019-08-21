#pragma once

#include <algorithm>
#include <iterator>
#include <string>

namespace nexus::detail {

template <typename InputIterator>
struct byte_array_encoder {
  // iterator must be byte-sized
  static_assert(sizeof(typename std::iterator_traits<InputIterator>::value_type) == 1);
  InputIterator begin;
  size_t size;

  explicit byte_array_encoder(InputIterator begin, size_t size)
    : begin(begin), size(size) {}

  // range-converting constructor
  template <typename Range>
  byte_array_encoder(const Range& r,
                     // don't override copy constructor
                     std::enable_if_t<!std::is_same_v<byte_array_encoder,
                         std::decay_t<Range>>>* = 0)
    : byte_array_encoder(std::begin(r), std::size(r)) {}
};
// range-converting deduction guide
template <typename Range>
byte_array_encoder(const Range& r) -> byte_array_encoder<decltype(std::begin(r))>;


template <typename InputIterator>
inline size_t encoded_size(const byte_array_encoder<InputIterator>& e)
{
  return e.size;
}

template <typename OutputIterator, typename InputIterator>
void encode(OutputIterator& out, const byte_array_encoder<InputIterator>& e)
{
  out = std::copy_n(e.begin, e.size, out);
}

template <typename OutputIterator>
struct byte_array_decoder {
  // iterators must be byte-sized
  static_assert(sizeof(typename std::iterator_traits<OutputIterator>::value_type) == 1);
  OutputIterator begin;
  size_t size;

  explicit byte_array_decoder(OutputIterator begin, size_t size)
    : begin(begin), size(size) {}

  // range-converting constructor
  template <typename Range>
  byte_array_decoder(Range& r,
                     // don't override copy constructor
                     std::enable_if_t<!std::is_same_v<byte_array_decoder,
                         std::decay_t<Range>>>* = 0)
    : byte_array_decoder(std::begin(r), std::size(r)) {}
};
// range-converting deduction guide
template <typename Range>
byte_array_decoder(Range& r) -> byte_array_decoder<decltype(std::begin(r))>;

template <typename InputIterator, typename OutputIterator>
bool decode(InputIterator& in, size_t& remaining,
            byte_array_decoder<OutputIterator>&& d)
{
  if (remaining < d.size) {
    return false;
  }
  auto begin = in;
  std::advance(in, d.size);
  std::copy(begin, in, d.begin);
  remaining -= d.size;
  return true;
}


using string_encoder = byte_array_encoder<std::string::const_iterator>;

struct string_decoder : byte_array_decoder<std::string::iterator> {
  static std::string::iterator resize_begin(std::string& str, size_t length) {
    str.resize(length);
    return str.begin();
  }
  explicit string_decoder(std::string& str, size_t length)
    : byte_array_decoder<std::string::iterator>(resize_begin(str, length), length)
  {}
};

} // namespace nexus::detail
