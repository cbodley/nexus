#pragma once

#include <algorithm>
#include <string>

namespace nexus::detail {

struct string_encoder {
  const std::string& str;
  constexpr string_encoder(const std::string& str) : str(str) {}
};

inline size_t encoded_size(const string_encoder& e)
{
  return e.str.size();
}

template <typename OutputIterator>
void encode(OutputIterator& out, const string_encoder& e)
{
  out = std::copy(e.str.begin(), e.str.end(), out);
}

struct string_decoder {
  std::string& str;
  size_t length;
  explicit string_decoder(std::string& str, size_t length)
    : str(str), length(length) {}
};

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, string_decoder&& str)
{
  if (remaining < str.length) {
    return false;
  }
  auto start = in;
  std::advance(in, str.length);
  str.str.insert(str.str.end(), start, in);
  remaining -= str.length;
  return true;
}

} // namespace nexus::detail
