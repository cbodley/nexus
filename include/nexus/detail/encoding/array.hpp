#pragma once

#include <algorithm>

namespace nexus::detail {

template <typename Encoder, typename InputIterator>
struct array_encoder {
  InputIterator begin;
  InputIterator end;

  explicit array_encoder(InputIterator begin, InputIterator end)
    : begin(begin), end(end) {}
};

template <typename Encoder, typename InputIterator>
auto make_array_encoder(InputIterator begin, InputIterator end)
{
  return array_encoder<Encoder, InputIterator>{begin, end};
}

template <typename Encoder, typename Range>
auto make_array_encoder(const Range& r)
{
  return make_array_encoder<Encoder>(std::begin(r), std::end(r));
}

template <typename Encoder, typename InputIterator>
size_t encoded_size(const array_encoder<Encoder, InputIterator>& e)
{
  size_t sum = 0;
  for (auto i = e.begin; i != e.end; ++i) {
    sum += encoded_size(Encoder{*i});
  }
  return sum;
}

template <typename OutputIterator, typename Encoder, typename InputIterator>
void encode(OutputIterator& out, const array_encoder<Encoder, InputIterator>& e)
{
  for (auto i = e.begin; i != e.end; ++i) {
    encode(out, Encoder{*i});
  }
}

template <typename Decoder, typename OutputIterator>
struct array_decoder {
  OutputIterator begin;
  OutputIterator end;

  explicit array_decoder(OutputIterator begin, OutputIterator end)
    : begin(begin), end(end) {}
};

template <typename Decoder, typename OutputIterator>
auto make_array_decoder(OutputIterator begin, OutputIterator end)
{
  return array_decoder<Decoder, OutputIterator>{begin, end};
}

template <typename Decoder, typename Range>
auto make_array_decoder(Range& r)
{
  return make_array_decoder<Decoder>(std::begin(r), std::end(r));
}

template <typename InputIterator, typename Decoder, typename OutputIterator>
bool decode(InputIterator& in, size_t& remaining,
            array_decoder<Decoder, OutputIterator>&& d)
{
  for (auto i = d.begin; i != d.end; ++i) {
    if (!decode(in, remaining, Decoder{*i})) {
      return false;
    }
  }
  return true;
}

} // namespace nexus::detail
