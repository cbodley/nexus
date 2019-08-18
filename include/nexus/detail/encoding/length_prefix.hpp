#pragma once

#include <cstdint>

namespace nexus::detail {

template <typename LengthEncoder, typename DataEncoder>
struct length_prefix_encoder {
  LengthEncoder len;
  const DataEncoder& data;
  length_prefix_encoder(const DataEncoder& data)
    : len(encoded_size(data)), data(data) {}
};

template <typename LengthEncoder, typename DataEncoder>
inline size_t encoded_size(const length_prefix_encoder<LengthEncoder, DataEncoder>& e)
{
  return encoded_size(e.len) + encoded_size(e.data);
}

template <typename OutputIterator, typename LengthEncoder, typename DataEncoder>
void encode(OutputIterator& out, const length_prefix_encoder<LengthEncoder, DataEncoder>& e)
{
  encode1(out, e.len, e.data);
}

template <typename LengthT, typename LengthDecoder,
          typename DataDecoder, typename DataT>
struct length_prefix_decoder {
  DataT& data;
  explicit length_prefix_decoder(DataT& data) : data(data) {}
};

template <typename InputIterator, typename LengthT,
          typename LengthDecoder, typename DataDecoder, typename DataT>
bool decode(InputIterator& in, size_t& remaining,
            length_prefix_decoder<LengthT, LengthDecoder, DataDecoder, DataT>&& d)
{
  LengthT length = 0;
  return decode(in, remaining, LengthDecoder{length})
      && decode(in, remaining, DataDecoder{d.data, length});
}

} // namespace nexus::detail
