#pragma once

#include <cstdint>
#include <cstddef>

#include <boost/asio/buffers_iterator.hpp>

namespace http2::hpack {

template <size_t PrefixN, typename IntegerT, typename DynamicBuffer>
size_t encode_integer(IntegerT value, uint8_t padding, DynamicBuffer& buffer);

template <size_t PrefixN, typename ConstBufferSequence, typename IntegerT>
bool decode_integer(boost::asio::buffers_iterator<ConstBufferSequence>& pos,
                    boost::asio::buffers_iterator<ConstBufferSequence> end,
                    IntegerT& value, uint8_t& padding);

template <typename DynamicBuffer>
size_t encode_string(std::string_view str, DynamicBuffer& buffer);

} // namespace http2::hpack

#include <http2/detail/hpack.hpp>
