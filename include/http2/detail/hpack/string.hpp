#pragma once

#include <cstdint>
#include <cstddef>

#include <boost/asio/buffer.hpp>
#include <boost/asio/buffers_iterator.hpp>

#include <http2/detail/hpack/integer.hpp>

namespace http2::detail::hpack {

template <typename DynamicBuffer>
size_t encode_string(std::string_view str, DynamicBuffer& buffer)
{
  constexpr uint8_t not_huffman_flag = 0x0;
  size_t size = str.size();
  size_t count = encode_integer<7>(size, not_huffman_flag, buffer);

  boost::asio::buffer_copy(buffer.prepare(size),
                           boost::asio::buffer(str.data(), size));
  buffer.commit(size);
  return count + size;
}

template <typename ConstBufferSequence, typename DynamicBuffer>
bool decode_string(boost::asio::buffers_iterator<ConstBufferSequence>& pos,
                   boost::asio::buffers_iterator<ConstBufferSequence> end,
                   DynamicBuffer& buffers)
{
  uint32_t len = 0;
  uint8_t huffman_flag = 0;
  if (!decode_integer<7>(pos, end, len, huffman_flag)) {
    return false;
  }
  if (std::distance(pos, end) < len) {
    return false;
  }
  if (huffman_flag & 0x80) {
    return false; // TODO: huffman decode
  }
  if (len) {
    auto output = buffers.prepare(len);
    std::copy(pos, pos + len, boost::asio::buffers_begin(output));
    buffers.commit(len);
  }
  return true;
}

} // namespace http2::detail::hpack
