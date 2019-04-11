#pragma once

#include <cstdint>
#include <cstddef>

#include <nexus/http2/detail/buffer.hpp>
#include <nexus/http2/hpack/integer.hpp>

namespace nexus::http2::hpack {

template <typename DynamicBuffer>
auto encode_string(std::string_view str, DynamicBuffer& buffer)
  -> std::enable_if_t<detail::is_dynamic_buffer_v<DynamicBuffer>, size_t>
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
    pos += len;
  }
  return true;
}

} // namespace nexus::http2::hpack
