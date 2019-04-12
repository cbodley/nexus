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

namespace string {

template <typename InputIterator, typename Integer,
          typename DynamicBuffer, typename State>
State decode(InputIterator& pos, InputIterator end,
             Integer& remaining, DynamicBuffer& buffers,
             State self, State done)
{
  const size_t input_size = std::distance(pos, end);
  if (input_size < remaining) {
    auto output = buffers.prepare(input_size);
    std::copy(pos, end, boost::asio::buffers_begin(output));
    buffers.commit(input_size);
    pos = end;
    remaining -= input_size;
    return self;
  }
  auto next = pos;
  std::advance(next, remaining);
  auto output = buffers.prepare(remaining);
  std::copy(pos, next, boost::asio::buffers_begin(output));
  buffers.commit(remaining);
  pos = next;
  remaining = 0;
  return done;
}

// TODO: huffman_decode()

} // namespace string

template <typename InputIterator, typename DynamicBuffer>
auto decode_string(InputIterator& pos, InputIterator end,
                   DynamicBuffer& buffers)
  -> std::enable_if_t<detail::is_dynamic_buffer_v<DynamicBuffer>, bool>
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
  enum class state { string, done };
  auto s = string::decode(pos, end, len, buffers, state::string, state::done);
  return s == state::done;
}

} // namespace nexus::http2::hpack
