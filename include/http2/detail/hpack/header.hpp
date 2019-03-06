#pragma once

#include <cstddef>
#include <string>
#include <string_view>

#include <boost/asio/buffer.hpp>

#include <http2/detail/hpack/integer.hpp>
#include <http2/detail/hpack/string.hpp>

#include <http2/detail/hpack/dynamic_table.hpp>
#include <http2/detail/hpack/static_table.hpp>

namespace http2::detail::hpack {

template <typename SizeType, typename Allocator, typename DynamicBuffer>
size_t encode_header(std::string_view name, std::string_view value,
                     [[maybe_unused]] basic_dynamic_table<SizeType, 32, Allocator>& table,
                     DynamicBuffer& buffers)
{
  uint32_t index = 0; // TODO: look up index
  size_t count = encode_integer<4>(index, 0, buffers);
  count += encode_string(name, buffers);
  count += encode_string(value, buffers);
  return count;
}

template <typename ConstBufferSequence, typename SizeType, typename Allocator>
bool decode_header(boost::asio::buffers_iterator<ConstBufferSequence>& pos,
                   boost::asio::buffers_iterator<ConstBufferSequence> end,
                   basic_dynamic_table<SizeType, 32, Allocator>& table,
                   std::string& name, std::string& value)
{
  uint8_t flags = *pos;
  const bool indexed_value = flags & 0x80;
  const bool add_to_index = flags & 0x40;
  //const bool never_index = flags & 0x10;

  uint32_t index = 0;
  if (indexed_value) {
    if (!decode_integer<7>(pos, end, index, flags)) {
      return false;
    }
  } else if (add_to_index) {
    if (!decode_integer<6>(pos, end, index, flags)) {
      return false;
    }
  } else {
    if (!decode_integer<4>(pos, end, index, flags)) {
      return false;
    }
  }

  if (index > 0) {
    --index;
    if (index <= static_table_size) {
      const auto& e = static_table[index];
      name.assign(e.name);
      if (indexed_value) {
        value.assign(e.value);
        return true;
      }
    } else {
      index -= static_table_size;
      if (indexed_value) {
        return table.lookup(index, &name, &value);
      }
      if (!table.lookup(index, &name, nullptr)) {
        return false;
      }
    }
  } else {
    if (indexed_value) {
      return false;
    }
    auto buf = boost::asio::dynamic_buffer(name);
    if (!decode_string(pos, end, buf)) {
      return false;
    }
  }

  auto buf = boost::asio::dynamic_buffer(value);
  if (!decode_string(pos, end, buf)) {
    return false;
  }

  if (add_to_index) {
    table.insert(name, value);
  }
  return true;
}

} // namespace http2::detail::hpack
