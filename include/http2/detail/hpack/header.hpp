#pragma once

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>

#include <boost/asio/buffer.hpp>

#include <http2/detail/hpack/integer.hpp>
#include <http2/detail/hpack/string.hpp>

#include <http2/detail/hpack/dynamic_table.hpp>
#include <http2/detail/hpack/static_table.hpp>

namespace http2::detail::hpack {

template <typename DynamicBuffer>
size_t encode_table_size_update(uint32_t size, DynamicBuffer& buffers)
{
  return encode_integer<5>(size, 0x20, buffers);
}

template <typename DynamicBuffer>
size_t encode_indexed_header(uint32_t index, DynamicBuffer& buffers)
{
  return encode_integer<7>(index, 0x80, buffers);
}

template <typename DynamicBuffer>
size_t encode_literal_header(uint32_t index,
                             std::string_view value,
                             DynamicBuffer& buffers)
{
  size_t count = encode_integer<6>(index, 0x40, buffers);
  return count + encode_string(value, buffers);
}

template <typename DynamicBuffer>
size_t encode_literal_header(std::string_view name,
                             std::string_view value,
                             DynamicBuffer& buffers)
{
  uint32_t index = 0;
  size_t count = encode_integer<6>(index, 0x40, buffers);
  count += encode_string(name, buffers);
  return count + encode_string(value, buffers);
}

template <typename DynamicBuffer>
size_t encode_literal_header_no_index(uint32_t index,
                                      std::string_view value,
                                      DynamicBuffer& buffers)
{
  size_t count = encode_integer<4>(index, 0, buffers);
  return count + encode_string(value, buffers);
}

template <typename DynamicBuffer>
size_t encode_literal_header_no_index(std::string_view name,
                                      std::string_view value,
                                      DynamicBuffer& buffers)
{
  uint32_t index = 0;
  size_t count = encode_integer<4>(index, 0, buffers);
  count += encode_string(name, buffers);
  return count + encode_string(value, buffers);
}

template <typename SizeType, typename Allocator, typename DynamicBuffer>
size_t encode_header(std::string_view name, std::string_view value,
                     basic_dynamic_table<SizeType, 32, Allocator>& table,
                     DynamicBuffer& buffers)
{
  // TODO: filter for 'never indexed' headers
  // search dynamic table
  bool has_value = false;
  auto index = table.search(name, value, has_value);
  if (index) {
    *index += 1 + static_table_size;
    if (has_value) {
      return encode_indexed_header(*index, buffers);
    }
  }
  // search static table
  constexpr auto entry_less = [] (const static_table_entry& entry,
                                  std::string_view name) {
    return entry.name < name;
  };
  auto p = std::lower_bound(std::begin(static_table),
                            std::end(static_table),
                            name, entry_less);
  if (p != std::end(static_table) && p->name == name) {
    index = 1 + std::distance(std::begin(static_table), p);
    if (p->value == value) {
      return encode_indexed_header(*index, buffers);
    }
  }
  // skip the dynamic table if it's too big
  const size_t esize = name.size() + value.size() + 32;
  if (esize > table.max_size()) {
    if (index) {
      return encode_literal_header_no_index(*index, value, buffers);
    }
    return encode_literal_header_no_index(name, value, buffers);
  }
  table.insert(name, value);
  if (index) {
    return encode_literal_header(*index, value, buffers);
  }
  return encode_literal_header(name, value, buffers);
}

template <typename RandomIterator, typename SizeType, typename Allocator>
bool decode_header(RandomIterator& pos, RandomIterator end,
                   basic_dynamic_table<SizeType, 32, Allocator>& table,
                   std::string& name, std::string& value)
{
  uint8_t flags = *pos;
  const bool indexed_value = flags & 0x80;
  const bool add_to_index = flags & 0x40;
  const bool table_size_update = flags & 0x20;
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
  } else if (table_size_update) {
    if (!decode_integer<5>(pos, end, index, flags)) {
      return false;
    }
    table.set_size(index);
    return true; // XXX: returns true with no name/value
  } else {
    if (!decode_integer<4>(pos, end, index, flags)) {
      return false;
    }
  }

  if (index > 0) {
    --index;
    if (index < static_table_size) {
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
    name.clear();
    auto buf = boost::asio::dynamic_buffer(name);
    if (!decode_string(pos, end, buf)) {
      return false;
    }
  }

  value.clear();
  auto buf = boost::asio::dynamic_buffer(value);
  if (!decode_string(pos, end, buf)) {
    return false;
  }

  if (add_to_index) {
    table.insert(name, value);
  }
  return true;
}

// TODO: Fields must store a flag for never-indexed
// TODO: decode literals directly into Field-allocated storage
// TODO: consider reference-counted fields to reuse literals in dynamic table

template <typename Fields, typename SizeType,
          typename Allocator, typename DynamicBuffer>
size_t encode_headers(const Fields& fields,
                      basic_dynamic_table<SizeType, 32, Allocator>& table,
                      DynamicBuffer& buffers)
{
  size_t count = 0;
  for (const auto& f : fields) {
    count += encode_header({f.name_string().data(), f.name_string().size()},
                           {f.value().data(), f.value().size()},
                           table, buffers);
  }
  return count;
}

template <typename RandomIterator, typename SizeType,
          typename Allocator, typename Fields>
bool decode_headers(RandomIterator& pos, RandomIterator end,
                    basic_dynamic_table<SizeType, 32, Allocator>& table,
                    Fields& fields)
{
  std::string name, value;
  while (pos != end) {
    if (!decode_header(pos, end, table, name, value)) {
      return false;
    }
    fields.insert(name, value);
  }
  return true;
}

} // namespace http2::detail::hpack
