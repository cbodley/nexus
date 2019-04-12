#pragma once

#include <nexus/http2/hpack/integer.hpp>
#include <nexus/http2/hpack/static_table.hpp>

namespace nexus::http2::hpack {

enum class decode_state : uint8_t {
  new_header = 0,
  // indexed header field
  indexed_header_index,
  // literal header field with incremental indexing
  literal_header_index,
  literal_header_name_length_prefix,
  literal_header_name_length,
  literal_header_huffman_name_length,
  literal_header_name,
  literal_header_huffman_name,
  literal_header_value_length_prefix,
  literal_header_value_length,
  literal_header_huffman_value_length,
  literal_header_value,
  literal_header_huffman_value,
  // literal header field without indexing
  noindex_literal_header_index,
  noindex_literal_header_name_length_prefix,
  noindex_literal_header_name_length,
  noindex_literal_header_huffman_name_length,
  noindex_literal_header_name,
  noindex_literal_header_huffman_name,
  noindex_literal_header_value_length_prefix,
  noindex_literal_header_value_length,
  noindex_literal_header_huffman_value_length,
  noindex_literal_header_value,
  noindex_literal_header_huffman_value,
  // literal header field never indexed
  neverindex_literal_header_index,
  neverindex_literal_header_name_length_prefix,
  neverindex_literal_header_name_length,
  neverindex_literal_header_huffman_name_length,
  neverindex_literal_header_name,
  neverindex_literal_header_huffman_name,
  neverindex_literal_header_value_length_prefix,
  neverindex_literal_header_value_length,
  neverindex_literal_header_huffman_value_length,
  neverindex_literal_header_value,
  neverindex_literal_header_huffman_value,
  // dynamic table size update
  dynamic_table_size,
};

// stateful hpack decoder
template <typename Table, typename Fields>
class decoder {
  Table& table;
  Fields& fields;
  std::string name;
  std::string value;
  using dynamic_buffer = boost::asio::dynamic_string_buffer<
      char, std::char_traits<char>, std::allocator<char>>;
  dynamic_buffer name_buffer;
  dynamic_buffer value_buffer;
  size_t max_header_list_size;
  size_t header_list_size = 0;
  uint32_t length = 0;
  decode_state state = decode_state::new_header;
  uint8_t flags = 0;
  uint8_t padding = 0;
  uint8_t shift = 0;

  void new_header(uint8_t octet, boost::system::error_code& ec);
  void decode_literal_prefix(uint8_t octet,
                             decode_state suffix,
                             decode_state literal,
                             decode_state huffman_suffix,
                             decode_state huffman_literal);
  void emit_indexed_header(boost::system::error_code& ec);
  void indexed_name(boost::system::error_code& ec);
  void emit_literal_header(boost::system::error_code& ec);
 public:
  decoder(Table& table, Fields& fields, size_t max_header_list_size)
    : table(table), fields(fields), name_buffer(name), value_buffer(value),
      max_header_list_size(max_header_list_size)
  {}

  template <typename ConstBufferSequence>
  auto decode(const ConstBufferSequence& buffers,
              boost::system::error_code& ec)
    -> std::enable_if_t<detail::is_const_buffer_sequence_v<ConstBufferSequence>>;

  void finish(boost::system::error_code& ec);
};

template <typename Table, typename Fields>
void decoder<Table, Fields>::new_header(
    uint8_t octet, boost::system::error_code& ec)
{
  length = 0;
  shift = 0;
  name.clear();
  name_buffer.consume(name_buffer.size());
  value.clear();
  value_buffer.consume(value_buffer.size());
  if (octet & 0x80) { // indexed value
    const auto suffix = decode_state::indexed_header_index;
    const auto done = decode_state::new_header;
    state = integer::decode_prefix<7>(octet, length, flags, suffix, done);
    if (state == done) {
      emit_indexed_header(ec);
    }
  } else if (octet & 0x40) { // add to index
    const auto suffix = decode_state::literal_header_index;
    const auto done = decode_state::literal_header_name_length_prefix;
    state = integer::decode_prefix<6>(octet, length, flags, suffix, done);
    if (state == done && length) {
      indexed_name(ec);
      state = decode_state::literal_header_value_length_prefix;
    }
  } else if (octet & 0x20) { // table size update
    const auto suffix = decode_state::dynamic_table_size;
    const auto done = decode_state::new_header;
    state = integer::decode_prefix<5>(octet, length, flags, suffix, done);
    if (state == done) {
      table.set_size(length); // TODO: validate length
    }
  } else if (octet & 0x10) { // never index
    const auto suffix = decode_state::neverindex_literal_header_index;
    const auto done = decode_state::neverindex_literal_header_name_length_prefix;
    state = integer::decode_prefix<4>(octet, length, flags, suffix, done);
    if (state == done && length) {
      indexed_name(ec);
      state = decode_state::neverindex_literal_header_value_length_prefix;
    }
  } else { // no index
    const auto suffix = decode_state::noindex_literal_header_index;
    const auto done = decode_state::noindex_literal_header_name_length_prefix;
    state = integer::decode_prefix<4>(octet, length, flags, suffix, done);
    if (state == done && length) {
      indexed_name(ec);
      state = decode_state::noindex_literal_header_value_length_prefix;
    }
  }
}

template <typename Table, typename Fields>
void decoder<Table, Fields>::decode_literal_prefix(
    uint8_t octet, decode_state suffix, decode_state literal,
    decode_state huffman_suffix, decode_state huffman_literal)
{
  state = integer::decode_prefix<7>(octet, length, padding, suffix, literal);
  if (padding & 0x80) { // huffman flag
    if (state == suffix) {
      state = huffman_suffix;
    } else if (state == literal) {
      state = huffman_literal;
    }
  }
}

template <typename Table, typename Fields>
void decoder<Table, Fields>::emit_indexed_header(boost::system::error_code& ec)
{
  if (length == 0) {
    ec = make_error_code(error::decode_invalid_index);
    return;
  }
  const uint32_t index = length - 1;
  if (index < static_table::size) {
    const auto& e = static_table::table[index];
    name.assign(e.name);
    value.assign(e.value);
  } else if (!table.lookup(index - static_table::size, &name, &value)) {
    ec = make_error_code(error::decode_invalid_index);
    return;
  }
  const size_t header_size = name.size() + value.size() + 32;
  if (header_list_size + header_size > max_header_list_size) {
    ec = make_error_code(error::exceeded_max_header_list_size);
    return;
  }
  header_list_size += header_size;
  fields.insert(name, value);
}

template <typename Table, typename Fields>
void decoder<Table, Fields>::indexed_name(boost::system::error_code& ec)
{
  if (length == 0) {
    ec = make_error_code(error::decode_invalid_index);
    return;
  }
  const uint32_t index = length - 1;
  if (index < static_table::size) {
    const auto& e = static_table::table[index];
    name.assign(e.name);
  } else if (!table.lookup(index - static_table::size, &name, nullptr)) {
    ec = make_error_code(error::decode_invalid_index);
    return;
  }
}

template <typename Table, typename Fields>
void decoder<Table, Fields>::emit_literal_header(boost::system::error_code& ec)
{
  const size_t header_size = name.size() + value.size() + 32;
  if (header_list_size + header_size > max_header_list_size) {
    ec = make_error_code(error::exceeded_max_header_list_size);
    return;
  }
  header_list_size += header_size;
  fields.insert(name, value); // TODO: track never-index flag
  if (flags & 0x40) { // add to index
    table.insert(name, value);
  }
}

template <typename Table, typename Fields>
template <typename ConstBufferSequence>
auto decoder<Table, Fields>::decode(const ConstBufferSequence& buffers,
                                    boost::system::error_code& ec)
  -> std::enable_if_t<detail::is_const_buffer_sequence_v<ConstBufferSequence>>
{
  ec.clear();
  auto pos = boost::asio::buffers_begin(buffers);
  auto end = boost::asio::buffers_end(buffers);
  while (!ec && pos != end) {
    switch (state) {
      case decode_state::new_header:
        new_header(*pos++, ec);
        break;

      case decode_state::indexed_header_index:
        state = integer::decode_suffix(
            pos, end, length, shift,
            decode_state::indexed_header_index,
            decode_state::new_header, ec);
        if (state == decode_state::new_header) {
          emit_indexed_header(ec);
        }
        break;

      // literal header field with incremental indexing
      case decode_state::literal_header_index:
        state = integer::decode_suffix(
            pos, end, length, shift,
            decode_state::literal_header_index,
            decode_state::literal_header_name_length_prefix, ec);
        if (state == decode_state::literal_header_name_length_prefix && length) {
          indexed_name(ec);
          state = decode_state::literal_header_value_length_prefix;
        }
        break;
      case decode_state::literal_header_name_length_prefix:
        decode_literal_prefix(
            *pos++, decode_state::literal_header_name_length,
            decode_state::literal_header_name,
            decode_state::literal_header_huffman_name_length,
            decode_state::literal_header_huffman_name);
        break;
      case decode_state::literal_header_name_length:
        state = integer::decode_suffix(
            pos, end, length, shift,
            decode_state::literal_header_name_length,
            decode_state::literal_header_name, ec);
        break;
      case decode_state::literal_header_huffman_name_length:
        ec = make_error_code(error::huffman_not_supported);
        break;
      case decode_state::literal_header_name:
        state = string::decode(
            pos, end, length, name_buffer,
            decode_state::literal_header_name,
            decode_state::literal_header_value_length_prefix);
        break;
      case decode_state::literal_header_huffman_name:
        ec = make_error_code(error::huffman_not_supported);
        break;
      case decode_state::literal_header_value_length_prefix:
        decode_literal_prefix(
            *pos++, decode_state::literal_header_value_length,
            decode_state::literal_header_value,
            decode_state::literal_header_huffman_value_length,
            decode_state::literal_header_huffman_value);
        break;
      case decode_state::literal_header_value_length:
        state = integer::decode_suffix(
            pos, end, length, shift,
            decode_state::literal_header_value_length,
            decode_state::literal_header_value, ec);
        break;
      case decode_state::literal_header_huffman_value_length:
        ec = make_error_code(error::huffman_not_supported);
        break;
      case decode_state::literal_header_value:
        state = string::decode(
            pos, end, length, value_buffer,
            decode_state::literal_header_value,
            decode_state::new_header);
        if (state == decode_state::new_header) {
          emit_literal_header(ec);
        }
        break;
      case decode_state::literal_header_huffman_value:
        ec = make_error_code(error::huffman_not_supported);
        break;

      // literal header field without indexing
      case decode_state::noindex_literal_header_index:
        state = integer::decode_suffix(
            pos, end, length, shift,
            decode_state::noindex_literal_header_index,
            decode_state::noindex_literal_header_name_length_prefix, ec);
        if (state == decode_state::noindex_literal_header_name_length_prefix && length) {
          indexed_name(ec);
          state = decode_state::noindex_literal_header_value_length_prefix;
        }
        break;
      case decode_state::noindex_literal_header_name_length_prefix:
        decode_literal_prefix(
            *pos++, decode_state::noindex_literal_header_name_length,
            decode_state::noindex_literal_header_name,
            decode_state::noindex_literal_header_huffman_name_length,
            decode_state::noindex_literal_header_huffman_name);
        break;
      case decode_state::noindex_literal_header_name_length:
        state = integer::decode_suffix(
            pos, end, length, shift,
            decode_state::noindex_literal_header_name_length,
            decode_state::noindex_literal_header_name, ec);
        break;
      case decode_state::noindex_literal_header_huffman_name_length:
        ec = make_error_code(error::huffman_not_supported);
        break;
      case decode_state::noindex_literal_header_name:
        state = string::decode(
            pos, end, length, name_buffer,
            decode_state::noindex_literal_header_name,
            decode_state::noindex_literal_header_value_length_prefix);
        break;
      case decode_state::noindex_literal_header_huffman_name:
        ec = make_error_code(error::huffman_not_supported);
        break;
      case decode_state::noindex_literal_header_value_length_prefix:
        decode_literal_prefix(
            *pos++, decode_state::noindex_literal_header_value_length,
            decode_state::noindex_literal_header_value,
            decode_state::noindex_literal_header_huffman_value_length,
            decode_state::noindex_literal_header_huffman_value);
        break;
      case decode_state::noindex_literal_header_value_length:
        state = integer::decode_suffix(
            pos, end, length, shift,
            decode_state::noindex_literal_header_value_length,
            decode_state::noindex_literal_header_value, ec);
        break;
      case decode_state::noindex_literal_header_huffman_value_length:
        ec = make_error_code(error::huffman_not_supported);
        break;
      case decode_state::noindex_literal_header_value:
        state = string::decode(
            pos, end, length, value_buffer,
            decode_state::noindex_literal_header_value,
            decode_state::new_header);
        if (state == decode_state::new_header) {
          emit_literal_header(ec);
        }
        break;
      case decode_state::noindex_literal_header_huffman_value:
        ec = make_error_code(error::huffman_not_supported);
        break;

      // literal header field never indexed
      case decode_state::neverindex_literal_header_index:
        state = integer::decode_suffix(
            pos, end, length, shift,
            decode_state::neverindex_literal_header_index,
            decode_state::neverindex_literal_header_name_length_prefix, ec);
        if (state == decode_state::neverindex_literal_header_name_length_prefix && length) {
          indexed_name(ec);
          state = decode_state::neverindex_literal_header_value_length_prefix;
        }
        break;
      case decode_state::neverindex_literal_header_name_length_prefix:
        decode_literal_prefix(
            *pos++, decode_state::neverindex_literal_header_name_length,
            decode_state::neverindex_literal_header_name,
            decode_state::neverindex_literal_header_huffman_name_length,
            decode_state::neverindex_literal_header_huffman_name);
        break;
      case decode_state::neverindex_literal_header_name_length:
        state = integer::decode_suffix(
            pos, end, length, shift,
            decode_state::neverindex_literal_header_name_length,
            decode_state::neverindex_literal_header_name, ec);
        break;
      case decode_state::neverindex_literal_header_huffman_name_length:
        ec = make_error_code(error::huffman_not_supported);
        break;
      case decode_state::neverindex_literal_header_name:
        state = string::decode(
            pos, end, length, name_buffer,
            decode_state::neverindex_literal_header_name,
            decode_state::neverindex_literal_header_value_length_prefix);
        break;
      case decode_state::neverindex_literal_header_huffman_name:
        ec = make_error_code(error::huffman_not_supported);
        break;
      case decode_state::neverindex_literal_header_value_length_prefix:
        decode_literal_prefix(
            *pos++, decode_state::neverindex_literal_header_value_length,
            decode_state::neverindex_literal_header_value,
            decode_state::neverindex_literal_header_huffman_value_length,
            decode_state::neverindex_literal_header_huffman_value);
        break;
      case decode_state::neverindex_literal_header_value_length:
        state = integer::decode_suffix(
            pos, end, length, shift,
            decode_state::neverindex_literal_header_value_length,
            decode_state::neverindex_literal_header_value, ec);
        break;
      case decode_state::neverindex_literal_header_huffman_value_length:
        ec = make_error_code(error::huffman_not_supported);
        break;
      case decode_state::neverindex_literal_header_value:
        state = string::decode(
            pos, end, length, value_buffer,
            decode_state::neverindex_literal_header_value,
            decode_state::new_header);
        if (state == decode_state::new_header) {
          emit_literal_header(ec);
        }
        break;
      case decode_state::neverindex_literal_header_huffman_value:
        ec = make_error_code(error::huffman_not_supported);
        break;

      // dynamic table size update
      case decode_state::dynamic_table_size:
        state = integer::decode_suffix(
            pos, end, length, shift,
            decode_state::dynamic_table_size,
            decode_state::new_header, ec);
        if (state == decode_state::new_header) {
          table.set_size(length); // TODO: validate length
        }
        break;
    }
  }
}

template <typename Table, typename Fields>
void decoder<Table, Fields>::finish(boost::system::error_code& ec)
{
  if (state == decode_state::new_header) {
    ec.clear();
  } else {
    ec = make_error_code(error::decode_truncated);
  }
}

} // namespace nexus::http2::hpack
