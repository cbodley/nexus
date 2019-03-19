#pragma once

#include <type_traits>

#include <boost/asio/buffers_iterator.hpp>
#include <boost/asio/write.hpp>

#include <http2/error.hpp>
#include <http2/detail/frame.hpp>

namespace http2 {

namespace protocol::detail {

constexpr setting_parameter_identifier id(setting_parameter param) {
  return static_cast<setting_parameter_identifier>(param);
}
setting_parameters::iterator copy(setting_parameters::iterator dst,
                                  const setting_values& values)
{
  auto pvalues = static_cast<const setting_value*>(&values.header_table_size);
  for (setting_parameter_identifier i = 0; i < num_setting_parameters; i++) {
    (*dst).identifier = i + 1;
    (*dst++).value = pvalues[i];
  }
  return dst;
}

setting_parameters::iterator copy_changes(setting_parameters::iterator dst,
                                          const setting_values& from,
                                          const setting_values& to)
{
  auto pfrom = static_cast<const setting_value*>(&from.header_table_size);
  auto pto = static_cast<const setting_value*>(&to.header_table_size);
  for (setting_parameter_identifier i = 0; i < num_setting_parameters; i++) {
    if (pfrom[i] != pto[i]) {
      (*dst).identifier = i + 1;
      (*dst++).value = pto[i];
    }
  }
  return dst;
}

template <typename OutputIterator>
OutputIterator encode_setting(const setting_parameter_pair& param,
                              OutputIterator pos)
{
  *pos++ = param.identifier >> 8;
  *pos++ = param.identifier;
  *pos++ = param.value >> 24;
  *pos++ = param.value >> 16;
  *pos++ = param.value >> 8;
  *pos++ = param.value;
  return pos;
}

template <typename InputIterator>
InputIterator decode_setting(InputIterator pos, setting_parameter_pair& param)
{
  param.identifier = *pos++ << 8;
  param.identifier |= *pos++;
  param.value = static_cast<uint8_t>(*pos++) << 24;
  param.value |= static_cast<uint8_t>(*pos++) << 16;
  param.value |= static_cast<uint8_t>(*pos++) << 8;
  param.value |= static_cast<uint8_t>(*pos++);
  return pos;
}

} // namespace protocol::detail

namespace detail {

template <typename SyncWriteStream, typename DynamicBuffer,
          typename RandomSettingIterator>
void write_settings(SyncWriteStream& stream,
                    DynamicBuffer& buffers,
                    RandomSettingIterator first,
                    RandomSettingIterator last,
                    boost::system::error_code& ec)
{
  const auto count = std::distance(first, last);

  protocol::frame_header header;
  header.length = count * (sizeof(uint16_t) + sizeof(uint32_t));
  header.type = static_cast<uint8_t>(protocol::frame_type::settings);
  header.flags = 0;
  header.stream_id = 0;

  const size_t size = 9 + header.length; // 9 byte header
  auto buf = buffers.prepare(size);
  auto pos = boost::asio::buffers_begin(buf);

  pos = protocol::detail::encode_frame_header(header, pos);

  for (auto param = first; param != last; ++param) {
    pos = protocol::detail::encode_setting(*param, pos);
  }
  buffers.commit(size);

  boost::asio::write(stream, buffers.data(), ec);
  buffers.consume(size);
}

template <typename SyncWriteStream>
void write_settings_ack(SyncWriteStream& stream,
                        boost::system::error_code& ec)
{
  protocol::frame_header header;
  header.length = 0;
  header.type = static_cast<uint8_t>(protocol::frame_type::settings);
  header.flags = protocol::frame_flag_ack;
  header.stream_id = 0;

  uint8_t buffer[9]; // 9 byte header
  auto buf = boost::asio::buffer(buffer);
  auto pos = boost::asio::buffers_begin(buf);
  pos = protocol::detail::encode_frame_header(header, pos);

  boost::asio::write(stream, buf, ec);
}

} // namespace detail
} // namespace http2
