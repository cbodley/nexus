#pragma once

#include <type_traits>

#include <boost/asio/write.hpp>

#include <http2/error.hpp>
#include <http2/detail/buffer.hpp>
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

template <typename DynamicBuffer, typename RandomSettingIterator>
auto encode_settings(DynamicBuffer& buffers,
                     RandomSettingIterator first,
                     RandomSettingIterator last)
  -> std::enable_if_t<detail::is_dynamic_buffer_v<DynamicBuffer>>
{
  // encode each parameter into the payload
  const size_t count = std::distance(first, last);
  const auto size = count * (sizeof(uint16_t) + sizeof(uint32_t));
  auto buf = buffers.prepare(size);
  auto pos = boost::asio::buffers_begin(buf);
  for (auto param = first; param != last; ++param) {
    pos = protocol::detail::encode_setting(*param, pos);
  }
  buffers.commit(size);
}

} // namespace detail
} // namespace http2
