#pragma once

#include <type_traits>

#include <boost/asio/buffers_iterator.hpp>

#include <http2/protocol.hpp>

namespace http2::protocol::detail {

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
  param.value = *pos++ << 24;
  param.value |= *pos++ << 16;
  param.value |= *pos++ << 8;
  param.value |= *pos++;
  return pos;
}

} // namespace http2::protocol::detail
