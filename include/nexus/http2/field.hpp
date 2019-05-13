#pragma once

#include <string_view>

#include <nexus/http2/hpack/static_table.hpp>

namespace nexus::http2 {

/// fields with corresponding entries in the hpack static table
enum class field : uint8_t {
  unknown = 255,

  authority = 0,
  method, // :method without value
  method_get = method,
  method_post,
  path, // :path without value
  path_slash = path,
  path_index_html,
  scheme, // :scheme without value
  scheme_http = scheme,
  scheme_https,
  status, // :status without value
  status_200 = status,
  status_204,
  status_206,
  status_304,
  status_400,
  status_404,
  status_500,
  accept_charset,
  accept_encoding, // accept-encoding without value
  accept_encoding_gzip_deflate = accept_encoding,
  accept_language,
  accept_ranges,
  accept,
  access_control_allow_origin,
  age,
  allow,
  authorization,
  cache_control,
  content_disposition,
  content_encoding,
  content_language,
  content_length,
  content_location,
  content_range,
  content_type,
  cookie,
  date,
  etag,
  expect,
  expires,
  from,
  host,
  if_match,
  if_modified_since,
  if_none_match,
  if_range,
  if_unmodified_since,
  last_modified,
  link,
  location,
  max_forwards,
  proxy_authenticate,
  proxy_authorization,
  range,
  referer,
  refresh,
  retry_after,
  server,
  set_cookie,
  strict_transport_security,
  transfer_encoding,
  user_agent,
  vary,
  via,
  www_authenticate,
};

inline std::string_view field_name(field f)
{
  if (f == field::unknown) {
    return "<unknown-field>";
  }
  const auto index = static_cast<size_t>(f);
  return hpack::static_table::table[index].name;
}

inline std::string_view field_value(field f)
{
  if (f == field::unknown) {
    return "<unknown-field>";
  }
  const auto index = static_cast<size_t>(f);
  return hpack::static_table::table[index].value;
}

inline field parse_field(std::string_view name)
{
  bool value_ignored = false;
  auto index = hpack::static_table::search(name, "", value_ignored);
  return index ? static_cast<field>(*index - 1) : field::unknown;
}

} // namespace nexus::http2
