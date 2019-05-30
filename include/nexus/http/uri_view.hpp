#pragma once

#include <nexus/http/detail/uri_parser.hpp>
#include <string_view>

namespace nexus::http {

// an immutable uri view
template <typename StringView, typename SizeType>
class basic_uri_view {
  using view_type = StringView;
  view_type value;
  using parts_type = typename detail::uri_parts<view_type, SizeType>;
  parts_type parts;
  basic_uri_view(view_type value, const parts_type& parts)
    : value(value), parts(parts) {}
  view_type part(const typename parts_type::part& p) const noexcept {
    return value.substr(p.begin, p.end - p.begin);
  }
 public:
  basic_uri_view() = default;
  basic_uri_view(const basic_uri_view&) = default;
  basic_uri_view& operator=(const basic_uri_view&) = default;
  basic_uri_view(basic_uri_view&&) = default;
  basic_uri_view& operator=(basic_uri_view&&) = default;

  view_type get() const noexcept { return value; }
  bool empty() const noexcept {
    return parts.scheme.begin == parts.fragment.end;
  }

  view_type scheme() const noexcept { return part(parts.scheme); }
  view_type authority() const noexcept {
    return value.substr(parts.userinfo.begin,
                        parts.port.end - parts.userinfo.begin);
  }
  view_type userinfo() const noexcept { return part(parts.userinfo); }
  view_type host() const noexcept { return part(parts.host); }
  view_type port() const noexcept { return part(parts.port); }
  view_type path() const noexcept { return part(parts.path); }
  view_type query() const noexcept { return part(parts.query); }
  view_type fragment() const noexcept { return part(parts.fragment); }

  static basic_uri_view parse(view_type str) {
    parts_type parts;
    parts.parse(str);
    return basic_uri_view(str, parts);
  }
};

using uri_view = basic_uri_view<std::string_view, uint16_t>;

} // namespace nexus::http
