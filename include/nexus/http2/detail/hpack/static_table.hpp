#pragma once

#include <iterator>
#include <string_view>

namespace nexus::http2::hpack::static_table {

struct entry {
  std::string_view name;
  std::string_view value;
};

inline constexpr entry table[] = {
  { ":authority", "" },
  { ":method", "GET" },
  { ":method", "POST" },
  { ":path", "/" },
  { ":path", "/index.html" },
  { ":scheme", "http" },
  { ":scheme", "https" },
  { ":status", "200" },
  { ":status", "204" },
  { ":status", "206" },
  { ":status", "304" },
  { ":status", "400" },
  { ":status", "404" },
  { ":status", "500" },
  { "accept-charset", "" },
  { "accept-encoding", "gzip, deflate" },
  { "accept-language", "" },
  { "accept-ranges", "" },
  { "accept", "" },
  { "access-control-allow-origin", "" },
  { "age", "" },
  { "allow", "" },
  { "authorization", "" },
  { "cache-control", "" },
  { "content-disposition", "" },
  { "content-encoding", "" },
  { "content-language", "" },
  { "content-length", "" },
  { "content-location", "" },
  { "content-range", "" },
  { "content-type", "" },
  { "cookie", "" },
  { "date", "" },
  { "etag", "" },
  { "expect", "" },
  { "expires", "" },
  { "from", "" },
  { "host", "" },
  { "if-match", "" },
  { "if-modified-since", "" },
  { "if-none-match", "" },
  { "if-range", "" },
  { "if-unmodified-since", "" },
  { "last-modified", "" },
  { "link", "" },
  { "location", "" },
  { "max-forwards", "" },
  { "proxy-authenticate", "" },
  { "proxy-authorization", "" },
  { "range", "" },
  { "referer", "" },
  { "refresh", "" },
  { "retry-after", "" },
  { "server", "" },
  { "set-cookie", "" },
  { "strict-transport-security", "" },
  { "transfer-encoding", "" },
  { "user-agent", "" },
  { "vary", "" },
  { "via", "" },
  { "www-authenticate", "" },
};
inline constexpr size_t size = std::size(table);

// searches for the best matching entry, returning its 1-based index
inline std::optional<uint32_t> search(std::string_view name,
                                      std::string_view value,
                                      bool& has_value)
{
  // search the table for matching names
  struct compare_names {
    constexpr bool operator()(const entry& e, std::string_view name) {
      return e.name < name;
    }
    constexpr bool operator()(std::string_view name, const entry& e) {
      return name < e.name;
    }
  };
  auto matches = std::equal_range(std::begin(table), std::end(table),
                                  name, compare_names{});
  // search matches for value
  constexpr auto compare_values = [] (const entry& e, std::string_view value) {
    return e.value < value;
  };
  auto p = std::lower_bound(matches.first, matches.second,
                            value, compare_values);

  std::optional<uint32_t> index;
  if (p != matches.second) {
    has_value = true;
    index = 1 + std::distance(std::begin(table), p);
  } else if (matches.first != matches.second) {
    has_value = false;
    index = 1 + std::distance(std::begin(table), matches.first);
  }
  return index;
}

} // namespace nexus::http2::hpack::static_table
