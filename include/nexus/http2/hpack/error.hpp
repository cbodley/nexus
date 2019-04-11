#pragma once

#include <boost/system/error_code.hpp>

namespace nexus::http2::hpack {

// hpack error conditions
enum class error {
  no_error = 0,
  decode_invalid_index,
  decode_integer_overflow,
  decode_truncated,
  exceeded_max_header_list_size,
};

// hpack error category
inline const boost::system::error_category& error_category()
{
  struct category : public boost::system::error_category {
    const char* name() const noexcept override {
      return "hpack";
    }
    std::string message(int ev) const override {
      switch (static_cast<error>(ev)) {
        case error::no_error:
          return "success";
        case error::decode_invalid_index:
          return "decode invalid index";
        case error::decode_integer_overflow:
          return "decode integer overflow";
        case error::decode_truncated:
          return "decode truncated";
        case error::exceeded_max_header_list_size:
          return "exceeded max header list size";
        default:
          return "unknown";
      }
    }
  };
  static category instance;
  return instance;
}

inline boost::system::error_code make_error_code(error e)
{
  return {static_cast<int>(e), error_category()};
}

inline boost::system::error_condition make_error_condition(error e)
{
  return {static_cast<int>(e), error_category()};
}

} // namespace nexus::http2::hpack

namespace boost::system {

// enables implicit conversion to boost::system::error_condition
template <>
struct is_error_condition_enum<nexus::http2::hpack::error> : public std::true_type {};

} // namespace boost::system
