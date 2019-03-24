#pragma once

#include <boost/system/system_error.hpp>
#include <http2/protocol.hpp>

namespace nexus::http2::protocol {

/// protocol error category
inline const boost::system::error_category& error_category()
{
  struct category : public boost::system::error_category {
    const char* name() const noexcept override {
      return "http2";
    }
    std::string message(int ev) const override {
      switch (static_cast<error>(ev)) {
        case error::no_error:
          return "success";
        case error::protocol_error:
          return "protocol error";
        case error::internal_error:
          return "internal error";
        case error::flow_control_error:
          return "flow control error";
        case error::settings_timeout:
          return "settings timeout";
        case error::stream_closed:
          return "stream closed";
        case error::frame_size_error:
          return "frame size error";
        case error::refused_stream:
          return "refused stream";
        case error::cancel:
          return "cancel";
        case error::compression_error:
          return "compression error";
        case error::connect_error:
          return "connect error";
        case error::enhance_your_calm:
          return "enhance your calm";
        case error::inadequate_security:
          return "inadequate security";
        case error::http_1_1_required:
          return "http/1.1 required";
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

} // namespace nexus::http::protocol

namespace boost::system {

/// enables implicit conversion to boost::system::error_condition
template <>
struct is_error_condition_enum<nexus::http2::protocol::error> : public std::true_type {};

} // namespace boost::system
