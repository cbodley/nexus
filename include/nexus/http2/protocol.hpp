#pragma once

#include <array>
#include <limits>
#include <string_view>

namespace nexus::http2::protocol {

static constexpr std::string_view client_connection_preface =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

enum class protocol_id : uint8_t {
  h2,
  h2c
};

// 5.1 Stream States
enum class stream_state {
  idle,
  open,
  reserved_remote,
  reserved_local,
  half_closed_remote,
  half_closed_local,
  closed,
};

// 5.1.1 Stream Identifiers
using stream_identifier = uint32_t;
constexpr bool client_initiated(stream_identifier id) { return (id & 1) == 1; } // odd
constexpr bool server_initiated(stream_identifier id) { return (id & 1) == 0; } // even

struct stream_priority {
  stream_identifier dependency = 0;
  bool exclusive = false;
  uint8_t weight = 15;
};

// 6. Frame Definitions
enum class frame_type : uint8_t {
  data = 0,
  headers = 1,
  priority = 2,
  rst_stream = 3,
  settings = 4,
  push_promise = 5,
  ping = 6,
  goaway = 7,
  window_update = 8,
  continuation = 9,
};

struct frame_header {
  uint32_t length; // payload size as 24-bit unsigned integer
  uint8_t type;
  uint8_t flags;
  stream_identifier stream_id; // highest bit reserved
};
constexpr stream_identifier stream_identifier_mask = 0x7fffffff;

constexpr uint8_t frame_flag_end_stream = 0x1;
constexpr uint8_t frame_flag_ack = 0x1;
constexpr uint8_t frame_flag_end_headers = 0x4;
constexpr uint8_t frame_flag_padded = 0x8;
constexpr uint8_t frame_flag_priority = 0x20;

// 6.5.1. SETTINGS Format
using setting_parameter_identifier = uint16_t;
using setting_value = uint32_t;

struct setting_parameter_pair {
  setting_parameter_identifier identifier;
  setting_value value;
};

// 6.5.2. Defined SETTINGS Parameters
enum class setting_parameter : setting_parameter_identifier {
  header_table_size = 1,
  enable_push = 2,
  max_concurrent_streams = 3,
  initial_window_size = 4,
  max_frame_size = 5,
  max_header_list_size = 6,
};
constexpr size_t num_setting_parameters = 6;

using setting_parameters = std::array<setting_parameter_pair,
                                      num_setting_parameters>;

// value bounds
constexpr setting_value max_setting_value = std::numeric_limits<setting_value>::max();
constexpr setting_value min_setting_max_frame_size = 16384;
constexpr setting_value max_setting_max_frame_size = 16777215;
// default values
constexpr setting_value default_setting_header_table_size = 4096;
constexpr setting_value default_setting_enable_push = 1;
constexpr setting_value default_setting_max_concurrent_streams = max_setting_value;
constexpr setting_value default_setting_initial_window_size = 65535;
constexpr setting_value default_setting_max_frame_size = min_setting_max_frame_size;
constexpr setting_value default_setting_max_header_list_size = max_setting_value;

struct setting_values {
  setting_value header_table_size = default_setting_header_table_size;
  setting_value enable_push = default_setting_enable_push;
  setting_value max_concurrent_streams = default_setting_max_concurrent_streams;
  setting_value initial_window_size = default_setting_initial_window_size;
  setting_value max_frame_size = default_setting_max_frame_size;
  setting_value max_header_list_size = default_setting_max_header_list_size;
};
inline const setting_values default_settings{};

inline bool operator==(const setting_values& lhs, const setting_values& rhs) {
  return std::equal(&lhs.header_table_size,
                    &lhs.header_table_size + protocol::num_setting_parameters,
                    &rhs.header_table_size);
}
inline bool operator!=(const setting_values& lhs, const setting_values& rhs) {
  return !std::equal(&lhs.header_table_size,
                     &lhs.header_table_size + protocol::num_setting_parameters,
                     &rhs.header_table_size);
}

using flow_control_size_type = uint32_t;
constexpr flow_control_size_type max_flow_control_window_size = 0x7fffffff;
using flow_control_ssize_type = int32_t;

/// protocol error codes
enum class error {
  no_error = 0x0,
  protocol_error = 0x1,
  internal_error = 0x2,
  flow_control_error = 0x3,
  settings_timeout = 0x4,
  stream_closed = 0x5,
  frame_size_error = 0x6,
  refused_stream = 0x7,
  cancel = 0x8,
  compression_error = 0x9,
  connect_error = 0xa,
  enhance_your_calm = 0xb,
  inadequate_security = 0xc,
  http_1_1_required = 0xd,
};

} // namespace nexus::http2::protocol
