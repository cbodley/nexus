#pragma once

#include <nexus/error_code.hpp>

namespace nexus::quic {

/// transport error codes sent in CONNECTION_CLOSE frames
enum class transport_error {
  no_error = 0x0,
  internal_error = 0x1,
  connection_refused = 0x2,
  flow_control_error = 0x3,
  stream_limit_error = 0x4,
  stream_state_error = 0x5,
  final_size_error = 0x6,
  frame_encoding_error = 0x7,
  transport_parameter_error = 0x8,
  connection_id_limit_error = 0x9,
  protocol_violation = 0xa,
  invalid_token = 0xb,
  application_error = 0xc,
  crypto_buffer_exceeded = 0xd,
  key_update_error = 0xe,
  aead_limit_reached = 0xf,
  no_viable_path = 0x10,
};

/// transport error category
const error_category& transport_category();

inline error_code make_error_code(transport_error e)
{
  return {static_cast<int>(e), transport_category()};
}

inline error_condition make_error_condition(transport_error e)
{
  return {static_cast<int>(e), transport_category()};
}

} // namespace nexus::quic

namespace SYSTEM_ERROR_NAMESPACE {

/// enables implicit conversion to std::error_condition
template <>
struct is_error_condition_enum<nexus::quic::transport_error> : public true_type {};

} // namespace SYSTEM_ERROR_NAMESPACE
