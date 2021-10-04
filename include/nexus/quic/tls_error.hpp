#pragma once

#include <nexus/error_code.hpp>

namespace nexus::quic {

// TLS alerts from https://www.rfc-editor.org/rfc/rfc8446#section-6
enum class tls_alert : uint8_t {
  close_notify = 0,
  unexpected_message = 10,
  bad_record_mac = 20,
  record_overflow = 22,
  handshake_failure = 40,
  bad_certificate = 42,
  unsupported_certificate = 43,
  certificate_revoked = 44,
  certificate_expired = 45,
  certificate_unknown = 46,
  illegal_parameter = 47,
  unknown_ca = 48,
  access_denied = 49,
  decode_error = 50,
  decrypt_error = 51,
  protocol_version = 70,
  insufficient_security = 71,
  internal_error = 80,
  inappropriate_fallback = 86,
  user_canceled = 90,
  missing_extension = 109,
  unsupported_extension = 110,
  unrecognized_name = 112,
  bad_certificate_status_response = 113,
  unknown_psk_identity = 115,
  certificate_required = 116,
  no_application_protocol = 120,
};

/// tls error category
const error_category& tls_category();

inline error_code make_error_code(tls_alert e)
{
  return {static_cast<int>(e), tls_category()};
}

inline error_condition make_error_condition(tls_alert e)
{
  return {static_cast<int>(e), tls_category()};
}

} // namespace nexus::quic

namespace SYSTEM_ERROR_NAMESPACE {

/// enables implicit conversion to std::error_condition
template <>
struct is_error_condition_enum<nexus::quic::tls_alert> : public true_type {};

} // namespace SYSTEM_ERROR_NAMESPACE
