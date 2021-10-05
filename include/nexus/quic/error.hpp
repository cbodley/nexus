#pragma once

#include <nexus/error_code.hpp>

namespace nexus::quic {

/// generic quic errors
enum class error {
  /// this end of the connection was closed
  connection_aborted = 1,
  /// the connection's tls handshake failed
  connection_handshake_failed,
  /// the connection or handshake timed out
  connection_timed_out,
  /// connection reset by peer
  connection_reset,
  /// sent GOAWAY to peer
  connection_going_away,
  /// peer sent GOAWAY
  peer_going_away,

  /// no bytes can be read because the peer closed the stream for writing
  end_of_stream,
  /// stream cannot process more than one read or more than one write at a time
  stream_busy,
  /// this end of the stream was closed
  stream_aborted,
  /// stream reset by peer
  stream_reset,
};

/// quic error category
const error_category& quic_category();

inline error_code make_error_code(error e)
{
  return {static_cast<int>(e), quic_category()};
}

inline error_condition make_error_condition(error e)
{
  return {static_cast<int>(e), quic_category()};
}

/// application-level error category
const error_category& application_category();

} // namespace nexus::quic

namespace SYSTEM_ERROR_NAMESPACE {

/// enables implicit conversion to std::error_condition
template <>
struct is_error_condition_enum<nexus::quic::error> : public true_type {};

} // namespace SYSTEM_ERROR_NAMESPACE
