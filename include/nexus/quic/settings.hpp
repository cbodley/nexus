#pragma once

#include <chrono>
#include <stdexcept>

struct lsquic_engine_settings;

namespace nexus::quic {

/// exception thrown by client/server constructors on unchecked settings
struct bad_setting : std::runtime_error {
  using runtime_error::runtime_error;
};

/// quic transport settings used to initialize a client or server
struct settings {
  /// handshake timeout, resulting in connection_error::timed_out
  std::chrono::seconds handshake_timeout;

  /// connection idle timeout, resulting in connection_error::timed_out
  std::chrono::seconds idle_timeout;

  /// number of concurrent streams a peer is allowed to open per connection
  uint32_t max_streams_per_connection;

  /// amount of unread bytes a peer is allowed to send per connection
  uint32_t connection_flow_control_window;

  /// amount of unread bytes a peer is allowed to send on streams they initiate
  uint32_t incoming_stream_flow_control_window;

  /// amount of unread bytes a peer is allowed to send on streams we initiate
  uint32_t outgoing_stream_flow_control_window;
};

/// return default client settings
/// \relatesalso settings
settings default_client_settings();
/// return default server settings
/// \relatesalso settings
settings default_server_settings();

/// check the validity of the client settings
/// \relatesalso settings
bool check_client_settings(const settings& s, std::string* message);
/// check the validity of the server settings
/// \relatesalso settings
bool check_server_settings(const settings& s, std::string* message);


namespace detail {

void read_settings(settings& out, const lsquic_engine_settings& in);
void write_settings(const settings& in, lsquic_engine_settings& out);

} // namespace detail

} // namespace nexus::quic
