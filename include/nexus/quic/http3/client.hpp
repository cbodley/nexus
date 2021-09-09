#pragma once

#include <nexus/quic/client.hpp>

namespace nexus::quic::http3 {

class client_connection;

class client {
  friend class client_connection;
  quic::detail::engine_state state;
 public:
  client();
  void close() { state.close(); }
};

class client_connection {
  friend class stream;
  quic::detail::connection_state state;
 public:
  client_connection(client& c, const sockaddr* remote_endpoint,
                    const char* remote_hostname)
      : state(c.state, remote_endpoint, remote_hostname) {}
  void open_stream(quic::detail::stream_state& stream, error_code& ec) {
    state.open_stream(stream, ec);
  }
  void close(error_code& ec) { state.close(ec); }
};

} // namespace nexus::quic::http3
