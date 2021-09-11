#pragma once

#include <nexus/udp.hpp>
#include <nexus/quic/detail/connection.hpp>
#include <nexus/quic/detail/engine.hpp>

namespace nexus::quic {

class client_connection;

class client {
  friend class client_connection;
  detail::engine_state state;
 public:
  explicit client(udp::socket&& socket);
  client(const asio::any_io_executor& ex, const udp::endpoint& endpoint);

  udp::endpoint local_endpoint() const;

  void close() { state.close(); }
};

class client_connection {
  friend class stream;
  detail::connection_state state;
 public:
  explicit client_connection(client& c) : state(c.state) {}

  udp::endpoint remote_endpoint();

  void connect(const udp::endpoint& endpoint,
               const char* hostname, error_code& ec);
  void connect(const udp::endpoint& endpoint,
               const char* hostname);

  void close(error_code& ec) { state.close(ec); }
  void close();
};

} // namespace nexus::quic
