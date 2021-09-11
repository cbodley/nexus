#pragma once

#include <nexus/udp.hpp>
#include <nexus/quic/detail/connection.hpp>
#include <nexus/quic/detail/engine.hpp>

namespace nexus::quic {

class stream;
class server_connection;

// TODO: ssl context

class server {
  friend class server_connection;
  detail::engine_state state;
 public:
  explicit server(udp::socket&& socket);
  server(const asio::any_io_executor& ex, const udp::endpoint& endpoint);

  udp::endpoint local_endpoint() const;

  void close() { state.close(); }
};

class server_connection {
  friend class server;
  friend class stream;
  detail::connection_state state;
 public:
  server_connection(server& s) : state(s.state) {}

  udp::endpoint remote_endpoint();

  void accept(error_code& ec);
  void accept();
  // TODO: push stream
  void close(error_code& ec) { state.close(ec); }
  void close();
};

} // namespace nexus::quic
