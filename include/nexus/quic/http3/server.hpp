#pragma once

#include <nexus/udp.hpp>
#include <nexus/quic/server.hpp>

namespace nexus::quic::http3 {

class server_connection;
class stream;

class server {
  friend class server_connection;
  quic::detail::engine_state state;
 public:
  explicit server(udp::socket&& socket);
  server(const asio::any_io_executor& ex, const udp::endpoint& endpoint);

  udp::endpoint local_endpoint() const;

  void close() { state.close(); }
};

class server_connection {
  friend class server;
  friend class stream;
  quic::detail::connection_state state;
 public:
  server_connection(server& s) : state(s.state) {}

  udp::endpoint remote_endpoint();

  void accept(error_code& ec);
  void accept();
  // TODO: push stream
  void close(error_code& ec) { state.close(ec); }
};

} // namespace nexus::quic::http3
