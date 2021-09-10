#pragma once

#include <nexus/quic/detail/connection.hpp>
#include <nexus/quic/detail/engine.hpp>
#include <nexus/quic/sockaddr.hpp>

namespace nexus::quic {

class stream;
class server_connection;

// TODO: ssl context

class server {
  friend class server_connection;
  detail::engine_state state;
 public:
  // arguments for getaddrinfo() to bind a specific address or port
  server(const char* node, const char* service);

  void local_endpoint(sockaddr_union& local);

  void close() { state.close(); }
};

class server_connection {
  friend class server;
  friend class stream;
  detail::connection_state state;
 public:
  server_connection(server& s) : state(s.state) {}

  void remote_endpoint(sockaddr_union& remote);

  void accept(error_code& ec);
  void accept();
  // TODO: push stream
  void close(error_code& ec) { state.close(ec); }
  void close();
};

} // namespace nexus::quic
