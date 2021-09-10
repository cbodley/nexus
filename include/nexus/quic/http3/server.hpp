#pragma once

#include <nexus/quic/server.hpp>
#include <nexus/quic/sockaddr.hpp>

namespace nexus::quic::http3 {

class server_connection;
class stream;

class server {
  friend class server_connection;
  quic::detail::engine_state state;
 public:
  // arguments for getaddrinfo() to bind a specific address or port
  server(const char* node, const char* service);

  void local_endpoint(sockaddr_union& local);

  void close() { state.close(); }
};

class server_connection {
  friend class server;
  friend class stream;
  quic::detail::connection_state state;
 public:
  server_connection(server& s) : state(s.state) {}

  void remote_endpoint(sockaddr_union& remote);

  void accept(error_code& ec);
  void accept();
  // TODO: push stream
  void close(error_code& ec) { state.close(ec); }
};

} // namespace nexus::quic::http3
