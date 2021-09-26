#pragma once

#include <nexus/udp.hpp>
#include <nexus/quic/ssl.hpp>
#include <nexus/quic/detail/engine.hpp>
#include <nexus/quic/detail/socket.hpp>

namespace nexus::quic {

class connection;
class stream;

/// a generic QUIC client that owns a UDP socket and uses it to service client
/// connections
class client {
  friend class connection;
  detail::engine_state state;
  detail::socket_state socket;
 public:
  /// the polymorphic executor type, asio::any_io_executor
  using executor_type = detail::engine_state::executor_type;

  /// construct the client, taking ownership of a bound UDP socket
  client(udp::socket&& socket, asio::ssl::context& ctx); // TODO: noexcept

  /// construct the client and bind a UDP socket to the given endpoint
  client(const executor_type& ex, const udp::endpoint& endpoint,
         asio::ssl::context& ctx);

  /// return the associated io executor
  executor_type get_executor() const;

  /// return the socket's locally-bound address/port
  udp::endpoint local_endpoint() const;

  /// open a connection to the given remote endpoint and hostname. this
  /// initiates the TLS handshake, but returns immediately without waiting
  /// for the handshake to complete
  void connect(connection& conn,
               const udp::endpoint& endpoint,
               const char* hostname);

  /// close the socket, along with any related connections
  void close(error_code& ec);
  /// close the socket, along with any related connections
  void close();
};

} // namespace nexus::quic
