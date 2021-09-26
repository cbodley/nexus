#pragma once

#include <nexus/udp.hpp>
#include <nexus/quic/client.hpp>

namespace nexus::quic::http3 {

class client_connection;
class stream;

/// an HTTP/3 client that owns a UDP socket and uses it to service client
/// connections
class client {
  friend class client_connection;
  quic::detail::engine_state state;
  quic::detail::socket_state socket;
 public:
  /// the polymorphic executor type, asio::any_io_executor
  using executor_type = quic::detail::engine_state::executor_type;

  /// construct the client, taking ownership of a bound UDP socket
  explicit client(udp::socket&& socket, asio::ssl::context& ctx);

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
  void connect(client_connection& conn,
               const udp::endpoint& endpoint,
               const char* hostname);

  /// close the socket, along with any related connections
  void close(error_code& ec);
  /// close the socket, along with any related connections
  void close();
};

/// an HTTP/3 connection that can initiate outgoing streams and accept
/// server-pushed streams
class client_connection {
  friend class client;
  friend class stream;
  quic::detail::connection_state state;
 public:
  /// the polymorphic executor type, asio::any_io_executor
  using executor_type = quic::detail::connection_state::executor_type;

  /// construct a client-side connection for use with connect()
  explicit client_connection(client& c) : state(c.socket) {}

  /// open a connection to the given remote endpoint and hostname. this
  /// initiates the TLS handshake, but returns immediately without waiting
  /// for the handshake to complete
  client_connection(client& c, const udp::endpoint& endpoint,
                    const char* hostname) : state(c.socket) {
    c.connect(*this, endpoint, hostname);
  }

  /// return the associated io executor
  executor_type get_executor() const;

  /// return the remote's address/port. requires that the connection has
  /// successfully been accepted or connected
  udp::endpoint remote_endpoint();

  /// open an outgoing stream
  template <typename CompletionToken> // void(error_code)
  decltype(auto) async_connect(stream& s, CompletionToken&& token) {
    return state.async_connect(s, std::forward<CompletionToken>(token));
  }

  /// open an outgoing stream
  void connect(stream& s, error_code& ec);
  /// open an outgoing stream
  void connect(stream& s);

  /// close the connection, along with any related streams
  void close(error_code& ec);
  /// close the connection, along with any related streams
  void close();
};

} // namespace nexus::quic::http3
