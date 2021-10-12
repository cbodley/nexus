#pragma once

#include <nexus/udp.hpp>
#include <nexus/quic/client.hpp>

namespace nexus::h3 {

class client_connection;
class stream;

/// an HTTP/3 client that owns a UDP socket and uses it to service client
/// connections
class client {
  friend class client_connection;
  quic::detail::engine_impl engine;
  quic::detail::socket_impl socket;
 public:
  /// the polymorphic executor type, asio::any_io_executor
  using executor_type = quic::detail::engine_impl::executor_type;

  /// construct the client, taking ownership of a bound UDP socket
  client(udp::socket&& socket, asio::ssl::context& ctx);

  /// construct the client, taking ownership of a bound UDP socket
  client(udp::socket&& socket, asio::ssl::context& ctx,
         const quic::settings& s);

  /// construct the client and bind a UDP socket to the given endpoint
  client(const executor_type& ex, const udp::endpoint& endpoint,
         asio::ssl::context& ctx);

  /// construct the client and bind a UDP socket to the given endpoint
  client(const executor_type& ex, const udp::endpoint& endpoint,
         asio::ssl::context& ctx, const quic::settings& s);

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
  /// \overload
  void close();
};

/// an HTTP/3 connection that can initiate outgoing streams and accept
/// server-pushed streams
class client_connection {
  friend class client;
  friend class stream;
  quic::detail::connection_impl impl;
 public:
  /// the polymorphic executor type, asio::any_io_executor
  using executor_type = quic::detail::connection_impl::executor_type;

  /// construct a client-side connection for use with connect()
  explicit client_connection(client& c) : impl(c.socket) {}

  /// open a connection to the given remote endpoint and hostname. this
  /// initiates the TLS handshake, but returns immediately without waiting
  /// for the handshake to complete
  client_connection(client& c, const udp::endpoint& endpoint,
                    const char* hostname) : impl(c.socket) {
    c.connect(*this, endpoint, hostname);
  }

  /// return the associated io executor
  executor_type get_executor() const;

  /// return the remote's address/port. requires that the connection has
  /// successfully been accepted or connected
  udp::endpoint remote_endpoint();

  /// determine whether the connection is open
  bool is_open() const;

  /// open an outgoing stream
  template <typename CompletionToken> // void(error_code, stream)
  decltype(auto) async_connect(CompletionToken&& token) {
    return impl.async_connect<stream>(std::forward<CompletionToken>(token));
  }
  /// \overload
  stream connect(error_code& ec);
  /// \overload
  stream connect();

  /// close the connection, along with any related streams
  void close(error_code& ec);
  /// \overload
  void close();
};

} // namespace nexus::h3
