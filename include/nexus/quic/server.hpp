#pragma once

#include <nexus/udp.hpp>
#include <nexus/ssl.hpp>
#include <nexus/quic/detail/engine_impl.hpp>
#include <nexus/quic/detail/socket_impl.hpp>

namespace nexus::quic {

class acceptor;
class connection;

/// a generic QUIC server capable of managing one or more UDP sockets via
/// class acceptor
class server {
  friend class acceptor;
  detail::engine_impl engine;
 public:
  /// the polymorphic executor type, boost::asio::any_io_executor
  using executor_type = detail::engine_impl::executor_type;

  /// construct the server with its associated executor
  explicit server(const executor_type& ex);

  /// construct the server with its associated executor and transport settings
  server(const executor_type& ex, const settings& s);

  /// return the associated io executor
  executor_type get_executor() const;

  /// stop accepting new connections and streams entirely, and mark existing
  /// connections as 'going away'. each associated acceptor is responsible for
  /// closing its own socket
  void close();
};

/// a generic QUIC acceptor that owns a UDP socket and uses it to accept and
/// service incoming connections
class acceptor {
  friend class connection;
  detail::socket_impl impl;
 public:
  /// the polymorphic executor type, boost::asio::any_io_executor
  using executor_type = detail::socket_impl::executor_type;

  /// construct the acceptor, taking ownership of a bound UDP socket
  acceptor(server& s, udp::socket&& socket, ssl::context& ctx);

  /// construct the acceptor and bind a UDP socket to the given endpoint
  acceptor(server& s, const udp::endpoint& endpoint, ssl::context& ctx);

  /// return the associated io executor
  executor_type get_executor() const;

  /// return the socket's locally-bound address/port
  udp::endpoint local_endpoint() const;

  /// start receiving packets on the socket. incoming connections can be
  /// accepted with accept()/async_accept(). if the queue of unaccepted
  /// connections reaches 'backlog' in size, new connections are rejected
  void listen(int backlog);

  /// accept an incoming connection whose TLS handshake has completed
  /// successfully
  template <typename CompletionToken> // void(error_code)
  decltype(auto) async_accept(connection& conn, CompletionToken&& token) {
    return impl.async_accept(conn, std::forward<CompletionToken>(token));
  }

  /// accept an incoming connection whose TLS handshake has completed
  /// successfully
  void accept(connection& conn, error_code& ec);
  /// \overload
  void accept(connection& conn);

  /// close the socket, along with any related connections
  void close();
};

} // namespace nexus::quic
