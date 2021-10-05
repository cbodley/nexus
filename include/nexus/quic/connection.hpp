#pragma once

#include <nexus/quic/detail/connection.hpp>

namespace nexus::quic {

class acceptor;
class client;
class stream;

/// a generic QUIC connection that can initiate outgoing streams and accept
/// incoming streams
class connection {
  friend class acceptor;
  friend class client;
  friend class stream;
  friend class detail::socket_state;
  detail::connection_state state;
 public:
  /// the polymorphic executor type, asio::any_io_executor
  using executor_type = detail::connection_state::executor_type;

  /// construct a server-side connection for use with accept()
  explicit connection(acceptor& a);

  /// construct a client-side connection for use with connect()
  explicit connection(client& c);

  /// open a connection to the given remote endpoint and hostname. this
  /// initiates the TLS handshake, but returns immediately without waiting
  /// for the handshake to complete
  connection(client& c, const udp::endpoint& endpoint, const char* hostname);

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
  /// \overload
  void connect(stream& s);

  /// accept an incoming stream
  template <typename CompletionToken> // void(error_code)
  decltype(auto) async_accept(stream& s, CompletionToken&& token) {
    return state.async_accept(s, std::forward<CompletionToken>(token));
  }

  /// accept an incoming stream
  void accept(stream& s, error_code& ec);
  /// \overload
  void accept(stream& s);

  /// close the connection, along with any related streams
  void close(error_code& ec);
  /// \overload
  void close();
};

} // namespace nexus::quic
