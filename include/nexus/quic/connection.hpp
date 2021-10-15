#pragma once

#include <nexus/quic/connection_id.hpp>
#include <nexus/quic/detail/connection_impl.hpp>

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
  friend class detail::socket_impl;
  detail::connection_impl impl;
 public:
  /// the polymorphic executor type, asio::any_io_executor
  using executor_type = detail::connection_impl::executor_type;

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

  /// determine whether the connection is open
  bool is_open() const;

  /// return the connection id if open
  connection_id id(error_code& ec) const;
  /// \overload
  connection_id id() const;

  /// return the remote's address/port if open
  udp::endpoint remote_endpoint(error_code& ec) const;
  /// \overload
  udp::endpoint remote_endpoint() const;

  /// open an outgoing stream
  template <typename CompletionToken> // void(error_code, stream)
  decltype(auto) async_connect(stream& s, CompletionToken&& token) {
    return impl.async_connect<stream>(s, std::forward<CompletionToken>(token));
  }
  /// \overload
  void connect(stream& s, error_code& ec);
  /// \overload
  void connect(stream& s);

  /// accept an incoming stream
  template <typename CompletionToken> // void(error_code, stream)
  decltype(auto) async_accept(stream& s, CompletionToken&& token) {
    return impl.async_accept<stream>(s, std::forward<CompletionToken>(token));
  }
  /// \overload
  void accept(stream& s, error_code& ec);
  /// \overload
  void accept(stream& s);

  /// close the connection, along with any related streams
  void close(error_code& ec);
  /// \overload
  void close();
};

} // namespace nexus::quic
