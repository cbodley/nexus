#pragma once

#include <nexus/udp.hpp>
#include <nexus/quic/ssl.hpp>
#include <nexus/quic/detail/connection.hpp>
#include <nexus/quic/detail/engine.hpp>
#include <nexus/quic/detail/socket.hpp>

namespace nexus::quic {

class acceptor;
class server_connection;
class stream;

class server {
  friend class acceptor;
  detail::engine_state state;
 public:
  using executor_type = detail::stream_state::executor_type;

  explicit server(const executor_type& ex, ssl::cert_lookup* certs);

  executor_type get_executor() { return state.get_executor(); }

  void close();
};

class acceptor {
  friend class server_connection;
  detail::socket_state state;
 public:
  acceptor(server& s, udp::socket&& socket, ssl::context_ptr ctx);
  acceptor(server& s, const udp::endpoint& endpoint, ssl::context_ptr ctx);

  udp::endpoint local_endpoint() const;

  void listen(int backlog);

  template <typename CompletionToken> // void(error_code)
  decltype(auto) async_accept(server_connection& conn,
                              CompletionToken&& token) {
    return state.async_accept(conn, std::forward<CompletionToken>(token));
  }

  void accept(server_connection& conn, error_code& ec);
  void accept(server_connection& conn);

  void close();
};

class server_connection {
  friend class acceptor;
  friend class detail::socket_state;
  friend class stream;
  detail::connection_state state;
 public:
  explicit server_connection(acceptor& a) : state(a.state) {}

  udp::endpoint remote_endpoint();

  template <typename CompletionToken> // void(error_code)
  decltype(auto) async_accept(stream& s, CompletionToken&& token) {
    return state.async_accept(s, std::forward<CompletionToken>(token));
  }

  void accept(stream& s, error_code& ec);
  void accept(stream& s);

  // TODO: push stream
  void close(error_code& ec) { state.close(ec); }
  void close();
};

} // namespace nexus::quic
