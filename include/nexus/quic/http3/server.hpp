#pragma once

#include <nexus/udp.hpp>
#include <nexus/quic/server.hpp>

namespace nexus::quic::http3 {

class acceptor;
class server_connection;
class stream;

class server {
  friend class acceptor;
  quic::detail::engine_state state;
 public:
  using executor_type = quic::detail::stream_state::executor_type;

  server(const executor_type& ex, ssl::certificate_provider* certs);

  executor_type get_executor() { return state.get_executor(); }

  void close() { state.close(); }
};

class acceptor {
  friend class server_connection;
  quic::detail::socket_state state;
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
  friend class stream;
  quic::detail::connection_state state;
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
};

} // namespace nexus::quic::http3
