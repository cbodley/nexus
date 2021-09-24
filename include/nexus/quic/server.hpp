#pragma once

#include <nexus/udp.hpp>
#include <nexus/quic/ssl.hpp>
#include <nexus/quic/detail/engine.hpp>
#include <nexus/quic/detail/socket.hpp>

namespace nexus::quic {

class acceptor;
class connection;

class server {
  friend class acceptor;
  detail::engine_state state;
 public:
  using executor_type = detail::engine_state::executor_type;

  server(const executor_type& ex, ssl::certificate_provider* certs);

  executor_type get_executor() { return state.get_executor(); }

  void close();
};

class acceptor {
  friend class connection;
  detail::socket_state state;
 public:
  acceptor(server& s, udp::socket&& socket, ssl::context_ptr ctx);
  acceptor(server& s, const udp::endpoint& endpoint, ssl::context_ptr ctx);

  udp::endpoint local_endpoint() const;

  void listen(int backlog);

  template <typename CompletionToken> // void(error_code)
  decltype(auto) async_accept(connection& conn, CompletionToken&& token) {
    return state.async_accept(conn, std::forward<CompletionToken>(token));
  }

  void accept(connection& conn, error_code& ec);
  void accept(connection& conn);

  void close();
};

} // namespace nexus::quic
