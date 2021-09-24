#pragma once

#include <nexus/udp.hpp>
#include <nexus/quic/client.hpp>

namespace nexus::quic::http3 {

class client_connection;
class stream;

class client {
  friend class client_connection;
  quic::detail::engine_state state;
  quic::detail::socket_state socket;
 public:
  using executor_type = quic::detail::engine_state::executor_type;

  explicit client(udp::socket&& socket, ssl::context_ptr ctx = nullptr);
  client(const executor_type& ex, const udp::endpoint& endpoint,
         ssl::context_ptr ctx = nullptr);

  executor_type get_executor() const;

  udp::endpoint local_endpoint() const;

  void connect(client_connection& conn,
               const udp::endpoint& endpoint,
               const char* hostname);

  void close(error_code& ec);
  void close();
};

class client_connection {
  friend class client;
  friend class stream;
  quic::detail::connection_state state;
 public:
  using executor_type = quic::detail::connection_state::executor_type;

  explicit client_connection(client& c) : state(c.socket) {}
  client_connection(client& c, const udp::endpoint& endpoint,
                    const char* hostname) : state(c.socket) {
    c.connect(*this, endpoint, hostname);
  }

  executor_type get_executor() const;

  udp::endpoint remote_endpoint();

  template <typename CompletionToken> // void(error_code)
  decltype(auto) async_connect(stream& s, CompletionToken&& token) {
    return state.async_connect(s, std::forward<CompletionToken>(token));
  }

  void connect(stream& s, error_code& ec);
  void connect(stream& s);

  void close(error_code& ec);
  void close();
};

} // namespace nexus::quic::http3
