#pragma once

#include <nexus/udp.hpp>
#include <nexus/quic/ssl.hpp>
#include <nexus/quic/detail/connection.hpp>
#include <nexus/quic/detail/engine.hpp>
#include <nexus/quic/detail/socket.hpp>

namespace nexus::quic {

class client_connection;
class stream;

class client {
  friend class client_connection;
  detail::engine_state state;
  detail::socket_state socket;
 public:
  client(udp::socket&& socket, const char* alpn,
         ssl::context_ptr ctx = nullptr);
  client(const asio::any_io_executor& ex, const udp::endpoint& endpoint,
         const char* alpn, ssl::context_ptr ctx = nullptr);

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
  detail::connection_state state;
 public:
  explicit client_connection(client& c) : state(c.socket) {}
  client_connection(client& c, const udp::endpoint& endpoint,
                    const char* hostname)
      : state(c.socket) {
    c.connect(*this, endpoint, hostname);
  }

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

} // namespace nexus::quic
