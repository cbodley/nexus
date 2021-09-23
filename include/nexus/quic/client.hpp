#pragma once

#include <nexus/udp.hpp>
#include <nexus/quic/ssl.hpp>
#include <nexus/quic/detail/engine.hpp>
#include <nexus/quic/detail/socket.hpp>

namespace nexus::quic {

class connection;
class stream;

class client {
  friend class connection;
  detail::engine_state state;
  detail::socket_state socket;
 public:
  client(udp::socket&& socket, const char* alpn,
         ssl::context_ptr ctx = nullptr); // TODO: noexcept
  client(const asio::any_io_executor& ex, const udp::endpoint& endpoint,
         const char* alpn, ssl::context_ptr ctx = nullptr);

  udp::endpoint local_endpoint() const;

  void connect(connection& conn,
               const udp::endpoint& endpoint,
               const char* hostname);

  void close(error_code& ec);
  void close();
};

} // namespace nexus::quic
