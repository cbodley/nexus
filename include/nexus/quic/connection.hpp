#pragma once

#include <nexus/quic/detail/connection.hpp>

namespace nexus::quic {

class acceptor;
class client;
class stream;

class connection {
  friend class acceptor;
  friend class client;
  friend class stream;
  friend class detail::socket_state;
  detail::connection_state state;
 public:
  using executor_type = detail::connection_state::executor_type;

  explicit connection(acceptor& a);
  explicit connection(client& c);
  connection(client& c, const udp::endpoint& endpoint, const char* hostname);

  executor_type get_executor() const;

  udp::endpoint remote_endpoint();

  template <typename CompletionToken> // void(error_code)
  decltype(auto) async_connect(stream& s, CompletionToken&& token) {
    return state.async_connect(s, std::forward<CompletionToken>(token));
  }

  void connect(stream& s, error_code& ec);
  void connect(stream& s);

  template <typename CompletionToken> // void(error_code)
  decltype(auto) async_accept(stream& s, CompletionToken&& token) {
    return state.async_accept(s, std::forward<CompletionToken>(token));
  }

  void accept(stream& s, error_code& ec);
  void accept(stream& s);

  void close(error_code& ec);
  void close();
};

} // namespace nexus::quic
