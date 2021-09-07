#pragma once

#include <memory>

#include <nexus/quic/detail/client.hpp>

namespace nexus::quic {

class client_connection {
  using state_ptr = boost::intrusive_ptr<detail::client_connection_state>;
  state_ptr state;
 public:
  client_connection(state_ptr&& state) : state(std::move(state)) {}
  ~client_connection() {
    if (state) {
      state->close();
    }
  }
  boost::intrusive_ptr<detail::stream_state> open_stream() {
    return state->open_stream();
  }
  void close() { state->close(); }
};

class client {
  boost::intrusive_ptr<detail::client_engine_state> state;
 public:
  explicit client(const boost::asio::executor& ex)
    : state(detail::client_engine_state::create(ex, 0)) {}

  client_connection connect(const udp::endpoint& remote_endpoint,
                            const char* remote_hostname) {
    return state->connect(remote_endpoint, remote_hostname);
  }
  void close() { state->close(); }
};

} // namespace nexus::quic
