#pragma once

#include <nexus/error_code.hpp>
#include <nexus/quic/client.hpp>
#include <nexus/quic/server.hpp>

namespace nexus::quic {

class stream {
 protected:
  friend class client_connection;
  friend class server_connection;
  detail::stream_state state;
  explicit stream(detail::connection_state& cstate) : state(cstate) {}
 public:
  explicit stream(server_connection& c) : stream(c.state) {}
  explicit stream(client_connection& c) : stream(c.state) {}

  void connect(error_code& ec) {
    state.connect(ec);
  }
  void connect() {
    error_code ec;
    state.connect(ec);
    if (ec) {
      throw system_error(ec);
    }
  }

  void accept(error_code& ec) {
    state.accept(ec);
  }
  void accept() {
    error_code ec;
    state.accept(ec);
    if (ec) {
      throw system_error(ec);
    }
  }

  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers, error_code& ec) {
    return state.read(buffers, ec);
  }
  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers) {
    error_code ec;
    const size_t bytes = state.read(buffers, ec);
    if (ec) {
      throw system_error(ec);
    }
    return bytes;
  }

  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers, error_code& ec) {
    return state.write(buffers, ec);
  }
  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers) {
    error_code ec;
    const size_t bytes = state.write(buffers, ec);
    if (ec) {
      throw system_error(ec);
    }
    return bytes;
  }

  void shutdown(int how, error_code& ec) {
    state.shutdown(how, ec);
  }
  void shutdown(int how) {
    error_code ec;
    state.shutdown(how, ec);
    if (ec) {
      throw system_error(ec);
    }
  }

  void close(error_code& ec) {
    state.close(ec);
  }
  void close() {
    error_code ec;
    state.close(ec);
    if (ec) {
      throw system_error(ec);
    }
  }
};

} // namespace nexus::quic
