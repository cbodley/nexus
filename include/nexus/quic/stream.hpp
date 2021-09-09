#pragma once

#include <nexus/error_code.hpp>
#include <nexus/quic/client.hpp>

namespace nexus::quic {

class stream {
 protected:
  detail::stream_state state;
  explicit stream(detail::connection_state& cstate) : state(cstate) {
    error_code ec;
    cstate.open_stream(state, ec);
    if (ec) {
      throw system_error(ec);
    }
  }
 public:
  explicit stream(client_connection& c) : stream(c.state) {}
  ~stream() {
    error_code ec_ignored;
    close(ec_ignored);
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
