#pragma once

#include <nexus/quic/client.hpp>

namespace nexus::quic {

class stream {
 protected:
  using state_ptr = boost::intrusive_ptr<detail::stream_state>;
  state_ptr state;
  explicit stream(state_ptr&& state) : state(std::move(state)) {}
 public:
  explicit stream(client_connection& conn) : state(conn.open_stream()) {}
  stream(stream&&) = default;
  stream& operator=(stream&&) = default;
  ~stream() {
    std::cerr << "~stream " << state.get() << std::endl;
    if (state) {
      error_code ec_ignored;
      state->close(ec_ignored);
    }
  }

  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers, error_code& ec) {
    return state->read(buffers, ec);
  }
  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers) {
    error_code ec;
    const size_t bytes = state->read(buffers, ec);
    if (ec) {
      throw boost::system::system_error(ec);
    }
    return bytes;
  }

  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers, error_code& ec) {
    return state->write(buffers, ec);
  }
  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers) {
    error_code ec;
    const size_t bytes = state->write(buffers, ec);
    if (ec) {
      throw boost::system::system_error(ec);
    }
    return bytes;
  }

  void shutdown(int how, error_code& ec) {
    state->shutdown(how, ec);
  }

  void close(error_code& ec) {
    state->close(ec);
  }
};

} // namespace nexus::quic
