#pragma once

#include <nexus/error_code.hpp>
#include <nexus/quic/client.hpp>
#include <nexus/quic/server.hpp>
#include <nexus/quic/detail/handler_ptr.hpp>
#include <nexus/quic/detail/operation.hpp>
#include <nexus/quic/detail/stream.hpp>

namespace nexus::quic {

class stream {
 protected:
  friend class client_connection;
  friend class server_connection;
  friend class detail::connection_state;
  detail::stream_state state;
  explicit stream(detail::connection_state& cstate) : state(cstate) {}
 public:
  explicit stream(server_connection& c) : stream(c.state) {}
  explicit stream(client_connection& c) : stream(c.state) {}

  using executor_type = detail::stream_state::executor_type;
  executor_type get_executor() { return state.get_executor(); }

  template <typename MutableBufferSequence,
            typename CompletionToken> // void(error_code, size_t)
  decltype(auto) async_read_some(const MutableBufferSequence& buffers,
                                 CompletionToken&& token) {
    return state.async_read_some(buffers, std::forward<CompletionToken>(token));
  }

  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers, error_code& ec) {
    return state.read_some(buffers, ec);
  }
  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers) {
    error_code ec;
    const size_t bytes = state.read_some(buffers, ec);
    if (ec) {
      throw system_error(ec);
    }
    return bytes;
  }

  template <typename ConstBufferSequence,
            typename CompletionToken> // void(error_code, size_t)
  decltype(auto) async_write_some(const ConstBufferSequence& buffers,
                                  CompletionToken&& token) {
    return state.async_write_some(buffers, std::forward<CompletionToken>(token));
  }

  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers, error_code& ec) {
    return state.write_some(buffers, ec);
  }
  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers) {
    error_code ec;
    const size_t bytes = state.write_some(buffers, ec);
    if (ec) {
      throw system_error(ec);
    }
    return bytes;
  }

  void flush(error_code& ec) {
    state.flush(ec);
  }
  void flush() {
    error_code ec;
    flush(ec);
    if (ec) {
      throw system_error(ec);
    }
  }

  void shutdown(int how, error_code& ec) {
    state.shutdown(how, ec);
  }
  void shutdown(int how) {
    error_code ec;
    shutdown(how, ec);
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
