#pragma once

#include <nexus/error_code.hpp>
#include <nexus/quic/detail/handler_ptr.hpp>
#include <nexus/quic/detail/operation.hpp>
#include <nexus/quic/detail/stream.hpp>

namespace nexus::quic {

namespace detail {

struct connection_state;

} // namespace detail

class connection;

class stream {
 protected:
  friend class connection;
  friend class detail::connection_state;
  detail::stream_state state;
  explicit stream(detail::connection_state& cstate) : state(cstate) {}
 public:
  using executor_type = detail::stream_state::executor_type;

  explicit stream(connection& c);

  executor_type get_executor() const;

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

  void flush(error_code& ec);
  void flush();

  void shutdown(int how, error_code& ec);
  void shutdown(int how);

  void close(error_code& ec);
  void close();
};

} // namespace nexus::quic
