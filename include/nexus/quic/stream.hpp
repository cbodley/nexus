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

/// a generic bidirectional QUIC stream that meets the type requirements of
/// asio's AsyncRead/WriteStream and SyncRead/WriteStream
class stream {
 protected:
  friend class connection;
  friend class detail::connection_state;
  detail::stream_state state;
  explicit stream(detail::connection_state& cstate) : state(cstate) {}
 public:
  /// the polymorphic executor type, asio::any_io_executor
  using executor_type = detail::stream_state::executor_type;

  /// construct a stream to be connected or accepted on the given connection
  explicit stream(connection& c);

  /// return the associated io executor
  executor_type get_executor() const;

  /// read some bytes into the given buffer sequence
  template <typename MutableBufferSequence,
            typename CompletionToken> // void(error_code, size_t)
  decltype(auto) async_read_some(const MutableBufferSequence& buffers,
                                 CompletionToken&& token) {
    return state.async_read_some(buffers, std::forward<CompletionToken>(token));
  }

  /// read some bytes into the given buffer sequence
  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers, error_code& ec) {
    return state.read_some(buffers, ec);
  }
  /// read some bytes into the given buffer sequence
  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers) {
    error_code ec;
    const size_t bytes = state.read_some(buffers, ec);
    if (ec) {
      throw system_error(ec);
    }
    return bytes;
  }

  /// write some bytes from the given buffer sequence. written bytes may be
  /// buffered until they fill an outgoing packet
  template <typename ConstBufferSequence,
            typename CompletionToken> // void(error_code, size_t)
  decltype(auto) async_write_some(const ConstBufferSequence& buffers,
                                  CompletionToken&& token) {
    return state.async_write_some(buffers, std::forward<CompletionToken>(token));
  }

  /// write some bytes from the given buffer sequence. written bytes may be
  /// buffered until they fill an outgoing packet
  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers, error_code& ec) {
    return state.write_some(buffers, ec);
  }
  /// write some bytes from the given buffer sequence. written bytes may be
  /// buffered until they fill an outgoing packet
  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers) {
    error_code ec;
    const size_t bytes = state.write_some(buffers, ec);
    if (ec) {
      throw system_error(ec);
    }
    return bytes;
  }

  /// flush any bytes that were buffered by write_some()/async_write_some() but
  /// not yet delivered
  void flush(error_code& ec);
  /// flush any bytes that were buffered by write_some()/async_write_some() but
  /// not yet delivered
  void flush();

  /// shut down a stream for reads (0), writes (1), or both (2). shutting down
  /// the read side will cancel any pending read operations. shutting down the
  /// write side will flush any buffered data, and cancel any pending write
  /// operations. once shut down for both sides, the stream will close itself
  void shutdown(int how, error_code& ec);
  /// shut down a stream for reads (0), writes (1), or both (2). shutting down
  /// the read side will cancel any pending read operations. shutting down the
  /// write side will flush any buffered data, and cancel any pending write
  /// operations. once shut down for both sides, the stream will close itself
  void shutdown(int how);

  /// close the stream, canceling any pending operations
  void close(error_code& ec);
  /// close the stream, canceling any pending operations
  void close();
};

} // namespace nexus::quic
