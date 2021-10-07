#pragma once

#include <memory>
#include <nexus/error_code.hpp>
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
  std::unique_ptr<detail::stream_state> state;
 public:
  /// the polymorphic executor type, asio::any_io_executor
  using executor_type = detail::stream_state::executor_type;

  /// default-construct an empty stream
  stream() = default;

  /// reset the stream on destruction
  ~stream();

  stream(stream&&) = default;
  stream& operator=(stream&&) = default;

  /// return the associated io executor
  executor_type get_executor() const;

  /// read some bytes into the given buffer sequence
  template <typename MutableBufferSequence,
            typename CompletionToken> // void(error_code, size_t)
  decltype(auto) async_read_some(const MutableBufferSequence& buffers,
                                 CompletionToken&& token) {
    return state->async_read_some(buffers, std::forward<CompletionToken>(token));
  }

  /// read some bytes into the given buffer sequence
  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers, error_code& ec) {
    return state->read_some(buffers, ec);
  }
  /// \overload
  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers) {
    error_code ec;
    const size_t bytes = state->read_some(buffers, ec);
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
    return state->async_write_some(buffers, std::forward<CompletionToken>(token));
  }

  /// write some bytes from the given buffer sequence. written bytes may be
  /// buffered until they fill an outgoing packet
  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers, error_code& ec) {
    return state->write_some(buffers, ec);
  }
  /// \overload
  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers) {
    error_code ec;
    const size_t bytes = state->write_some(buffers, ec);
    if (ec) {
      throw system_error(ec);
    }
    return bytes;
  }

  /// flush any bytes that were buffered by write_some()/async_write_some() but
  /// not yet delivered
  void flush(error_code& ec);
  /// \overload
  void flush();

  /// shut down a stream for reads (0), writes (1), or both (2). shutting down
  /// the read side will cancel any pending read operations. shutting down the
  /// write side will flush any buffered data, and cancel any pending write
  /// operations
  void shutdown(int how, error_code& ec);
  /// \overload
  void shutdown(int how);

  /// close the stream gracefully, blocking until all written data is
  /// acknowledged by the peer
  template <typename CompletionToken> // void(error_code)
  decltype(auto) async_close(CompletionToken&& token) {
    return state->async_close(std::forward<CompletionToken>(token));
  }
  /// \overload
  void close(error_code& ec);
  /// \overload
  void close();

  /// reset the stream immediately in both directions, canceling any pending
  /// operations and discarding any unsent data
  void reset();
};

} // namespace nexus::quic
