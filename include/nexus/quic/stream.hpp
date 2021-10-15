#pragma once

#include <nexus/error_code.hpp>
#include <nexus/quic/stream_id.hpp>
#include <nexus/quic/detail/stream_impl.hpp>

namespace nexus::quic {

namespace detail {

struct connection_impl;

template <typename Stream> struct stream_factory;

} // namespace detail

class connection;

/// a generic bidirectional QUIC stream that meets the type requirements of
/// asio's AsyncRead/WriteStream and SyncRead/WriteStream
class stream {
 protected:
  friend class connection;
  friend class detail::connection_impl;
  detail::stream_impl impl;
  explicit stream(detail::connection_impl& impl);
 public:
  /// construct a stream associated with the given connection
  explicit stream(connection& conn);

  /// reset the stream on destruction
  ~stream();

  stream(const stream&) = delete;
  stream& operator=(const stream&) = delete;
  stream(stream&&) = delete;
  stream& operator=(stream&&) = delete;

  /// the polymorphic executor type, asio::any_io_executor
  using executor_type = detail::stream_impl::executor_type;

  /// return the associated io executor
  executor_type get_executor() const;

  /// determine whether the stream is open
  bool is_open() const;

  /// return the stream identifier if open. for streams initiated locally,
  /// an identifier may not be assigned until the first STREAM frame is sent
  stream_id id(error_code& ec) const;
  /// \overload
  stream_id id() const;

  /// read some bytes into the given buffer sequence
  template <typename MutableBufferSequence,
            typename CompletionToken> // void(error_code, size_t)
  decltype(auto) async_read_some(const MutableBufferSequence& buffers,
                                 CompletionToken&& token) {
    return impl.async_read_some(buffers, std::forward<CompletionToken>(token));
  }

  /// read some bytes into the given buffer sequence
  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers, error_code& ec) {
    return impl.read_some(buffers, ec);
  }
  /// \overload
  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers) {
    error_code ec;
    const size_t bytes = impl.read_some(buffers, ec);
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
    return impl.async_write_some(buffers, std::forward<CompletionToken>(token));
  }

  /// write some bytes from the given buffer sequence. written bytes may be
  /// buffered until they fill an outgoing packet
  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers, error_code& ec) {
    return impl.write_some(buffers, ec);
  }
  /// \overload
  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers) {
    error_code ec;
    const size_t bytes = impl.write_some(buffers, ec);
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
  /// acknowledged by the peer. the associated connection must remain open until
  /// this graceful shutdown completes
  template <typename CompletionToken> // void(error_code)
  decltype(auto) async_close(CompletionToken&& token) {
    return impl.async_close(std::forward<CompletionToken>(token));
  }
  /// \overload
  void close(error_code& ec);
  /// \overload
  void close();

  /// reset the stream immediately in both directions, canceling any pending
  /// operations and discarding any unacked data
  void reset();
};

} // namespace nexus::quic
