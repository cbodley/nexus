#pragma once

#include <nexus/quic/stream.hpp>
#include <nexus/h3/fields.hpp>

namespace nexus::h3 {

class client_connection;
class server_connection;

/// a bidirectional HTTP/3 stream that can send and receive HTTP headers, and
/// meets the type requirements of asio's AsyncRead/WriteStream and
/// SyncRead/WriteStream for transferring the HTTP message body
class stream : public quic::stream {
  friend class client_connection;
  friend class server_connection;
  using quic::stream::stream;
 public:
  /// construct a stream associated with the given client connection
  explicit stream(client_connection& conn);

  /// construct a stream associated with the given server connection
  explicit stream(server_connection& conn);

  /// read headers from the stream
  template <typename CompletionToken> // void(error_code)
  decltype(auto) async_read_headers(fields& f, CompletionToken&& token) {
    return impl.async_read_headers(f, std::forward<CompletionToken>(token));
  }

  /// read headers from the stream
  void read_headers(fields& f, error_code& ec);
  /// \overload
  void read_headers(fields& f);

  /// write headers to the stream
  template <typename CompletionToken> // void(error_code)
  decltype(auto) async_write_headers(const fields& f, CompletionToken&& token) {
    return impl.async_write_headers(f, std::forward<CompletionToken>(token));
  }

  /// write headers to the stream
  void write_headers(const fields& f, error_code& ec);
  /// \overload
  void write_headers(const fields& f);
};

} // namespace nexus::h3
