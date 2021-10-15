#pragma once

#include <variant>
#include <nexus/error_code.hpp>
#include <nexus/quic/stream_id.hpp>

struct lsquic_stream;

namespace nexus::quic::detail {

struct connection_impl;
struct stream_impl;

struct stream_header_read_operation;
struct stream_header_write_operation;
struct stream_data_operation;
struct stream_accept_operation;
struct stream_connect_operation;
struct stream_close_operation;

/// state machine for the sending side of a quic stream. h3 streams start at the
/// expecting_header state, and non-h3 streams start at expecting_body
namespace sending_stream_state {

using header_operation = stream_header_write_operation;
using data_operation = stream_data_operation;

struct expecting_header {};
struct header {
  header_operation* op = nullptr;
};
struct expecting_body {};
struct body {
  data_operation* op = nullptr;
};
struct shutdown {};

using variant = std::variant<expecting_header, header,
                             expecting_body, body,
                             shutdown>;

// sending stream events
void write_header(variant& state, lsquic_stream* handle, header_operation& op);
void write_body(variant& state, lsquic_stream* handle, data_operation& op);
void on_write_header(variant& state, lsquic_stream* handle);
void on_write_body(variant& state, lsquic_stream* handle);
void on_write(variant& state, lsquic_stream* handle);
int cancel(variant& state, error_code ec);
void destroy(variant& state);

} // namespace sending_stream_state

/// state machine for the receiving side of a quic stream. h3 streams start at
/// the expecting_header state, and non-h3 streams start at expecting_body
namespace receiving_stream_state {

using header_operation = stream_header_read_operation;
using data_operation = stream_data_operation;

struct expecting_header {};
struct header {
  header_operation* op = nullptr;
};
struct expecting_body {};
struct body {
  data_operation* op = nullptr;
};
struct shutdown {};

using variant = std::variant<expecting_header, header,
                             expecting_body, body,
                             shutdown>;

// receiving stream events
void read_header(variant& state, lsquic_stream* handle, header_operation* op);
void read_body(variant& state, lsquic_stream* handle, data_operation* op);
void on_read_header(variant& state, error_code ec);
void on_read_body(variant& state, error_code ec);
void on_read(variant& state, lsquic_stream* handle);
int cancel(variant& state, error_code ec);
void destroy(variant& state);

} // namespace receiving_stream_state

/// state machine for quic streams
namespace stream_state {

/// an incoming stream that has been received by the library, but has not been
/// requested by the application via accept()
struct incoming {
  lsquic_stream& handle;

  explicit incoming(lsquic_stream& handle) noexcept : handle(handle) {}
};

/// the application has requested to accept() a stream, but no incoming stream
/// has been received yet to satisfy the request
struct accepting {
  stream_accept_operation* op = nullptr;
};

/// the application has requested to connect() a new outgoing stream, but the
/// library has not yet opened one
struct connecting {
  stream_connect_operation* op = nullptr;
};

/// the stream is open
struct open {
  lsquic_stream& handle;

  receiving_stream_state::variant in;
  sending_stream_state::variant out;

  struct quic_tag {};
  open(lsquic_stream& handle, quic_tag) noexcept
      : handle(handle),
        in(receiving_stream_state::expecting_body{}),
        out(sending_stream_state::expecting_body{})
  {}

  struct h3_tag {};
  open(lsquic_stream& handle, h3_tag) noexcept
      : handle(handle),
        in(receiving_stream_state::expecting_header{}),
        out(sending_stream_state::expecting_header{})
  {}
};

/// the application has requested graceful shutdown with close(), and the
/// library is waiting for all sent bytes to be acknowledged
struct closing {
  stream_close_operation* op = nullptr;
};

/// closed with a connection error that has yet to be delivered to the stream
struct error {
  error_code ec;
};

/// the stream is closed
struct closed {
};

using variant = std::variant<incoming, accepting, connecting,
                             open, closing, error, closed>;

/// stream state transitions (only those relevent to close)
enum class transition {
  none,
  incoming_to_closed,
  accepting_to_closed,
  connecting_to_closed,
  open_to_closing,
  open_to_closed,
  open_to_error,
  closing_to_closed,
  error_to_closed,
};

// stream accessors
bool is_open(const variant& state);
stream_id id(const variant& state, error_code& ec);

// stream events
void connect(variant& state, stream_connect_operation& op);
void on_connect(variant& state, stream_impl& s, lsquic_stream* handle);

void accept(variant& state, stream_accept_operation& op);
void on_incoming(variant& state, lsquic_stream* handle);
void accept_incoming(variant& state, bool is_http);
void on_accept(variant& state, stream_impl& s, lsquic_stream* handle);

bool read(variant& state, stream_data_operation& op);
bool read_headers(variant& state, stream_header_read_operation& op);
void on_read(variant& state);

bool write(variant& state, stream_data_operation& op);
bool write_headers(variant& state, stream_header_write_operation& op);
void on_write(variant& state);

void flush(variant& state, error_code& ec);
void shutdown(variant& state, int how, error_code& ec);
int cancel(variant& state, error_code ec);

transition close(variant& state, stream_close_operation& op);
transition on_close(variant& state);
transition on_error(variant& state, error_code ec);
transition reset(variant& state);

void destroy(variant& state);

} // namespace stream_state

} // namespace nexus::quic::detail
