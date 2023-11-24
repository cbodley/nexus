#pragma once

#include <variant>
#include <boost/circular_buffer.hpp>
#include <boost/intrusive/list.hpp>
#include <nexus/quic/connection_id.hpp>
#include <nexus/quic/detail/stream_impl.hpp>
#include <nexus/udp.hpp>

struct lsquic_conn;

namespace nexus::quic::detail {

struct accept_operation;
struct stream_accept_operation;
struct stream_connect_operation;

using stream_list = boost::intrusive::list<stream_impl>;

inline void list_erase(stream_impl& s, stream_list& from)
{
  from.erase(from.iterator_to(s));
}

inline void list_transfer(stream_impl& s, stream_list& from, stream_list& to)
{
  from.erase(from.iterator_to(s));
  to.push_back(s);
}

struct connection_context {
  bool incoming;
  explicit connection_context(bool incoming) noexcept : incoming(incoming) {}
};

struct incoming_connection : connection_context {
  lsquic_conn* handle;
  boost::circular_buffer<lsquic_stream*> incoming_streams; // TODO: allocator

  incoming_connection(lsquic_conn* handle, uint32_t max_streams)
      : connection_context(true),
        handle(handle),
        incoming_streams(max_streams) {}
};

/// state machine for quic connections
namespace connection_state {

/// the application has requested to accept() a connection, but no incoming
/// connection has been received yet to satisfy the request
struct accepting {
  accept_operation* op = nullptr;
};

/// the connection is open and ready to initiate and accept streams
struct open {
  lsquic_conn& handle;
  boost::circular_buffer<lsquic_stream*> incoming_streams;
  stream_list connecting_streams;
  stream_list accepting_streams;
  stream_list open_streams;
  stream_list closing_streams;
  // handshake errors are stored here until they can be delivered on close
  error_code ec;

 explicit open( incoming_connection&& incoming ) noexcept
  : handle( *incoming.handle ),
  incoming_streams(std::move(incoming.incoming_streams))  
  {
  }
};

/// the connection is processing open streams but not initiating or accepting
struct going_away {
  lsquic_conn& handle;
  stream_list open_streams;
  stream_list closing_streams;
  // handshake errors are stored here until they can be delivered on close
  error_code ec;

  explicit going_away(lsquic_conn& handle) noexcept : handle(handle) {}
};

/// the connection has closed with a connection error which hasn't yet been
/// delivered to the application
struct error {
  error_code ec;
};

/// the connection is closed
struct closed {
};

using variant = std::variant<accepting, open, going_away, error, closed>;

/// connection state transitions (only those relevent to close)
enum class transition {
  none,
  accepting_to_closed,
  open_to_going_away,
  open_to_closed,
  open_to_error,
  going_away_to_closed,
  going_away_to_error,
  error_to_closed,
};

// connection accessors
bool is_open(const variant& state);
connection_id id(const variant& state, error_code& ec);
udp::endpoint remote_endpoint(const variant& state, error_code& ec);

// connection events
void on_connect(variant& state, incoming_connection&& conn);
void on_handshake(variant& state, int status);
void accept(variant& state, accept_operation& op);
void accept_incoming(variant& state, incoming_connection&& incoming);
void on_accept(variant& state, incoming_connection&& handle);

bool stream_connect(variant& state, stream_connect_operation& op);
stream_impl* on_stream_connect(variant& state, lsquic_stream* handle,
                               bool is_http);

void stream_accept(variant& state, stream_accept_operation& op, bool is_http);
stream_impl* on_stream_accept(variant& state, lsquic_stream* handle,
                              bool is_http);

transition goaway(variant& state, error_code& ec);
transition on_remote_goaway(variant& state);
transition reset(variant& state, error_code ec);
transition close(variant& state, error_code& ec);
transition on_close(variant& state);
transition on_remote_close(variant& state, error_code ec);
void destroy(variant& state);

} // namespace connection_state

} // namespace nexus::quic::detail
