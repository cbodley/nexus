#pragma once

#include <variant>
#include <boost/intrusive/list.hpp>
#include <nexus/quic/detail/operation.hpp>
#include <nexus/quic/detail/stream_impl.hpp>
#include <nexus/udp.hpp>
#include <lsquic.h>

struct lsquic_conn;

namespace nexus::quic::detail {

struct connection_impl;

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

namespace connection_state {

struct accepting {
  accept_operation* op = nullptr;
};

struct open {
  lsquic_conn& handle;
  // maintain ownership of incoming/connecting/accepting streams
  stream_list incoming_streams;
  stream_list connecting_streams;
  stream_list accepting_streams;
  // open/closing streams are owned by a quic::stream or h3::stream
  stream_list open_streams;
  stream_list closing_streams;
  // handshake and connection errors are stored here until they can be delivered
  // when the connection closes
  error_code ec;

  explicit open(lsquic_conn& handle) noexcept : handle(handle) {}
};

// TODO: going_away with just handle/open_streams/closing_streams

struct error {
  error_code ec;
};

struct closed {
};

using variant = std::variant<accepting, open, error, closed>;

enum class transition {
  none,
  accepting_to_closed,
  open_to_closed,
  open_to_error,
  error_to_closed,
};

bool is_open(const variant& state);
udp::endpoint remote_endpoint(const variant& state);

void on_connect(variant& state, lsquic_conn* handle);
void on_handshake(variant& state, int status);
void accept(variant& state, accept_operation& op);
void accept_incoming(variant& state, lsquic_conn* handle);
void on_accept(variant& state, lsquic_conn* handle);

bool stream_connect(variant& state, stream_connect_operation& op,
                    const stream_impl::executor_type& ex, connection_impl* c);
stream_impl* on_stream_connect(variant& state, lsquic_stream_t* handle);

void stream_accept(variant& state, stream_accept_operation& op, bool is_http,
                   const stream_impl::executor_type& ex, connection_impl* c);
stream_impl* on_stream_accept(variant& state, lsquic_stream* handle,
                              const stream_impl::executor_type& ex,
                              connection_impl* c);

transition reset(variant& state, error_code ec);
transition close(variant& state, error_code& ec);
transition on_close(variant& state);
transition on_connection_close_frame(variant& state, error_code ec);
void destroy(variant& state);

} // namespace connection_state

} // namespace nexus::quic::detail
