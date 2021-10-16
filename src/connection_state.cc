#include <nexus/quic/detail/connection_state.hpp>

namespace nexus::quic::detail {

namespace connection_state {

bool is_open(const variant& state)
{
  return std::holds_alternative<open>(state);
}

connection_id id(const variant& state, error_code& ec)
{
  connection_id cid;
  if (std::holds_alternative<open>(state)) {
    auto& o = *std::get_if<open>(&state);
    auto i = ::lsquic_conn_id(&o.handle);
    cid = connection_id{i->idbuf, i->len};
    ec = error_code{};
  } else if (std::holds_alternative<going_away>(state)) {
    auto& g = *std::get_if<going_away>(&state);
    auto i = ::lsquic_conn_id(&g.handle);
    cid = connection_id{i->idbuf, i->len};
    ec = error_code{};
  } else {
    ec = make_error_code(errc::not_connected);
  }
  return cid;
}

void remote_endpoint(lsquic_conn* handle, sockaddr* remote)
{
  const sockaddr* l = nullptr;
  const sockaddr* r = nullptr;
  lsquic_conn_get_sockaddr(handle, &l, &r);
  if (r->sa_family == AF_INET6) {
    ::memcpy(remote, r, sizeof(sockaddr_in6));
  } else {
    ::memcpy(remote, r, sizeof(sockaddr_in));
  }
}

udp::endpoint remote_endpoint(const variant& state, error_code& ec)
{
  auto remote = udp::endpoint{};
  if (std::holds_alternative<open>(state)) {
    auto& o = *std::get_if<open>(&state);
    remote_endpoint(&o.handle, remote.data());
    ec = error_code{};
  } else if (std::holds_alternative<going_away>(state)) {
    auto& g = *std::get_if<going_away>(&state);
    remote_endpoint(&g.handle, remote.data());
    ec = error_code{};
  } else {
    ec = make_error_code(errc::not_connected);
  }
  return remote;
}

void on_connect(variant& state, lsquic_conn* handle)
{
  assert(handle);
  assert(std::holds_alternative<closed>(state));
  state.emplace<open>(*handle);
}

void on_handshake(variant& state, int status)
{
  if (status != LSQ_HSK_FAIL && status != LSQ_HSK_RESUMED_FAIL) {
    return;
  }
  // set a generic connection handshake error. we may get a more specific
  // error from on_connection_close_frame() before on_closed() delivers
  // this error to the application
  const auto ec = make_error_code(connection_error::handshake_failed);
  if (std::holds_alternative<open>(state)) {
    auto& o = *std::get_if<open>(&state);
    if (!o.ec) {
      o.ec = ec;
    }
  } else if (std::holds_alternative<going_away>(state)) {
    auto& g = *std::get_if<going_away>(&state);
    if (!g.ec) {
      g.ec = ec;
    }
  }
}

void accept(variant& state, accept_operation& op)
{
  assert(std::holds_alternative<closed>(state));
  state = accepting{&op};
}

void accept_incoming(variant& state, lsquic_conn* handle)
{
  assert(handle);
  assert(std::holds_alternative<closed>(state));
  state.emplace<open>(*handle);
}

void on_accept(variant& state, lsquic_conn* handle)
{
  assert(handle);
  assert(std::holds_alternative<accepting>(state));
  std::get_if<accepting>(&state)->op->defer(error_code{}); // success
  state.emplace<open>(*handle);
}

bool stream_connect(variant& state, stream_connect_operation& op)
{
  if (std::holds_alternative<error>(state)) {
    op.post(std::get_if<error>(&state)->ec);
    state = closed{};
    return false;
  } else if (std::holds_alternative<going_away>(state)) {
    op.post(make_error_code(connection_error::going_away));
    return false;
  } else if (!std::holds_alternative<open>(state)) {
    op.post(make_error_code(errc::bad_file_descriptor));
    return false;
  }
  auto& o = *std::get_if<open>(&state);
  stream_state::connect(op.stream.state, op);
  o.connecting_streams.push_back(op.stream);
  ::lsquic_conn_make_stream(&o.handle);
  return true;
}

stream_impl* on_stream_connect(variant& state, lsquic_stream_t* handle,
                               bool is_http)
{
  assert(std::holds_alternative<open>(state));
  auto& o = *std::get_if<open>(&state);
  assert(!o.connecting_streams.empty());
  auto& s = o.connecting_streams.front();
  list_transfer(s, o.connecting_streams, o.open_streams);
  stream_state::on_connect(s.state, handle, is_http);
  return &s;
}

void stream_accept(variant& state, stream_accept_operation& op, bool is_http)
{
  if (std::holds_alternative<error>(state)) {
    op.post(std::get_if<error>(&state)->ec);
    state = closed{};
    return;
  } else if (std::holds_alternative<going_away>(state)) {
    op.post(make_error_code(connection_error::going_away));
    return;
  } else if (!std::holds_alternative<open>(state)) {
    op.post(make_error_code(errc::bad_file_descriptor));
    return;
  }
  auto& o = *std::get_if<open>(&state);
  if (!o.incoming_streams.empty()) {
    auto handle = o.incoming_streams.front();
    o.incoming_streams.pop_front();
    stream_state::on_accept(op.stream.state, handle, is_http);
    o.open_streams.push_back(op.stream);
    // when we accepted this, we had to return nullptr for the stream ctx
    // because we didn't have this stream_impl yet. update the ctx
    auto ctx = reinterpret_cast<lsquic_stream_ctx_t*>(&op.stream);
    ::lsquic_stream_set_ctx(handle, ctx);
    op.post(error_code{}); // success
    return;
  }
  stream_state::accept(op.stream.state, op);
  o.accepting_streams.push_back(op.stream);
}

stream_impl* on_stream_accept(variant& state, lsquic_stream* handle,
                              bool is_http)
{
  assert(std::holds_alternative<open>(state));
  auto& o = *std::get_if<open>(&state);
  if (o.accepting_streams.empty()) {
    // not waiting on accept, try to queue this for later
    if (o.incoming_streams.full()) {
      ::lsquic_stream_close(handle);
    } else {
      o.incoming_streams.push_back(handle);
    }
    return nullptr;
  }
  auto& s = o.accepting_streams.front();
  list_transfer(s, o.accepting_streams, o.open_streams);
  stream_state::on_accept(s.state, handle, is_http);
  return &s;
}

int abort_streams(stream_list& streams, error_code ec)
{
  int canceled = 0;
  while (!streams.empty()) {
    auto& s = streams.front();
    streams.pop_front();
    stream_state::on_error(s.state, ec);
    canceled++;
  }
  return canceled;
}

void close_handles(boost::circular_buffer<lsquic_stream*>& handles)
{
  while (!handles.empty()) {
    auto handle = handles.front();
    handles.pop_front();
    ::lsquic_stream_close(handle);
  }
}

int abort_streams(open& state, error_code ec)
{
  int canceled = 0;
  close_handles(state.incoming_streams);
  canceled += abort_streams(state.connecting_streams, ec);
  canceled += abort_streams(state.accepting_streams, ec);
  canceled += abort_streams(state.open_streams, ec);
  canceled += abort_streams(state.closing_streams, ec);
  return canceled;
}

int abort_streams(going_away& state, error_code ec)
{
  int canceled = 0;
  canceled += abort_streams(state.open_streams, ec);
  canceled += abort_streams(state.closing_streams, ec);
  return canceled;
}

transition go_away(variant& state, error_code& ec)
{
  if (std::holds_alternative<going_away>(state)) {
    ec = error_code{};
    return transition::none;
  }
  if (!std::holds_alternative<open>(state)) {
    ec = make_error_code(errc::not_connected);
    return transition::none;
  }
  auto& o = *std::get_if<open>(&state);
  ::lsquic_conn_going_away(&o.handle);

  const auto aborted = make_error_code(connection_error::going_away);
  close_handles(o.incoming_streams);
  abort_streams(o.connecting_streams, aborted);
  abort_streams(o.accepting_streams, aborted);

  auto& handle = o.handle;
  auto open = std::move(o.open_streams);
  auto closing = std::move(o.closing_streams);
  auto conn_ec = o.ec;

  auto& g = state.emplace<going_away>(handle);
  g.open_streams = std::move(open);
  g.closing_streams = std::move(closing);
  g.ec = conn_ec;

  ec = error_code{};
  return transition::open_to_going_away;
}

transition on_error(variant& state, open& o, error_code ec)
{
  const int canceled = abort_streams(o, ec);
  if (!canceled) {
    state = error{ec};
    return transition::open_to_error;
  }
  state = closed{};
  return transition::open_to_closed;
}

transition on_error(variant& state, going_away& g, error_code ec)
{
  const int canceled = abort_streams(g, ec);
  if (!canceled) {
    state = error{ec};
    return transition::going_away_to_error;
  }
  state = closed{};
  return transition::going_away_to_closed;
}

transition reset(variant& state, error_code ec)
{
  if (std::holds_alternative<accepting>(state)) {
    if (auto op = std::get_if<accepting>(&state)->op; op) {
      op->defer(ec);
    }
    state = closed{};
    return transition::accepting_to_closed;
  }
  if (std::holds_alternative<open>(state)) {
    auto& o = *std::get_if<open>(&state);
    ::lsquic_conn_close(&o.handle);
    return on_error(state, o, ec);
  }
  if (std::holds_alternative<going_away>(state)) {
    auto& g = *std::get_if<going_away>(&state);
    ::lsquic_conn_close(&g.handle);
    return on_error(state, g, ec);
  }
  if (std::holds_alternative<error>(state)) {
    ec = std::get_if<error>(&state)->ec;
    state = closed{};
    return transition::error_to_closed;
  }
  assert(std::holds_alternative<closed>(state));
  return transition::none;
}

transition close(variant& state, error_code& ec)
{
  const auto aborted = make_error_code(connection_error::aborted);
  if (std::holds_alternative<accepting>(state)) {
    if (auto op = std::get_if<accepting>(&state)->op; op) {
      op->defer(aborted);
    }
    state = closed{};
    return transition::accepting_to_closed;
  }
  if (std::holds_alternative<open>(state)) {
    auto& o = *std::get_if<open>(&state);
    abort_streams(o, aborted);
    ::lsquic_conn_close(&o.handle);
    state = closed{};
    return transition::open_to_closed;
  }
  if (std::holds_alternative<going_away>(state)) {
    auto& g = *std::get_if<going_away>(&state);
    abort_streams(g, aborted);
    ::lsquic_conn_close(&g.handle);
    state = closed{};
    return transition::going_away_to_closed;
  }
  if (std::holds_alternative<error>(state)) {
    ec = std::get_if<error>(&state)->ec;
    state = closed{};
    return transition::error_to_closed;
  }
  assert(std::holds_alternative<closed>(state));
  return transition::none;
}

static error_code connection_status(lsquic_conn* handle)
{
  // use lsquic_conn_status() to choose the most relevant error code
  const auto status = ::lsquic_conn_status(handle, nullptr, 0);
  switch (status) {
    case LSCONN_ST_VERNEG_FAILURE:
    case LSCONN_ST_HSK_FAILURE:
      return make_error_code(connection_error::handshake_failed);

    case LSCONN_ST_TIMED_OUT:
      return make_error_code(connection_error::timed_out);

    case LSCONN_ST_PEER_GOING_AWAY:
      return make_error_code(connection_error::going_away);

    case LSCONN_ST_USER_ABORTED:
    case LSCONN_ST_CLOSED:
      return make_error_code(connection_error::aborted);

    case LSCONN_ST_ERROR:
    case LSCONN_ST_RESET:
    default:
      return make_error_code(connection_error::reset);
  }
}

transition on_close(variant& state)
{
  if (std::holds_alternative<open>(state)) {
    auto& o = *std::get_if<open>(&state);
    return on_error(state, o, o.ec ? o.ec : connection_status(&o.handle));
  }
  if (std::holds_alternative<going_away>(state)) {
    auto& g = *std::get_if<going_away>(&state);
    return on_error(state, g, g.ec ? g.ec : connection_status(&g.handle));
  }
  return transition::none;
}

transition on_connection_close_frame(variant& state, error_code ec)
{
  if (std::holds_alternative<open>(state)) {
    return on_error(state, *std::get_if<open>(&state), ec);
  }
  if (std::holds_alternative<going_away>(state)) {
    return on_error(state, *std::get_if<going_away>(&state), ec);
  }
  return transition::none;
}

void destroy(variant& state)
{
  if (std::holds_alternative<accepting>(state)) {
    std::get_if<accepting>(&state)->op->destroy(error_code{});
  }
}

} // namespace connection_state

} // namespace nexus::quic::detail
