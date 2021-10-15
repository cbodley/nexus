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
  } else {
    ec = make_error_code(errc::not_connected);
  }
  return cid;
}

udp::endpoint remote_endpoint(const variant& state, error_code& ec)
{
  auto remote = udp::endpoint{};
  if (std::holds_alternative<open>(state)) {
    auto& o = *std::get_if<open>(&state);
    const sockaddr* l = nullptr;
    const sockaddr* r = nullptr;
    lsquic_conn_get_sockaddr(&o.handle, &l, &r);
    if (r->sa_family == AF_INET6) {
      ::memcpy(remote.data(), r, sizeof(sockaddr_in6));
    } else {
      ::memcpy(remote.data(), r, sizeof(sockaddr_in));
    }
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
  assert(std::holds_alternative<open>(state));
  auto& o = *std::get_if<open>(&state);
  switch (status) {
    case LSQ_HSK_FAIL:
    case LSQ_HSK_RESUMED_FAIL:
      if (!o.ec) {
        // set a generic connection handshake error. we may get a more specific
        // error from on_connection_close_frame() before on_closed() delivers
        // this error to the application
        o.ec = make_error_code(connection_error::handshake_failed);
      }
      break;
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

int abort_streams(open& state, error_code ec)
{
  int canceled = 0;
  // close incoming streams that we haven't accepted yet
  while (!state.incoming_streams.empty()) {
    auto handle = state.incoming_streams.front();
    state.incoming_streams.pop_front();
    ::lsquic_stream_close(handle);
  }
  // cancel pending stream connect/accept
  while (!state.connecting_streams.empty()) {
    auto& s = state.connecting_streams.front();
    state.connecting_streams.pop_front();
    [[maybe_unused]] auto t = stream_state::on_error(s.state, ec);
    assert(t == stream_state::transition::connecting_to_closed);
    canceled++;
  }
  while (!state.accepting_streams.empty()) {
    auto& s = state.accepting_streams.front();
    state.accepting_streams.pop_front();
    [[maybe_unused]] auto t = stream_state::on_error(s.state, ec);
    assert(t == stream_state::transition::accepting_to_closed);
    canceled++;
  }
  // close connected streams
  while (!state.open_streams.empty()) {
    auto& s = state.open_streams.front();
    state.open_streams.pop_front();
    [[maybe_unused]] auto t = stream_state::on_error(s.state, ec);
    assert(t == stream_state::transition::open_to_closed ||
           t == stream_state::transition::open_to_error);
    canceled++;
  }
  // cancel closing streams
  while (!state.closing_streams.empty()) {
    auto& s = state.closing_streams.front();
    state.closing_streams.pop_front();
    [[maybe_unused]] auto t = stream_state::on_error(s.state, ec);
    assert(t == stream_state::transition::closing_to_closed);
    canceled++;
  }
  return canceled;
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
    const int canceled = abort_streams(o, ec);
    ::lsquic_conn_close(&o.handle);
    if (!canceled) { // connection error was not delivered
      state = error{ec};
      return transition::open_to_error;
    }
    state = closed{};
    return transition::open_to_closed;
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
  if (!std::holds_alternative<open>(state)) {
    return transition::none;
  }
  auto& o = *std::get_if<open>(&state);
  const auto ec = o.ec ? o.ec : connection_status(&o.handle);
  const int canceled = abort_streams(o, ec);
  if (!canceled) { // connection error wasn't delivered
    state = error{ec};
    return transition::open_to_error;
  }
  state = closed{};
  return transition::open_to_closed;
}

transition on_connection_close_frame(variant& state, error_code ec)
{
  assert(std::holds_alternative<open>(state));
  auto& o = *std::get_if<open>(&state);
  const int canceled = abort_streams(o, ec);
  if (!canceled) { // connection error wasn't delivered
    state = error{ec};
    return transition::open_to_error;
  } else {
    state = closed{};
    return transition::open_to_closed;
  }
}

void destroy(variant& state)
{
  if (std::holds_alternative<accepting>(state)) {
    std::get_if<accepting>(&state)->op->destroy(error_code{});
  }
}

} // namespace connection_state

} // namespace nexus::quic::detail
