#include <nexus/quic/detail/stream_state.hpp>
#include <nexus/quic/detail/connection_impl.hpp>
#include <nexus/quic/detail/socket_impl.hpp>
#include <nexus/quic/detail/engine_impl.hpp>
#include <lsquic.h>

#include "recv_header_set.hpp"

namespace nexus::quic::detail {

namespace sending_stream_state {

void write_header(variant& state, lsquic_stream* handle, header_operation& op)
{
  if (std::holds_alternative<shutdown>(state)) {
    op.post(make_error_code(errc::bad_file_descriptor));
    return;
  }
  if (!std::holds_alternative<expecting_header>(state)) {
    op.post(make_error_code(errc::invalid_argument));
    return;
  }
  if (::lsquic_stream_wantwrite(handle, 1) == -1) {
    op.post(error_code{errno, system_category()});
    return;
  }
  state = header{&op};
}

void write_body(variant& state, lsquic_stream* handle, data_operation& op)
{
  if (std::holds_alternative<shutdown>(state)) {
    op.post(make_error_code(errc::bad_file_descriptor), 0);
    return;
  }
  if (!std::holds_alternative<expecting_body>(state)) {
    op.post(make_error_code(errc::invalid_argument), 0);
    return;
  }
  if (::lsquic_stream_wantwrite(handle, 1) == -1) {
    op.post(error_code{errno, system_category()}, 0);
    return;
  }
  state = body{&op};
}

void on_write_header(variant& state, lsquic_stream* handle)
{
  auto& h = *std::get_if<header>(&state);
  error_code ec;
  auto& fields = h.op->fields;

  // stack-allocate a lsxpack_header array
  auto array = reinterpret_cast<lsxpack_header*>(
      ::alloca(fields.size() * sizeof(lsxpack_header)));
  int num_headers = 0;
  for (auto f = fields.begin(); f != fields.end(); ++f, ++num_headers) {
    auto& header = array[num_headers];
    const char* buf = f->data();
    const size_t name_offset = std::distance(buf, f->name().data());
    const size_t name_len = f->name().size();
    const size_t val_offset = std::distance(buf, f->value().data());
    const size_t val_len = f->value().size();
    lsxpack_header_set_offset2(&header, buf, name_offset, name_len,
                               val_offset, val_len);
    if (f->never_index()) {
      header.flags = LSXPACK_NEVER_INDEX;
    }
  }
  auto headers = lsquic_http_headers{num_headers, array};
  if (::lsquic_stream_send_headers(handle, &headers, 0) == -1) {
    ec.assign(errno, system_category());
  }

  h.op->defer(ec);
  state = expecting_body{};
}

void on_write_body(variant& state, lsquic_stream* handle)
{
  auto& b = *std::get_if<body>(&state);
  error_code ec;
  auto bytes = ::lsquic_stream_writev(handle, b.op->iovs, b.op->num_iovs);
  if (bytes == -1) {
    bytes = 0;
    ec.assign(errno, system_category());
  }
  b.op->defer(ec, bytes);
  state = expecting_body{};
}

void on_write(variant& state, lsquic_stream* handle)
{
  if (std::holds_alternative<shutdown>(state)) {
    return;
  } else if (std::holds_alternative<header>(state)) {
    on_write_header(state, handle);
  } else {
    assert(std::holds_alternative<body>(state)); // expecting states shouldn't wantwrite
    on_write_body(state, handle);
  }
}

int cancel(variant& state, error_code ec)
{
  if (std::holds_alternative<header>(state)) {
    if (auto op = std::get_if<header>(&state)->op; op) { // maybe destroy()ed
      op->defer(ec);
    }
    state = shutdown{};
    return 1;
  } else if (std::holds_alternative<body>(state)) {
    if (auto op = std::get_if<body>(&state)->op; op) { // maybe destroy()ed
      op->defer(ec, 0);
    }
    state = shutdown{};
    return 1;
  } else {
    return 0;
  }
}

void destroy(variant& state)
{
  if (std::holds_alternative<header>(state)) {
    auto& h = *std::get_if<header>(&state);
    h.op->destroy(error_code{});
    h.op = nullptr;
  } else if (std::holds_alternative<body>(state)) {
    auto& b = *std::get_if<body>(&state);
    b.op->destroy(error_code{}, 0);
    b.op = nullptr;
  }
}

} // namespace sending_stream_state

namespace receiving_stream_state {

void read_header(variant& state, lsquic_stream* handle, header_operation& op)
{
  if (!std::holds_alternative<expecting_header>(state)) {
    op.post(make_error_code(errc::invalid_argument));
    return;
  }
  if (::lsquic_stream_wantread(handle, 1) == -1) {
    op.post(error_code{errno, system_category()});
    return;
  }
  state = header{&op};
}

void read_body(variant& state, lsquic_stream* handle, data_operation& op)
{
  if (!std::holds_alternative<expecting_body>(state)) {
    op.post(make_error_code(errc::invalid_argument), 0);
    return;
  }
  if (::lsquic_stream_wantread(handle, 1) == -1) {
    op.post(error_code{errno, system_category()}, 0);
    return;
  }
  state = body{&op};
}

void on_read_header(variant& state, lsquic_stream* handle)
{
  auto& h = *std::get_if<header>(&state);
  error_code ec;
  auto hset = ::lsquic_stream_get_hset(handle);
  if (!hset) {
    ec = make_error_code(stream_error::eof);
  } else {
    auto headers = std::unique_ptr<recv_header_set>{
        reinterpret_cast<recv_header_set*>(hset)}; // take ownership
    h.op->fields = std::move(headers->fields);
  }
  h.op->defer(ec);
  state = expecting_body{};
}

void on_read_body(variant& state, lsquic_stream* handle)
{
  auto& b = *std::get_if<body>(&state);
  error_code ec;
  auto bytes = ::lsquic_stream_readv(handle, b.op->iovs, b.op->num_iovs);
  if (bytes == -1) {
    bytes = 0;
    ec.assign(errno, system_category());
  }
  b.op->defer(ec, bytes);
  state = expecting_body{};
}

void on_read(variant& state, lsquic_stream* handle)
{
  if (std::holds_alternative<shutdown>(state)) {
    return;
  } else if (std::holds_alternative<header>(state)) {
    on_read_header(state, handle);
  } else {
    assert(std::holds_alternative<body>(state)); // expecting states shouldn't wantread
    on_read_body(state, handle);
  }
}

int cancel(variant& state, error_code ec)
{
  if (std::holds_alternative<header>(state)) {
    if (auto op = std::get_if<header>(&state)->op; op) { // maybe destroy()ed
      op->defer(ec);
    }
    state = shutdown{};
    return 1;
  } else if (std::holds_alternative<body>(state)) {
    if (auto op = std::get_if<body>(&state)->op; op) { // maybe destroy()ed
      op->defer(ec, 0);
    }
    state = shutdown{};
    return 1;
  } else {
    return 0;
  }
}

void destroy(variant& state)
{
  if (std::holds_alternative<header>(state)) {
    auto& h = *std::get_if<header>(&state);
    h.op->destroy(error_code{});
    h.op = nullptr;
  } else if (std::holds_alternative<body>(state)) {
    auto& b = *std::get_if<body>(&state);
    b.op->destroy(error_code{}, 0);
    b.op = nullptr;
  }
}

} // namespace receiving_stream_state

namespace stream_state {

bool is_open(const variant& state)
{
  return std::holds_alternative<open>(state);
}

stream_id id(const variant& state, error_code& ec)
{
  stream_id sid = 0;
  if (std::holds_alternative<open>(state)) {
    auto& o = *std::get_if<open>(&state);
    sid = ::lsquic_stream_id(&o.handle);
    ec = error_code{};
  } else {
    ec = make_error_code(errc::not_connected);
  }
  return sid;
}

void connect(variant& state, stream_connect_operation& op)
{
  assert(std::holds_alternative<closed>(state));
  state = connecting{&op};
}

void on_connect(variant& state, stream_impl& s, lsquic_stream* handle)
{
  assert(std::holds_alternative<connecting>(state));
  std::get_if<connecting>(&state)->op->defer(error_code{}, &s);
  assert(s.conn);
  if (s.conn->socket.engine.is_http) {
    state.emplace<open>(*handle, open::h3_tag{});
  } else {
    state.emplace<open>(*handle, open::quic_tag{});
  }
}

void accept(variant& state, stream_accept_operation& op)
{
  assert(std::holds_alternative<closed>(state));
  state = accepting{&op};
}

void on_incoming(variant& state, lsquic_stream* handle)
{
  assert(std::holds_alternative<closed>(state));
  assert(handle);
  state.emplace<incoming>(*handle);
}

void accept_incoming(variant& state, bool is_http)
{
  assert(std::holds_alternative<incoming>(state));
  auto handle = &std::get_if<incoming>(&state)->handle;
  if (is_http) {
    state.emplace<open>(*handle, open::h3_tag{});
  } else {
    state.emplace<open>(*handle, open::quic_tag{});
  }
}

void on_accept(variant& state, stream_impl& s, lsquic_stream* handle)
{
  assert(std::holds_alternative<accepting>(state));
  std::get_if<accepting>(&state)->op->defer(error_code{}, &s);
  assert(s.conn);
  if (s.conn->socket.engine.is_http) {
    state.emplace<open>(*handle, open::h3_tag{});
  } else {
    state.emplace<open>(*handle, open::quic_tag{});
  }
}

bool read(variant& state, stream_data_operation& op)
{
  if (std::holds_alternative<error>(state)) {
    op.post(std::get_if<error>(&state)->ec, 0);
    state = closed{};
    return false;
  } else if (std::holds_alternative<open>(state)) {
    auto& o = *std::get_if<open>(&state);
    receiving_stream_state::read_body(o.in, &o.handle, op);
    return true;
  } else {
    op.post(make_error_code(errc::bad_file_descriptor), 0);
    return false;
  }
}

bool read_headers(variant& state, stream_header_read_operation& op)
{
  if (std::holds_alternative<error>(state)) {
    op.post(std::get_if<error>(&state)->ec);
    state = closed{};
    return false;
  } else if (std::holds_alternative<open>(state)) {
    auto& o = *std::get_if<open>(&state);
    receiving_stream_state::read_header(o.in, &o.handle, op);
    return true;
  } else {
    op.post(make_error_code(errc::bad_file_descriptor));
    return false;
  }
}

void on_read(variant& state)
{
  assert(std::holds_alternative<open>(state));
  auto& o = *std::get_if<open>(&state);
  receiving_stream_state::on_read(o.in, &o.handle);
  ::lsquic_stream_wantread(&o.handle, 0);
}

bool write(variant& state, stream_data_operation& op)
{
  if (std::holds_alternative<error>(state)) {
    op.post(std::get_if<error>(&state)->ec, 0);
    state = closed{};
    return false;
  } else if (std::holds_alternative<open>(state)) {
    auto& o = *std::get_if<open>(&state);
    sending_stream_state::write_body(o.out, &o.handle, op);
    return true;
  } else {
    op.post(make_error_code(errc::bad_file_descriptor), 0);
    return false;
  }
}

bool write_headers(variant& state, stream_header_write_operation& op)
{
  if (std::holds_alternative<error>(state)) {
    op.post(std::get_if<error>(&state)->ec);
    state = closed{};
    return false;
  } else if (std::holds_alternative<open>(state)) {
    auto& o = *std::get_if<open>(&state);
    sending_stream_state::write_header(o.out, &o.handle, op);
    return true;
  } else {
    op.post(make_error_code(errc::bad_file_descriptor));
    return false;
  }
}

void on_write(variant& state)
{
  assert(std::holds_alternative<open>(state));
  auto& o = *std::get_if<open>(&state);
  sending_stream_state::on_write(o.out, &o.handle);
  ::lsquic_stream_wantwrite(&o.handle, 0);
}

void flush(variant& state, error_code& ec)
{
  if (std::holds_alternative<error>(state)) {
    ec = std::get_if<error>(&state)->ec;
    state = closed{};
    return;
  } else if (!std::holds_alternative<open>(state)) {
    ec = make_error_code(errc::not_connected);
    return;
  }
  auto& o = *std::get_if<open>(&state);
  if (::lsquic_stream_flush(&o.handle) == -1) {
    ec.assign(errno, system_category());
    return;
  }
}

void shutdown(variant& state, int how, error_code& ec)
{
  if (std::holds_alternative<error>(state)) {
    ec = std::get_if<error>(&state)->ec;
    state = closed{};
    return;
  } else if (!std::holds_alternative<open>(state)) {
    ec = make_error_code(errc::bad_file_descriptor);
    return;
  }

  auto& o = *std::get_if<open>(&state);
  if (::lsquic_stream_shutdown(&o.handle, how) == -1) {
    ec.assign(errno, system_category());
    return;
  }
  auto ecanceled = make_error_code(stream_error::aborted);
  const bool shutdown_read = (how == 0 || how == 2);
  const bool shutdown_write = (how == 1 || how == 2);
  if (shutdown_read) {
    receiving_stream_state::cancel(o.in, ecanceled);
  }
  if (shutdown_write) {
    sending_stream_state::cancel(o.out, ecanceled);
  }
  ec = error_code{};
}

int cancel(variant& state, error_code ec)
{
  if (std::holds_alternative<open>(state)) {
    auto& o = *std::get_if<open>(&state);
    return receiving_stream_state::cancel(o.in, ec)
         + sending_stream_state::cancel(o.out, ec);
  } else {
    return 0;
  }
}

transition close(variant& state, stream_close_operation& op)
{
  if (std::holds_alternative<closing>(state)) {
    op.defer(make_error_code(errc::invalid_argument));
    return transition::none;
  }
  if (std::holds_alternative<error>(state)) {
    op.post(std::get_if<error>(&state)->ec);
    state = closed{};
    return transition::error_to_closed;
  }
  if (!std::holds_alternative<open>(state)) {
    assert(!std::holds_alternative<incoming>(state)); // not visible yet
    assert(!std::holds_alternative<accepting>(state)); // not visible yet
    assert(!std::holds_alternative<connecting>(state)); // not visible yet
    op.post(make_error_code(errc::not_connected));
    return transition::none;
  }
  auto& o = *std::get_if<open>(&state);
  ::lsquic_stream_close(&o.handle);

  auto ec = make_error_code(stream_error::aborted);
  receiving_stream_state::cancel(o.in, ec);
  sending_stream_state::cancel(o.out, ec);

  state = closing{&op};
  return transition::open_to_closing;
}

transition on_close(variant& state)
{
  if (std::holds_alternative<incoming>(state)) {
    state = closed{};
    return transition::incoming_to_closed;
  }
  if (std::holds_alternative<closing>(state)) {
    std::get_if<closing>(&state)->op->defer(error_code{});
    state = closed{};
    return transition::closing_to_closed;
  }
  if (!std::holds_alternative<open>(state)) {
    assert(!std::holds_alternative<accepting>(state)); // no lsquic_stream yet
    assert(!std::holds_alternative<connecting>(state)); // no lsquic_stream yet
    return transition::none;
  }
  auto& o = *std::get_if<open>(&state);
  const auto ec = make_error_code(stream_error::reset);
  receiving_stream_state::cancel(o.in, ec);
  sending_stream_state::cancel(o.out, ec);
  state = closed{};
  return transition::open_to_closed;
}

transition on_error(variant& state, error_code ec)
{
  if (std::holds_alternative<incoming>(state)) {
    state = closed{};
    return transition::incoming_to_closed;
  }
  if (std::holds_alternative<accepting>(state)) {
    if (auto op = std::get_if<accepting>(&state)->op; op) { // maybe destroy()ed
      op->defer(ec, nullptr);
    }
    state = closed{};
    return transition::accepting_to_closed;
  }
  if (std::holds_alternative<connecting>(state)) {
    if (auto op = std::get_if<connecting>(&state)->op; op) { // maybe destroy()ed
      op->defer(ec, nullptr);
    }
    state = closed{};
    return transition::connecting_to_closed;
  }
  if (std::holds_alternative<closing>(state)) {
    if (auto op = std::get_if<closing>(&state)->op; op) { // maybe destroy()ed
      op->defer(ec);
    }
    state = closed{};
    return transition::closing_to_closed;
  }
  if (!std::holds_alternative<open>(state)) {
    return transition::none;
  }
  auto& o = *std::get_if<open>(&state);
  int canceled = 0;
  canceled += receiving_stream_state::cancel(o.in, ec);
  canceled += sending_stream_state::cancel(o.out, ec);
  if (canceled) {
    state = closed{};
    return transition::open_to_closed;
  } else {
    state = error{ec};
    return transition::open_to_error;
  }
}

transition reset(variant& state)
{
  const auto ec = make_error_code(stream_error::aborted);
  if (std::holds_alternative<incoming>(state)) {
    auto& i = *std::get_if<incoming>(&state);
    ::lsquic_stream_close(&i.handle);
    state = closed{};
    return transition::incoming_to_closed;
  }
  if (std::holds_alternative<accepting>(state)) {
    if (auto op = std::get_if<accepting>(&state)->op; op) { // maybe destroy()ed
      op->defer(ec, nullptr);
    }
    state = closed{};
    return transition::accepting_to_closed;
  }
  if (std::holds_alternative<connecting>(state)) {
    if (auto op = std::get_if<connecting>(&state)->op; op) { // maybe destroy()ed
      op->defer(ec, nullptr);
    }
    state = closed{};
    return transition::connecting_to_closed;
  }
  if (std::holds_alternative<closing>(state)) {
    if (auto op = std::get_if<closing>(&state)->op; op) { // maybe destroy()ed
      op->defer(ec);
    }
    state = closed{};
    return transition::closing_to_closed;
  }
  if (std::holds_alternative<error>(state)) {
    state = closed{}; // discard connection error
    return transition::error_to_closed;
  }
  if (!std::holds_alternative<open>(state)) {
    return transition::none;
  }
  auto& o = *std::get_if<open>(&state);
  ::lsquic_stream_close(&o.handle);

  receiving_stream_state::cancel(o.in, ec);
  sending_stream_state::cancel(o.out, ec);

  state = closed{};
  return transition::open_to_closed;
}

void destroy(variant& state)
{
  if (std::holds_alternative<accepting>(state)) {
    auto& a = *std::get_if<accepting>(&state);
    a.op->destroy(error_code{}, nullptr);
    a.op = nullptr;
  } else if (std::holds_alternative<connecting>(state)) {
    auto& c = *std::get_if<connecting>(&state);
    c.op->destroy(error_code{}, nullptr);
    c.op = nullptr;
  } else if (std::holds_alternative<open>(state)) {
    auto& o = *std::get_if<open>(&state);
    destroy(o.in);
    destroy(o.out);
  } else if (std::holds_alternative<closing>(state)) {
    auto& c = *std::get_if<closing>(&state);
    c.op->destroy(error_code{});
    c.op = nullptr;
  }
}

} // namespace stream_state

} // namespace nexus::quic::detail
