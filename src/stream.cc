#include <nexus/quic/connection.hpp>
#include <nexus/h3/stream.hpp>
#include <nexus/h3/client.hpp>
#include <nexus/h3/server.hpp>
#include <nexus/quic/detail/engine.hpp>

#include <lsquic.h>
#include <lsxpack_header.h>

namespace nexus {
namespace quic {
namespace detail {

bool stream_state::is_open() const
{
  return conn && conn->socket.engine.is_open(*this);
}

void stream_state::read_headers(stream_header_read_operation& op)
{
  if (conn) {
    conn->socket.engine.stream_read_headers(*this, op);
  } else if (conn_err) {
    op.post(std::exchange(conn_err, {}));
  } else {
    op.post(make_error_code(errc::bad_file_descriptor));
  }
}

void stream_state::read_some(stream_data_operation& op)
{
  if (conn) {
    conn->socket.engine.stream_read(*this, op);
  } else if (conn_err) {
    op.post(std::exchange(conn_err, {}), 0);
  } else {
    op.post(make_error_code(errc::bad_file_descriptor), 0);
  }
}

void stream_state::write_some(stream_data_operation& op)
{
  if (conn) {
    conn->socket.engine.stream_write(*this, op);
  } else if (conn_err) {
    op.post(std::exchange(conn_err, {}), 0);
  } else {
    op.post(make_error_code(errc::bad_file_descriptor), 0);
  }
}

void stream_state::write_headers(stream_header_write_operation& op)
{
  if (conn) {
    conn->socket.engine.stream_write_headers(*this, op);
  } else if (conn_err) {
    op.post(std::exchange(conn_err, {}));
  } else {
    op.post(make_error_code(errc::bad_file_descriptor));
  }
}

void stream_state::flush(error_code& ec)
{
  if (conn) {
    conn->socket.engine.stream_flush(*this, ec);
  } else if (conn_err) {
    ec = std::exchange(conn_err, {});
  } else {
    ec = make_error_code(errc::bad_file_descriptor);
  }
}

void stream_state::shutdown(int how, error_code& ec)
{
  if (conn) {
    conn->socket.engine.stream_shutdown(*this, how, ec);
  } else if (conn_err) {
    ec = std::exchange(conn_err, {});
  } else {
    ec = make_error_code(errc::bad_file_descriptor);
  }
}

void stream_state::close(stream_close_operation& op)
{
  if (conn) {
    conn->socket.engine.stream_close(*this, op);
  } else if (conn_err) {
    op.post(std::exchange(conn_err, {}));
  } else {
    op.post(error_code{}); // already closed
  }
}

void stream_state::reset()
{
  if (conn) {
    conn->socket.engine.stream_reset(*this);
  } else if (close_) {
    auto op = std::exchange(close_, nullptr);
    op->dispatch(make_error_code(stream_error::aborted));
  }
}

} // namespace detail

stream::~stream()
{
  if (state) {
    state->reset();
  }
}

stream::executor_type stream::get_executor() const
{
  return state->get_executor();
}

bool stream::is_open() const
{
  return state && state->is_open();
}

void stream::flush(error_code& ec)
{
  state->flush(ec);
}

void stream::flush()
{
  error_code ec;
  flush(ec);
  if (ec) {
    throw system_error(ec);
  }
}

void stream::shutdown(int how, error_code& ec)
{
  state->shutdown(how, ec);
}

void stream::shutdown(int how)
{
  error_code ec;
  shutdown(how, ec);
  if (ec) {
    throw system_error(ec);
  }
}

void stream::close(error_code& ec)
{
  detail::stream_close_sync op;
  state->close(op);
  op.wait();
  ec = std::get<0>(*op.result);
}

void stream::close()
{
  error_code ec;
  close(ec);
  if (ec) {
    throw system_error(ec);
  }
}

void stream::reset()
{
  state->reset();
}

} // namespace quic

namespace h3 {

void stream::read_headers(fields& f, error_code& ec)
{
  auto op = quic::detail::stream_header_read_sync{f};
  state->read_headers(op);
  op.wait();
  ec = std::get<0>(*op.result);
}
void stream::read_headers(fields& f)
{
  error_code ec;
  read_headers(f, ec);
  if (ec) {
    throw system_error(ec);
  }
}

void stream::write_headers(const fields& f, error_code& ec)
{
  auto op = quic::detail::stream_header_write_sync{f};
  state->write_headers(op);
  op.wait();
  ec = std::get<0>(*op.result);
}
void stream::write_headers(const fields& f)
{
  error_code ec;
  write_headers(f, ec);
  if (ec) {
    throw system_error(ec);
  }
}

} // namespace h3
} // namespace nexus
