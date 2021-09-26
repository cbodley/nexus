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

stream_state::executor_type stream_state::get_executor() const
{
  return conn.get_executor();
}

void stream_state::read_headers(stream_header_read_operation& op)
{
  conn.socket.engine.stream_read_headers(*this, op);
}

void stream_state::read_some(stream_data_operation& op)
{
  conn.socket.engine.stream_read(*this, op);
}

void stream_state::write_some(stream_data_operation& op)
{
  conn.socket.engine.stream_write(*this, op);
}

void stream_state::write_headers(stream_header_write_operation& op)
{
  conn.socket.engine.stream_write_headers(*this, op);
}

void stream_state::flush(error_code& ec)
{
  conn.socket.engine.stream_flush(*this, ec);
}

void stream_state::shutdown(int how, error_code& ec)
{
  conn.socket.engine.stream_shutdown(*this, how, ec);
}

void stream_state::close(error_code& ec)
{
  conn.socket.engine.stream_close(*this, ec);
}

} // namespace detail

stream::stream(connection& c) : stream(c.state) {}

stream::executor_type stream::get_executor() const
{
  return state.get_executor();
}

void stream::flush(error_code& ec)
{
  state.flush(ec);
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
  state.shutdown(how, ec);
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
  state.close(ec);
}

void stream::close()
{
  error_code ec;
  state.close(ec);
  if (ec) {
    throw system_error(ec);
  }
}

} // namespace quic

namespace h3 {

stream::stream(client_connection& c) : quic::stream(c.state) {}
stream::stream(server_connection& c) : quic::stream(c.state) {}

void stream::read_headers(fields& f, error_code& ec)
{
  auto op = quic::detail::stream_header_read_sync{f};
  state.read_headers(op);
  ec = *op.ec;
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
  state.write_headers(op);
  ec = *op.ec;
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
