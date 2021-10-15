#include <nexus/quic/connection.hpp>
#include <nexus/h3/stream.hpp>
#include <nexus/h3/client.hpp>
#include <nexus/h3/server.hpp>
#include <nexus/quic/detail/engine_impl.hpp>

#include <lsquic.h>
#include <lsxpack_header.h>

namespace nexus {
namespace quic {
namespace detail {

stream_impl::stream_impl(connection_impl& conn)
    : engine(conn.socket.engine),
      svc(asio::use_service<service<stream_impl>>(
            asio::query(engine.get_executor(),
                        asio::execution::context))),
      conn(conn),
      state(stream_state::closed{})
{
  // register for service_shutdown() notifications
  svc.add(*this);
}

stream_impl::~stream_impl()
{
  svc.remove(*this);
}

void stream_impl::service_shutdown()
{
  // destroy any pending operations
  stream_state::destroy(state);
}

stream_impl::executor_type stream_impl::get_executor() const
{
  return engine.get_executor();
}

bool stream_impl::is_open() const
{
  auto lock = std::unique_lock{engine.mutex};
  return stream_state::is_open(state);
}

stream_id stream_impl::id(error_code& ec) const
{
  auto lock = std::unique_lock{engine.mutex};
  return stream_state::id(state, ec);
}

void stream_impl::read_headers(stream_header_read_operation& op)
{
  auto lock = std::unique_lock{engine.mutex};
  if (stream_state::read_headers(state, op)) {
    engine.process(lock);
  }
}

void stream_impl::read_some(stream_data_operation& op)
{
  auto lock = std::unique_lock{engine.mutex};
  if (stream_state::read(state, op)) {
    engine.process(lock);
  }
}

void stream_impl::on_read()
{
  stream_state::on_read(state);
}

void stream_impl::write_some(stream_data_operation& op)
{
  auto lock = std::unique_lock{engine.mutex};
  if (stream_state::write(state, op)) {
    engine.process(lock);
  }
}

void stream_impl::write_headers(stream_header_write_operation& op)
{
  auto lock = std::unique_lock{engine.mutex};
  if (stream_state::write_headers(state, op)) {
    engine.process(lock);
  }
}

void stream_impl::on_write()
{
  stream_state::on_write(state);
}

void stream_impl::flush(error_code& ec)
{
  auto lock = std::unique_lock{engine.mutex};
  stream_state::flush(state, ec);
  if (!ec) {
    engine.process(lock);
  }
}

void stream_impl::shutdown(int how, error_code& ec)
{
  auto lock = std::unique_lock{engine.mutex};
  stream_state::shutdown(state, how, ec);
  if (!ec) {
    engine.process(lock);
  }
}

void stream_impl::close(stream_close_operation& op)
{
  auto lock = std::unique_lock{engine.mutex};
  const auto t = stream_state::close(state, op);
  if (t == stream_state::transition::open_to_closing) {
    conn.on_open_stream_closing(*this);
    engine.process(lock);
  }
}

void stream_impl::on_close()
{
  const auto t = stream_state::on_close(state);
  switch (t) {
    case stream_state::transition::closing_to_closed:
      conn.on_closing_stream_closed(*this);
      break;
    case stream_state::transition::open_to_closed:
    case stream_state::transition::open_to_error:
      conn.on_open_stream_closed(*this);
      break;
    default:
      break;
  }
}

void stream_impl::reset()
{
  auto lock = std::unique_lock{engine.mutex};
  const auto t = stream_state::reset(state);
  switch (t) {
    case stream_state::transition::accepting_to_closed:
      conn.on_accepting_stream_closed(*this);
      break;
    case stream_state::transition::connecting_to_closed:
      conn.on_connecting_stream_closed(*this);
      break;
    case stream_state::transition::closing_to_closed:
      conn.on_closing_stream_closed(*this);
      break;
    case stream_state::transition::open_to_closed:
      conn.on_open_stream_closed(*this);
      break;
    default:
      return; // nothing changed, return without calling process()
  }
  engine.process(lock);
}

} // namespace detail

stream::stream(connection& conn) : stream(conn.impl) {}
stream::stream(detail::connection_impl& conn) : impl(conn) {}

stream::~stream()
{
  impl.reset();
}

stream::executor_type stream::get_executor() const
{
  return impl.get_executor();
}

bool stream::is_open() const
{
  return impl.is_open();
}

stream_id stream::id(error_code& ec) const
{
  return impl.id(ec);
}

stream_id stream::id() const
{
  error_code ec;
  auto sid = id(ec);
  if (ec) {
    throw system_error(ec);
  }
  return sid;
}

void stream::flush(error_code& ec)
{
  impl.flush(ec);
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
  impl.shutdown(how, ec);
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
  impl.close(op);
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
  impl.reset();
}

} // namespace quic

namespace h3 {

stream::stream(client_connection& conn) : quic::stream(conn.impl) {}
stream::stream(server_connection& conn) : quic::stream(conn.impl) {}

void stream::read_headers(fields& f, error_code& ec)
{
  auto op = quic::detail::stream_header_read_sync{f};
  impl.read_headers(op);
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
  impl.write_headers(op);
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
