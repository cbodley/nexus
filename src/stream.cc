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

bool stream_impl::is_open() const
{
  if (conn) {
    auto lock = std::unique_lock{conn->socket.engine.mutex};
    return std::holds_alternative<stream_state::open>(state);
  } else {
    return std::holds_alternative<stream_state::open>(state);
  }
}

void stream_impl::read_headers(stream_header_read_operation& op)
{
  if (conn) {
    auto lock = std::unique_lock{conn->socket.engine.mutex};
    if (stream_state::read_headers(state, op)) {
      conn->socket.engine.process(lock);
    }
  } else {
    stream_state::read_headers(state, op);
  }
}

void stream_impl::read_some(stream_data_operation& op)
{
  if (conn) {
    auto lock = std::unique_lock{conn->socket.engine.mutex};
    if (stream_state::read(state, op)) {
      conn->socket.engine.process(lock);
    }
  } else {
    stream_state::read(state, op);
  }
}

void stream_impl::on_read()
{
  stream_state::on_read(state);
}

void stream_impl::write_some(stream_data_operation& op)
{
  if (conn) {
    auto lock = std::unique_lock{conn->socket.engine.mutex};
    if (stream_state::write(state, op)) {
      conn->socket.engine.process(lock);
    }
  } else {
    stream_state::write(state, op);
  }
}

void stream_impl::write_headers(stream_header_write_operation& op)
{
  if (conn) {
    auto lock = std::unique_lock{conn->socket.engine.mutex};
    if (stream_state::write_headers(state, op)) {
      conn->socket.engine.process(lock);
    }
  } else {
    stream_state::write_headers(state, op);
  }
}

void stream_impl::on_write()
{
  stream_state::on_write(state);
}

void stream_impl::flush(error_code& ec)
{
  if (conn) {
    auto lock = std::unique_lock{conn->socket.engine.mutex};
    stream_state::flush(state, ec);
    if (!ec) {
      conn->socket.engine.process(lock);
    }
  } else {
    stream_state::flush(state, ec);
  }
}

void stream_impl::shutdown(int how, error_code& ec)
{
  if (conn) {
    auto lock = std::unique_lock{conn->socket.engine.mutex};
    stream_state::shutdown(state, how, ec);
    if (!ec) {
      conn->socket.engine.process(lock);
    }
  } else {
    stream_state::shutdown(state, how, ec);
  }
}

void stream_impl::close(stream_close_operation& op)
{
  if (!conn) {
    stream_state::close(state, op);
    return;
  }
  auto lock = std::unique_lock{conn->socket.engine.mutex};
  const auto t = stream_state::close(state, op);
  if (t == stream_state::transition::open_to_closing) {
    list_transfer(*this, conn->open_streams, conn->closing_streams);
    conn->socket.engine.process(lock);
  }
}

void stream_impl::on_close()
{
  if (!conn) {
    error_code ec;
    stream_state::on_close(state, ec);
    return;
  }

  const auto t = stream_state::on_close(state, conn->err);
  switch (t) {
    case stream_state::transition::incoming_to_closed:
      list_erase(*this, conn->incoming_streams);
      break;
    case stream_state::transition::closing_to_closed:
      list_erase(*this, conn->closing_streams);
      break;
    case stream_state::transition::open_to_closed:
    case stream_state::transition::open_to_error:
      list_erase(*this, conn->open_streams);
      break;
  }
}

void stream_impl::reset()
{
  if (conn) {
    auto lock = std::unique_lock{conn->socket.engine.mutex};
    const auto t = stream_state::reset(state);
    switch (t) {
      case stream_state::transition::incoming_to_closed:
        list_erase(*this, conn->incoming_streams);
        break;
      case stream_state::transition::accepting_to_closed:
        list_erase(*this, conn->accepting_streams);
        break;
      case stream_state::transition::connecting_to_closed:
        list_erase(*this, conn->connecting_streams);
        break;
      case stream_state::transition::closing_to_closed:
        list_erase(*this, conn->closing_streams);
        break;
      case stream_state::transition::open_to_closed:
        list_erase(*this, conn->open_streams);
        break;

      default:
        return; // nothing changed, return without calling process()
    }
    conn->socket.engine.process(lock);
  } else {
    stream_state::reset(state);
  }
}

} // namespace detail

stream::~stream()
{
  if (impl) {
    impl->reset();
  }
}

stream::executor_type stream::get_executor() const
{
  return impl->get_executor();
}

bool stream::is_open() const
{
  return impl && impl->is_open();
}

void stream::flush(error_code& ec)
{
  impl->flush(ec);
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
  impl->shutdown(how, ec);
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
  impl->close(op);
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
  impl->reset();
}

} // namespace quic

namespace h3 {

void stream::read_headers(fields& f, error_code& ec)
{
  auto op = quic::detail::stream_header_read_sync{f};
  impl->read_headers(op);
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
  impl->write_headers(op);
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
