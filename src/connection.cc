#include <nexus/quic/connection.hpp>
#include <nexus/quic/client.hpp>
#include <nexus/quic/server.hpp>
#include <nexus/quic/stream.hpp>
#include <lsquic.h>

namespace nexus::quic {

connection::connection(acceptor& a) : impl(a.impl) {}
connection::connection(client& c) : impl(c.socket) {}

connection::connection(client& c, const udp::endpoint& endpoint,
                       const char* hostname)
    : impl(c.socket)
{
  c.connect(*this, endpoint, hostname);
}

connection::executor_type connection::get_executor() const
{
  return impl.get_executor();
}

bool connection::is_open() const
{
  return impl.is_open();
}

connection_id connection::id(error_code& ec) const
{
  return impl.id(ec);
}

connection_id connection::id() const
{
  error_code ec;
  auto i = impl.id(ec);
  if (ec) {
    throw system_error(ec);
  }
  return i;
}

udp::endpoint connection::remote_endpoint(error_code& ec) const
{
  return impl.remote_endpoint(ec);
}

udp::endpoint connection::remote_endpoint() const
{
  error_code ec;
  auto e = impl.remote_endpoint(ec);
  if (ec) {
    throw system_error(ec);
  }
  return e;
}

void connection::connect(stream& s, error_code& ec)
{
  auto op = detail::stream_connect_sync{s.impl};
  impl.connect(op);
  op.wait();
  ec = std::get<0>(*op.result);
}

void connection::connect(stream& s)
{
  error_code ec;
  connect(s, ec);
  if (ec) {
    throw system_error(ec);
  }
}

void connection::accept(stream& s, error_code& ec)
{
  auto op = detail::stream_accept_sync{s.impl};
  impl.accept(op);
  op.wait();
  ec = std::get<0>(*op.result);
}

void connection::accept(stream& s)
{
  error_code ec;
  accept(s, ec);
  if (ec) {
    throw system_error(ec);
  }
}

void connection::close(error_code& ec)
{
  impl.close(ec);
}

void connection::close()
{
  error_code ec;
  close(ec);
  if (ec) {
    throw system_error(ec);
  }
}

namespace detail {

connection_impl::connection_impl(socket_impl& socket)
    : svc(asio::use_service<service<connection_impl>>(
            asio::query(socket.get_executor(),
                        asio::execution::context))),
      socket(socket), state(connection_state::closed{})
{
  // register for service_shutdown() notifications
  svc.add(*this);
}

connection_impl::~connection_impl()
{
  error_code ec_ignored;
  close(ec_ignored);
  svc.remove(*this);
}

void connection_impl::service_shutdown()
{
  // destroy any pending operations
  connection_state::destroy(state);
}

connection_impl::executor_type connection_impl::get_executor() const
{
  return socket.get_executor();
}

bool connection_impl::is_open() const
{
  auto lock = std::unique_lock{socket.engine.mutex};
  return connection_state::is_open(state);
}

connection_id connection_impl::id(error_code& ec) const
{
  auto lock = std::unique_lock{socket.engine.mutex};
  return connection_state::id(state, ec);
}

udp::endpoint connection_impl::remote_endpoint(error_code& ec) const
{
  auto lock = std::unique_lock{socket.engine.mutex};
  return connection_state::remote_endpoint(state, ec);
}

void connection_impl::connect(stream_connect_operation& op)
{
  auto lock = std::unique_lock{socket.engine.mutex};
  if (connection_state::stream_connect(state, op)) {
    socket.engine.process(lock);
  }
}

stream_impl* connection_impl::on_connect(lsquic_stream_t* stream)
{
  return connection_state::on_stream_connect(state, stream, socket.engine.is_http);
}

void connection_impl::accept(stream_accept_operation& op)
{
  auto lock = std::unique_lock{socket.engine.mutex};
  connection_state::stream_accept(state, op, socket.engine.is_http);
}

stream_impl* connection_impl::on_accept(lsquic_stream* stream)
{
  return connection_state::on_stream_accept(state, stream, socket.engine.is_http);
}

void connection_impl::close(error_code& ec)
{
  auto lock = std::unique_lock{socket.engine.mutex};
  const auto t = connection_state::close(state, ec);
  switch (t) {
    case connection_state::transition::accepting_to_closed:
      list_erase(*this, socket.accepting_connections);
      break;
    case connection_state::transition::open_to_closed:
      list_erase(*this, socket.open_connections);
      socket.engine.process(lock);
      break;
    default:
      break;
  }
}

void connection_impl::on_close()
{
  const auto t = connection_state::on_close(state);
  if (t == connection_state::transition::open_to_error ||
      t == connection_state::transition::open_to_closed) {
    list_erase(*this, socket.open_connections);
  }
}

void connection_impl::on_handshake(int status)
{
  connection_state::on_handshake(state, status);
}

void connection_impl::on_conncloseframe(int app_error, uint64_t code)
{
  error_code ec;
  if (app_error == -1) {
    ec = make_error_code(connection_error::reset);
  } else if (app_error) {
    ec.assign(code, application_category());
  } else if ((code & 0xffff'ffff'ffff'ff00) == 0x0100) {
    // CRYPTO_ERROR 0x0100-0x01ff
    ec.assign(code & 0xff, tls_category());
  } else {
    ec.assign(code, transport_category());
  }

  const auto t = connection_state::on_connection_close_frame(state, ec);
  if (t == connection_state::transition::open_to_error ||
      t == connection_state::transition::open_to_closed) {
    list_erase(*this, socket.open_connections);
  }
}

void connection_impl::on_accepting_stream_closed(stream_impl& s)
{
  if (std::holds_alternative<connection_state::open>(state)) {
    auto& o = *std::get_if<connection_state::open>(&state);
    list_erase(s, o.accepting_streams);
  }
}

void connection_impl::on_connecting_stream_closed(stream_impl& s)
{
  if (std::holds_alternative<connection_state::open>(state)) {
    auto& o = *std::get_if<connection_state::open>(&state);
    list_erase(s, o.connecting_streams);
  }
}

void connection_impl::on_open_stream_closing(stream_impl& s)
{
  if (std::holds_alternative<connection_state::open>(state)) {
    auto& o = *std::get_if<connection_state::open>(&state);
    list_transfer(s, o.open_streams, o.closing_streams);
  }
}

void connection_impl::on_open_stream_closed(stream_impl& s)
{
  if (std::holds_alternative<connection_state::open>(state)) {
    auto& o = *std::get_if<connection_state::open>(&state);
    list_erase(s, o.open_streams);
  }
}

void connection_impl::on_closing_stream_closed(stream_impl& s)
{
  if (std::holds_alternative<connection_state::open>(state)) {
    auto& o = *std::get_if<connection_state::open>(&state);
    list_erase(s, o.closing_streams);
  }
}

} // namespace detail

} // namespace nexus::quic
