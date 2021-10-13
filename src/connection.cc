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

udp::endpoint connection::remote_endpoint()
{
  return impl.remote_endpoint();
}

bool connection::is_open() const
{
  return impl.is_open();
}

stream connection::connect(error_code& ec)
{
  detail::stream_connect_sync op;
  impl.connect(op);
  op.wait();
  ec = std::get<0>(*op.result);
  return detail::stream_factory<stream>::create(
      std::get<1>(std::move(*op.result)));
}

stream connection::connect()
{
  error_code ec;
  auto s = connect(ec);
  if (ec) {
    throw system_error(ec);
  }
  return s;
}

stream connection::accept(error_code& ec)
{
  detail::stream_accept_sync op;
  impl.accept(op);
  op.wait();
  ec = std::get<0>(*op.result);
  return detail::stream_factory<stream>::create(
      std::get<1>(std::move(*op.result)));
}

stream connection::accept()
{
  error_code ec;
  auto s = accept(ec);
  if (ec) {
    throw system_error(ec);
  }
  return s;
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

connection_impl::executor_type connection_impl::get_executor() const
{
  return socket.get_executor();
}

udp::endpoint connection_impl::remote_endpoint()
{
  return socket.engine.remote_endpoint(*this);
}

void connection_impl::connect(stream_connect_operation& op)
{
  auto lock = std::unique_lock{socket.engine.mutex};
  if (err) {
    op.post(std::exchange(err, {}), nullptr);
    return;
  }
  if (!handle) {
    op.post(make_error_code(errc::bad_file_descriptor), nullptr);
    return;
  }
  auto s = std::make_unique<stream_impl>(get_executor(), this);
  stream_state::connect(s->state, op);
  connecting_streams.push_back(*s.release()); // transfer ownership
  ::lsquic_conn_make_stream(handle);
  socket.engine.process(lock);
}

stream_impl* connection_impl::on_connect(lsquic_stream_t* stream)
{
  assert(!connecting_streams.empty());
  auto& s = connecting_streams.front();
  connecting_streams.pop_front();
  open_streams.push_back(s);
  stream_state::on_connect(s.state, s, stream);
  return &s;
}

void connection_impl::accept(stream_accept_operation& op)
{
  auto lock = std::unique_lock{socket.engine.mutex};
  if (err) {
    op.post(std::exchange(err, {}), nullptr);
    return;
  }
  if (!handle) {
    op.post(make_error_code(errc::bad_file_descriptor), nullptr);
    return;
  }
  if (!incoming_streams.empty()) {
    // take ownership of the first incoming stream
    auto s = std::unique_ptr<stream_impl>{&incoming_streams.front()};
    incoming_streams.pop_front();
    open_streams.push_back(*s);
    stream_state::accept_incoming(s->state, socket.engine.is_http);
    op.post(error_code{}, std::move(s)); // success
    return;
  }
  auto s = std::make_unique<stream_impl>(get_executor(), this);
  stream_state::accept(s->state, op);
  accepting_streams.push_back(*s.release()); // transfer ownership
}

stream_impl* connection_impl::on_accept(lsquic_stream* stream)
{
  if (accepting_streams.empty()) {
    // not waiting on accept, queue this for later
    auto s = std::make_unique<stream_impl>(get_executor(), this);
    incoming_streams.push_back(*s);
    stream_state::on_incoming(s->state, stream);
    return s.release();
  }
  auto& s = accepting_streams.front();
  accepting_streams.pop_front();
  open_streams.push_back(s);
  stream_state::on_accept(s.state, s, stream);
  return &s;
}

bool connection_impl::is_open() const
{
  return socket.engine.is_open(*this);
}

void connection_impl::close(error_code& ec)
{
  socket.engine.close(*this, ec);
}

} // namespace detail

} // namespace nexus::quic
