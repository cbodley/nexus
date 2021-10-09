#include <nexus/quic/connection.hpp>
#include <nexus/quic/client.hpp>
#include <nexus/quic/server.hpp>
#include <nexus/quic/stream.hpp>

namespace nexus::quic {

connection::connection(acceptor& a) : state(a.state) {}
connection::connection(client& c) : state(c.socket) {}

connection::connection(client& c, const udp::endpoint& endpoint,
                       const char* hostname)
    : state(c.socket)
{
  c.connect(*this, endpoint, hostname);
}

connection::executor_type connection::get_executor() const
{
  return state.get_executor();
}

udp::endpoint connection::remote_endpoint()
{
  return state.remote_endpoint();
}

bool connection::is_open() const
{
  return state.is_open();
}

stream connection::connect(error_code& ec)
{
  detail::stream_connect_sync op;
  state.connect(op);
  op.wait();
  ec = std::get<0>(*op.result);
  return std::get<1>(std::move(*op.result));
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
  state.accept(op);
  op.wait();
  ec = std::get<0>(*op.result);
  return std::get<1>(std::move(*op.result));
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
  state.close(ec);
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

connection_state::executor_type connection_state::get_executor() const
{
  return socket.get_executor();
}

udp::endpoint connection_state::remote_endpoint()
{
  return socket.engine.remote_endpoint(*this);
}

void connection_state::connect(stream_connect_operation& op)
{
  socket.engine.stream_connect(*this, op);
}

void connection_state::accept(stream_accept_operation& op)
{
  socket.engine.stream_accept(*this, op);
}

bool connection_state::is_open() const
{
  return socket.engine.is_open(*this);
}

void connection_state::close(error_code& ec)
{
  socket.engine.close(*this, ec);
}

} // namespace detail

} // namespace nexus::quic
