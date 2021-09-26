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

void connection::connect(stream& s, error_code& ec)
{
  detail::stream_connect_sync op;
  state.connect(s.state, op);
  ec = *op.ec;
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
  detail::stream_accept_sync op;
  state.accept(s.state, op);
  ec = *op.ec;
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

void connection_state::connect(stream_state& sstate,
                               stream_connect_operation& op)
{
  socket.engine.stream_connect(sstate, op);
}

void connection_state::accept(stream_state& sstate,
                              stream_accept_operation& op)
{
  socket.engine.stream_accept(sstate, op);
}

void connection_state::close(error_code& ec)
{
  socket.engine.close(*this, ec);
}

} // namespace detail

} // namespace nexus::quic
