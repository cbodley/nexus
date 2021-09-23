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

} // namespace nexus::quic
