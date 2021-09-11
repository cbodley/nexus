#include <nexus/quic/http3/server.hpp>
#include <nexus/quic/http3/stream.hpp>
#include <nexus/udp.hpp>
#include <lsquic.h>

namespace nexus::quic {

server::server(const asio::any_io_executor& ex,
               const udp::endpoint& endpoint)
    : state(ex, endpoint, LSENG_SERVER | LSENG_HTTP)
{}

server::server(udp::socket&& socket)
    : state(std::move(socket), LSENG_SERVER | LSENG_HTTP)
{}

udp::endpoint server::local_endpoint() const
{
  return state.local_endpoint();
}

udp::endpoint server_connection::remote_endpoint()
{
  return state.remote_endpoint();
}

void server_connection::accept(error_code& ec)
{
  state.accept(ec);
}

void server_connection::accept()
{
  error_code ec;
  state.accept(ec);
  if (ec) {
    throw system_error(ec);
  }
}

namespace http3 {

server::server(const asio::any_io_executor& ex,
               const udp::endpoint& endpoint)
    : state(ex, endpoint, LSENG_SERVER | LSENG_HTTP)
{}

server::server(udp::socket&& socket)
    : state(std::move(socket), LSENG_SERVER | LSENG_HTTP)
{}

udp::endpoint server::local_endpoint() const
{
  return state.local_endpoint();
}

udp::endpoint server_connection::remote_endpoint()
{
  return state.remote_endpoint();
}

void server_connection::accept(error_code& ec)
{
  state.accept(ec);
}

void server_connection::accept()
{
  error_code ec;
  state.accept(ec);
  if (ec) {
    throw system_error(ec);
  }
}

} // namespace http3

} // namespace nexus::quic
