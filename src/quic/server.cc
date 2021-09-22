#include <nexus/quic/http3/server.hpp>
#include <nexus/quic/http3/stream.hpp>
#include <nexus/udp.hpp>
#include <lsquic.h>

namespace nexus::quic {

server::server(const executor_type& ex, ssl::cert_lookup* certs)
    : state(ex, LSENG_SERVER, certs, nullptr)
{}

acceptor::acceptor(server& s, udp::socket&& socket, ssl::context_ptr ctx)
    : state(s.state, std::move(socket), std::move(ctx))
{}

acceptor::acceptor(server& s, const udp::endpoint& endpoint,
                   ssl::context_ptr ctx)
    : state(s.state, endpoint, true, std::move(ctx))
{}

udp::endpoint acceptor::local_endpoint() const
{
  return state.local_endpoint();
}

void acceptor::listen(int backlog)
{
  return state.listen(backlog);
}

void acceptor::accept(server_connection& conn, error_code& ec)
{
  detail::accept_sync op;
  state.accept(conn.state, op);
  ec = *op.ec;
}

void acceptor::accept(server_connection& conn)
{
  error_code ec;
  accept(conn, ec);
  if (ec) {
    throw system_error(ec);
  }
}

udp::endpoint server_connection::remote_endpoint()
{
  return state.remote_endpoint();
}

void server_connection::accept(stream& s, error_code& ec)
{
  detail::stream_accept_sync op;
  state.accept(s.state, op);
  ec = *op.ec;
}

void server_connection::accept(stream& s)
{
  error_code ec;
  accept(s, ec);
  if (ec) {
    throw system_error(ec);
  }
}

namespace http3 {

server::server(const executor_type& ex, ssl::cert_lookup* certs)
    : state(ex, LSENG_SERVER | LSENG_HTTP, certs, nullptr)
{}

acceptor::acceptor(server& s, udp::socket&& socket, ssl::context_ptr ctx)
    : state(s.state, std::move(socket), std::move(ctx))
{}

acceptor::acceptor(server& s, const udp::endpoint& endpoint,
                   ssl::context_ptr ctx)
    : state(s.state, endpoint, true, std::move(ctx))
{}

udp::endpoint acceptor::local_endpoint() const
{
  return state.local_endpoint();
}

void acceptor::listen(int backlog)
{
  return state.listen(backlog);
}

udp::endpoint server_connection::remote_endpoint()
{
  return state.remote_endpoint();
}

void server_connection::accept(stream& s, error_code& ec)
{
  quic::detail::stream_accept_sync op;
  state.accept(s.state, op);
  ec = *op.ec;
}

void server_connection::accept(stream& s)
{
  error_code ec;
  accept(s, ec);
  if (ec) {
    throw system_error(ec);
  }
}

} // namespace http3

} // namespace nexus::quic
