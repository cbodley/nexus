#include <nexus/h3/server.hpp>
#include <nexus/h3/stream.hpp>
#include <nexus/quic/connection.hpp>
#include <nexus/udp.hpp>
#include <lsquic.h>

namespace nexus {
namespace quic {

server::server(const executor_type& ex)
    : state(ex, nullptr, LSENG_SERVER)
{}

server::server(const executor_type& ex, const settings& s)
    : state(ex, &s, LSENG_SERVER)
{}

server::executor_type server::get_executor() const
{
  return state.get_executor();
}

acceptor::acceptor(server& s, udp::socket&& socket, asio::ssl::context& ctx)
    : state(s.state, std::move(socket), ctx)
{}

acceptor::acceptor(server& s, const udp::endpoint& endpoint,
                   asio::ssl::context& ctx)
    : state(s.state, endpoint, true, ctx)
{}

acceptor::executor_type acceptor::get_executor() const
{
  return state.get_executor();
}

udp::endpoint acceptor::local_endpoint() const
{
  return state.local_endpoint();
}

void acceptor::listen(int backlog)
{
  return state.listen(backlog);
}

void acceptor::accept(connection& conn, error_code& ec)
{
  detail::accept_sync op;
  state.accept(conn.state, op);
  op.wait();
  ec = *op.ec;
}

void acceptor::accept(connection& conn)
{
  error_code ec;
  accept(conn, ec);
  if (ec) {
    throw system_error(ec);
  }
}

void acceptor::close()
{
  state.close();
}

} // namespace quic

namespace h3 {

server::server(const executor_type& ex)
    : state(ex, nullptr, LSENG_SERVER | LSENG_HTTP)
{}

server::server(const executor_type& ex, const quic::settings& s)
    : state(ex, &s, LSENG_SERVER | LSENG_HTTP)
{}

server::executor_type server::get_executor() const
{
  return state.get_executor();
}

acceptor::acceptor(server& s, udp::socket&& socket, asio::ssl::context& ctx)
    : state(s.state, std::move(socket), ctx)
{}

acceptor::acceptor(server& s, const udp::endpoint& endpoint,
                   asio::ssl::context& ctx)
    : state(s.state, endpoint, true, ctx)
{}

acceptor::executor_type acceptor::get_executor() const
{
  return state.get_executor();
}

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
  quic::detail::accept_sync op;
  state.accept(conn.state, op);
  op.wait();
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

void acceptor::close()
{
  state.close();
}

udp::endpoint server_connection::remote_endpoint()
{
  return state.remote_endpoint();
}

void server_connection::accept(stream& s, error_code& ec)
{
  auto op = quic::detail::stream_accept_sync{s.state};
  state.accept(op);
  op.wait();
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

void server_connection::close(error_code& ec)
{
  state.close(ec);
}

void server_connection::close()
{
  error_code ec;
  close(ec);
  if (ec) {
    throw system_error(ec);
  }
}

} // namespace h3
} // namespace nexus
