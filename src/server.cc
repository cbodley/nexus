#include <nexus/h3/server.hpp>
#include <nexus/h3/stream.hpp>
#include <nexus/quic/connection.hpp>
#include <nexus/udp.hpp>
#include <lsquic.h>

namespace nexus {
namespace quic {

server::server(const executor_type& ex)
    : state(ex, nullptr, nullptr, LSENG_SERVER)
{}

server::server(const executor_type& ex, const settings& s)
    : state(ex, nullptr, &s, LSENG_SERVER)
{}

server::executor_type server::get_executor() const
{
  return state.get_executor();
}

void server::close()
{
  state.close();
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
  state.accept(conn.impl, op);
  op.wait();
  ec = std::get<0>(*op.result);
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
    : state(ex, nullptr, nullptr, LSENG_SERVER | LSENG_HTTP)
{}

server::server(const executor_type& ex, const quic::settings& s)
    : state(ex, nullptr, &s, LSENG_SERVER | LSENG_HTTP)
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
  state.accept(conn.impl, op);
  op.wait();
  ec = std::get<0>(*op.result);
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
  return impl.remote_endpoint();
}

bool server_connection::is_open() const
{
  return impl.is_open();
}

stream server_connection::accept(error_code& ec)
{
  quic::detail::stream_accept_sync op;
  impl.accept(op);
  op.wait();
  ec = std::get<0>(*op.result);
  return quic::detail::stream_factory<stream>::create(
      std::get<1>(std::move(*op.result)));
}

stream server_connection::accept()
{
  error_code ec;
  auto s = accept(ec);
  if (ec) {
    throw system_error(ec);
  }
  return s;
}

void server_connection::close(error_code& ec)
{
  impl.close(ec);
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
