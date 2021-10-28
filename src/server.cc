#include <nexus/h3/server.hpp>
#include <nexus/h3/stream.hpp>
#include <nexus/quic/connection.hpp>
#include <nexus/udp.hpp>
#include <lsquic.h>

namespace nexus {
namespace quic {

server::server(const executor_type& ex)
    : engine(ex, nullptr, nullptr, LSENG_SERVER)
{}

server::server(const executor_type& ex, const settings& s)
    : engine(ex, nullptr, &s, LSENG_SERVER)
{}

server::executor_type server::get_executor() const
{
  return engine.get_executor();
}

void server::close()
{
  engine.close();
}

acceptor::acceptor(server& s, udp::socket&& socket, ssl::context& ctx)
    : impl(s.engine, std::move(socket), ctx)
{}

acceptor::acceptor(server& s, const udp::endpoint& endpoint,
                   ssl::context& ctx)
    : impl(s.engine, endpoint, true, ctx)
{}

acceptor::executor_type acceptor::get_executor() const
{
  return impl.get_executor();
}

udp::endpoint acceptor::local_endpoint() const
{
  return impl.local_endpoint();
}

void acceptor::listen(int backlog)
{
  return impl.listen(backlog);
}

void acceptor::accept(connection& conn, error_code& ec)
{
  detail::accept_sync op;
  impl.accept(conn.impl, op);
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
  impl.close();
}

} // namespace quic

namespace h3 {

server::server(const executor_type& ex)
    : engine(ex, nullptr, nullptr, LSENG_SERVER | LSENG_HTTP)
{}

server::server(const executor_type& ex, const quic::settings& s)
    : engine(ex, nullptr, &s, LSENG_SERVER | LSENG_HTTP)
{}

server::executor_type server::get_executor() const
{
  return engine.get_executor();
}

acceptor::acceptor(server& s, udp::socket&& socket, ssl::context& ctx)
    : impl(s.engine, std::move(socket), ctx)
{}

acceptor::acceptor(server& s, const udp::endpoint& endpoint,
                   ssl::context& ctx)
    : impl(s.engine, endpoint, true, ctx)
{}

acceptor::executor_type acceptor::get_executor() const
{
  return impl.get_executor();
}

udp::endpoint acceptor::local_endpoint() const
{
  return impl.local_endpoint();
}

void acceptor::listen(int backlog)
{
  return impl.listen(backlog);
}

void acceptor::accept(server_connection& conn, error_code& ec)
{
  quic::detail::accept_sync op;
  impl.accept(conn.impl, op);
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
  impl.close();
}

bool server_connection::is_open() const
{
  return impl.is_open();
}

quic::connection_id server_connection::id(error_code& ec) const
{
  return impl.id(ec);
}

quic::connection_id server_connection::id() const
{
  error_code ec;
  auto i = impl.id(ec);
  if (ec) {
    throw system_error(ec);
  }
  return i;
}

udp::endpoint server_connection::remote_endpoint(error_code& ec) const
{
  return impl.remote_endpoint(ec);
}

udp::endpoint server_connection::remote_endpoint() const
{
  error_code ec;
  auto e = impl.remote_endpoint(ec);
  if (ec) {
    throw system_error(ec);
  }
  return e;
}

void server_connection::accept(stream& s, error_code& ec)
{
  auto op = quic::detail::stream_accept_sync{s.impl};
  impl.accept(op);
  op.wait();
  ec = std::get<0>(*op.result);
}

void server_connection::accept(stream& s)
{
  error_code ec;
  accept(s, ec);
  if (ec) {
    throw system_error(ec);
  }
}

void server_connection::go_away(error_code& ec)
{
  impl.go_away(ec);
}

void server_connection::go_away()
{
  error_code ec;
  impl.go_away(ec);
  if (ec) {
    throw system_error(ec);
  }
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
