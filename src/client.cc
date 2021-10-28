#include <nexus/h3/client.hpp>
#include <nexus/h3/stream.hpp>
#include <nexus/quic/connection.hpp>
#include <lsquic.h>

namespace nexus {
namespace quic {

client::client(const executor_type& ex, const udp::endpoint& endpoint,
               ssl::context& ctx)
    : engine(ex, &socket, nullptr, 0),
      socket(engine, endpoint, false, ctx)
{
}

client::client(const executor_type& ex, const udp::endpoint& endpoint,
               ssl::context& ctx, const settings& s)
    : engine(ex, &socket, &s, 0),
      socket(engine, endpoint, false, ctx)
{
}

client::client(udp::socket&& socket, ssl::context& ctx)
    : engine(socket.get_executor(), &this->socket, nullptr, 0),
      socket(engine, std::move(socket), ctx)
{
}

client::client(udp::socket&& socket, ssl::context& ctx, const settings& s)
    : engine(socket.get_executor(), &this->socket, &s, 0),
      socket(engine, std::move(socket), ctx)
{
}

client::executor_type client::get_executor() const
{
  return engine.get_executor();
}

udp::endpoint client::local_endpoint() const
{
  return socket.local_endpoint();
}

void client::connect(connection& conn,
                     const udp::endpoint& endpoint,
                     const char* hostname)
{
  socket.connect(conn.impl, endpoint, hostname);
}

void client::close()
{
  engine.close();
  socket.close();
}

} // namespace quic

namespace h3 {

client::client(const executor_type& ex, const udp::endpoint& endpoint,
               ssl::context& ctx)
    : engine(ex, &socket, nullptr, LSENG_HTTP),
      socket(engine, endpoint, false, ctx)
{
}

client::client(const executor_type& ex, const udp::endpoint& endpoint,
               ssl::context& ctx, const quic::settings& s)
    : engine(ex, &socket, &s, LSENG_HTTP),
      socket(engine, endpoint, false, ctx)
{
}

client::client(udp::socket&& socket, ssl::context& ctx)
    : engine(socket.get_executor(), &this->socket, nullptr, LSENG_HTTP),
      socket(engine, std::move(socket), ctx)
{
}

client::client(udp::socket&& socket, ssl::context& ctx,
               const quic::settings& s)
    : engine(socket.get_executor(), &this->socket, &s, LSENG_HTTP),
      socket(engine, std::move(socket), ctx)
{
}

client::executor_type client::get_executor() const
{
  return engine.get_executor();
}

udp::endpoint client::local_endpoint() const
{
  return socket.local_endpoint();
}

void client::connect(client_connection& conn,
                     const udp::endpoint& endpoint,
                     const char* hostname)
{
  socket.connect(conn.impl, endpoint, hostname);
}

void client::close()
{
  engine.close();
  socket.close();
}

bool client_connection::is_open() const
{
  return impl.is_open();
}

quic::connection_id client_connection::id(error_code& ec) const
{
  return impl.id(ec);
}

quic::connection_id client_connection::id() const
{
  error_code ec;
  auto i = impl.id(ec);
  if (ec) {
    throw system_error(ec);
  }
  return i;
}

udp::endpoint client_connection::remote_endpoint(error_code& ec) const
{
  return impl.remote_endpoint(ec);
}

udp::endpoint client_connection::remote_endpoint() const
{
  error_code ec;
  auto e = impl.remote_endpoint(ec);
  if (ec) {
    throw system_error(ec);
  }
  return e;
}

void client_connection::connect(stream& s, error_code& ec)
{
  auto op = quic::detail::stream_connect_sync{s.impl};
  impl.connect(op);
  op.wait();
  ec = std::get<0>(*op.result);
}

void client_connection::connect(stream& s)
{
  error_code ec;
  connect(s, ec);
  if (ec) {
    throw system_error(ec);
  }
}

void client_connection::go_away(error_code& ec)
{
  impl.go_away(ec);
}

void client_connection::go_away()
{
  error_code ec;
  impl.go_away(ec);
  if (ec) {
    throw system_error(ec);
  }
}

void client_connection::close(error_code& ec)
{
  impl.close(ec);
}

void client_connection::close()
{
  error_code ec;
  close(ec);
  if (ec) {
    throw system_error(ec);
  }
}

} // namespace h3
} // namespace nexus
