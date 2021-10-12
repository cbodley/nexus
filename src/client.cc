#include <nexus/h3/client.hpp>
#include <nexus/h3/stream.hpp>
#include <nexus/quic/connection.hpp>
#include <lsquic.h>

namespace nexus {
namespace quic {

client::client(const executor_type& ex, const udp::endpoint& endpoint,
               asio::ssl::context& ctx)
    : engine(ex, &socket, nullptr, 0),
      socket(engine, endpoint, false, ctx)
{
}

client::client(const executor_type& ex, const udp::endpoint& endpoint,
               asio::ssl::context& ctx, const settings& s)
    : engine(ex, &socket, &s, 0),
      socket(engine, endpoint, false, ctx)
{
}

client::client(udp::socket&& socket, asio::ssl::context& ctx)
    : engine(socket.get_executor(), &this->socket, nullptr, 0),
      socket(engine, std::move(socket), ctx)
{
}

client::client(udp::socket&& socket, asio::ssl::context& ctx, const settings& s)
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
  engine.connect(conn.impl, endpoint, hostname);
}

void client::close()
{
  engine.close();
  socket.close();
}

} // namespace quic

namespace h3 {

client::client(const executor_type& ex, const udp::endpoint& endpoint,
               asio::ssl::context& ctx)
    : engine(ex, &socket, nullptr, LSENG_HTTP),
      socket(engine, endpoint, false, ctx)
{
}

client::client(const executor_type& ex, const udp::endpoint& endpoint,
               asio::ssl::context& ctx, const quic::settings& s)
    : engine(ex, &socket, &s, LSENG_HTTP),
      socket(engine, endpoint, false, ctx)
{
}

client::client(udp::socket&& socket, asio::ssl::context& ctx)
    : engine(socket.get_executor(), &this->socket, nullptr, LSENG_HTTP),
      socket(engine, std::move(socket), ctx)
{
}

client::client(udp::socket&& socket, asio::ssl::context& ctx,
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
  engine.connect(conn.impl, endpoint, hostname);
}

void client::close()
{
  engine.close();
  socket.close();
}

udp::endpoint client_connection::remote_endpoint()
{
  return impl.remote_endpoint();
}

bool client_connection::is_open() const
{
  return impl.is_open();
}

stream client_connection::connect(error_code& ec)
{
  quic::detail::stream_connect_sync op;
  impl.connect(op);
  op.wait();
  ec = std::get<0>(*op.result);
  return quic::detail::stream_factory<stream>::create(
      std::get<1>(std::move(*op.result)));
}

stream client_connection::connect()
{
  error_code ec;
  auto s = connect(ec);
  if (ec) {
    throw system_error(ec);
  }
  return s;
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
