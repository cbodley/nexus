#include <nexus/h3/client.hpp>
#include <nexus/h3/stream.hpp>
#include <nexus/quic/connection.hpp>
#include <lsquic.h>

namespace nexus {
namespace quic {

client::client(const executor_type& ex,
               const udp::endpoint& endpoint,
               asio::ssl::context& ctx)
    : state(ex, 0),
      socket(state, endpoint, false, ctx)
{
  socket.listen(0);
}

client::client(udp::socket&& socket, asio::ssl::context& ctx)
    : state(socket.get_executor(), 0),
      socket(state, std::move(socket), ctx)
{
  this->socket.listen(0);
}

client::executor_type client::get_executor() const
{
  return state.get_executor();
}

udp::endpoint client::local_endpoint() const
{
  return socket.local_endpoint();
}

void client::connect(connection& conn,
                     const udp::endpoint& endpoint,
                     const char* hostname)
{
  state.connect(conn.state, endpoint, hostname);
}

void client::close(error_code& ec)
{
  state.close();
  socket.close(ec);
}

void client::close()
{
  error_code ec;
  close(ec);
  if (ec) {
    throw system_error(ec);
  }
}

} // namespace quic

namespace h3 {

client::client(const executor_type& ex, const udp::endpoint& endpoint,
               asio::ssl::context& ctx)
    : state(ex, LSENG_HTTP),
      socket(state, endpoint, false, ctx)
{
  socket.listen(0);
}

client::client(udp::socket&& socket, asio::ssl::context& ctx)
    : state(socket.get_executor(), LSENG_HTTP),
      socket(state, std::move(socket), ctx)
{
  this->socket.listen(0);
}

client::executor_type client::get_executor() const
{
  return state.get_executor();
}

udp::endpoint client::local_endpoint() const
{
  return socket.local_endpoint();
}

void client::connect(client_connection& conn,
                     const udp::endpoint& endpoint,
                     const char* hostname)
{
  state.connect(conn.state, endpoint, hostname);
}

void client::close(error_code& ec)
{
  state.close();
  socket.close(ec);
}

void client::close()
{
  error_code ec;
  close(ec);
  if (ec) {
    throw system_error(ec);
  }
}

udp::endpoint client_connection::remote_endpoint()
{
  return state.remote_endpoint();
}

void client_connection::connect(stream& s, error_code& ec)
{
  quic::detail::stream_connect_sync op;
  state.connect(s.state, op);
  ec = *op.ec;
}

void client_connection::connect(stream& s)
{
  error_code ec;
  connect(s, ec);
  if (ec) {
    throw system_error(ec);
  }
}

void client_connection::close(error_code& ec)
{
  state.close(ec);
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
