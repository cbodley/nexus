#include <nexus/quic/http3/client.hpp>
#include <nexus/quic/http3/stream.hpp>
#include <lsquic.h>

namespace nexus::quic {

client::client(const asio::any_io_executor& ex,
               const udp::endpoint& endpoint,
               const char* alpn)
    : state(ex, 0, nullptr, alpn),
      socket(state, endpoint, false, nullptr)
{
  socket.listen(0);
}

client::client(udp::socket&& socket, const char* alpn)
    : state(socket.get_executor(), 0, nullptr, alpn),
      socket(state, std::move(socket), nullptr)
{
  this->socket.listen(0);
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
  detail::stream_connect_sync op;
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

namespace http3 {

client::client(const asio::any_io_executor& ex,
               const udp::endpoint& endpoint)
    : state(ex, LSENG_HTTP, nullptr, nullptr),
      socket(state, endpoint, false, nullptr)
{
  socket.listen(0);
}

client::client(udp::socket&& socket)
    : state(socket.get_executor(), LSENG_HTTP, nullptr, nullptr),
      socket(state, std::move(socket), nullptr)
{
  this->socket.listen(0);
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

} // namespace http3

} // namespace nexus::quic
