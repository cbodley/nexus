#include <nexus/quic/http3/client.hpp>
#include <lsquic.h>

namespace nexus::quic {

client::client(const asio::any_io_executor& ex,
               const udp::endpoint& endpoint)
    : state(ex, endpoint, 0)
{}

client::client(udp::socket&& socket)
    : state(std::move(socket), 0)
{}

udp::endpoint client::local_endpoint() const
{
  return state.local_endpoint();
}

udp::endpoint client_connection::remote_endpoint()
{
  return state.remote_endpoint();
}

void client_connection::connect(const udp::endpoint& endpoint,
                                const char* hostname, error_code& ec)
{
  state.connect(endpoint, hostname, ec);
}

void client_connection::connect(const udp::endpoint& endpoint,
                                const char* hostname)
{
  error_code ec;
  state.connect(endpoint, hostname, ec);
  if (ec) {
    throw system_error(ec);
  }
}

namespace http3 {

client::client(const asio::any_io_executor& ex,
               const udp::endpoint& endpoint)
    : state(ex, endpoint, LSENG_HTTP)
{}

client::client(udp::socket&& socket)
    : state(std::move(socket), LSENG_HTTP)
{}

udp::endpoint client::local_endpoint() const
{
  return state.local_endpoint();
}

udp::endpoint client_connection::remote_endpoint()
{
  return state.remote_endpoint();
}

void client_connection::connect(const udp::endpoint& endpoint,
                                const char* hostname, error_code& ec)
{
  state.connect(endpoint, hostname, ec);
}

void client_connection::connect(const udp::endpoint& endpoint,
                                const char* hostname)
{
  error_code ec;
  state.connect(endpoint, hostname, ec);
  if (ec) {
    throw system_error(ec);
  }
}

} // namespace http3

} // namespace nexus::quic
