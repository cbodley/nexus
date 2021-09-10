#include <nexus/quic/http3/client.hpp>
#include <lsquic.h>

namespace nexus::quic {


void client::local_endpoint(sockaddr_union& local)
{
  state.local_endpoint(local);
}

void client_connection::remote_endpoint(sockaddr_union& remote)
{
  state.remote_endpoint(remote);
}

void client_connection::connect(const sockaddr* endpoint,
                                const char* hostname, error_code& ec)
{
  state.connect(endpoint, hostname, ec);
}

void client_connection::connect(const sockaddr* endpoint, const char* hostname)
{
  error_code ec;
  state.connect(endpoint, hostname, ec);
  if (ec) {
    throw system_error(ec);
  }
}

namespace http3 {

// this is here just to hide LSENG_HTTP from the header
client::client(const char* node, const char* service)
    : state(nullptr, service, LSENG_HTTP)
{}

void client::local_endpoint(sockaddr_union& local)
{
  state.local_endpoint(local);
}

void client_connection::remote_endpoint(sockaddr_union& remote)
{
  state.remote_endpoint(remote);
}

void client_connection::connect(const sockaddr* endpoint,
                                const char* hostname, error_code& ec)
{
  state.connect(endpoint, hostname, ec);
}

void client_connection::connect(const sockaddr* endpoint, const char* hostname)
{
  error_code ec;
  state.connect(endpoint, hostname, ec);
  if (ec) {
    throw system_error(ec);
  }
}

} // namespace http3

} // namespace nexus::quic
