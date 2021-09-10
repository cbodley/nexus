#include <nexus/quic/http3/server.hpp>
#include <nexus/quic/http3/stream.hpp>
#include <lsquic.h>

namespace nexus::quic {

server::server(const char* node, const char* service)
    : state(node, service, LSENG_SERVER)
{}

void server::local_endpoint(sockaddr_union& local)
{
  state.local_endpoint(local);
}

void server_connection::remote_endpoint(sockaddr_union& remote)
{
  state.remote_endpoint(remote);
}

void server_connection::accept(error_code& ec)
{
  state.accept(ec);
}

void server_connection::accept()
{
  error_code ec;
  state.accept(ec);
  if (ec) {
    throw system_error(ec);
  }
}

namespace http3 {

server::server(const char* node, const char* service)
    : state(node, service, LSENG_SERVER | LSENG_HTTP)
{}

void server::local_endpoint(sockaddr_union& local)
{
  state.local_endpoint(local);
}

void server_connection::remote_endpoint(sockaddr_union& remote)
{
  state.remote_endpoint(remote);
}

void server_connection::accept(error_code& ec)
{
  state.accept(ec);
}

void server_connection::accept()
{
  error_code ec;
  state.accept(ec);
  if (ec) {
    throw system_error(ec);
  }
}

} // namespace http3

} // namespace nexus::quic
