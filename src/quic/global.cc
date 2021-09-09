#include <nexus/quic/global_context.hpp>

#include <lsquic.h>

namespace nexus::quic::global {

context::~context()
{
  if (initialized) {
    ::lsquic_global_cleanup();
  }
}

namespace detail {

context init(int flags)
{
  if (int r = ::lsquic_global_init(flags); r != 0) {
    throw init_exception{};
  }
  return context::initialized_tag{};
}

} // namespace detail

context init_client()
{
  return detail::init(LSQUIC_GLOBAL_CLIENT);
}
context init_server()
{
  return detail::init(LSQUIC_GLOBAL_SERVER);
}
context init_client_server()
{
  return detail::init(LSQUIC_GLOBAL_CLIENT | LSQUIC_GLOBAL_SERVER);
}

} // namespace nexus::quic::global
