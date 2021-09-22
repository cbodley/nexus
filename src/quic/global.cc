#include <nexus/quic/global_context.hpp>

#include <stdio.h>
#include <lsquic.h>

namespace nexus::quic::global {

context::~context()
{
  if (initialized) {
    ::lsquic_global_cleanup();
  }
}

namespace detail {

int log(void* ctx, const char* buf, size_t len)
{
  return ::fwrite(buf, 1, len, stderr);
}

context init(int flags)
{
  if (int r = ::lsquic_global_init(flags); r != 0) {
    throw init_exception{};
  }
  return context::initialized_tag{};
}

} // namespace detail

void context::log_to_stderr(const char* level)
{
  static lsquic_logger_if logger{detail::log};
  ::lsquic_logger_init(&logger, nullptr, LLTS_HHMMSSMS);
  ::lsquic_set_log_level(level);
}

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
