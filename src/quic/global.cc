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

context init(int flags, error_code& ec)
{
  if (int r = ::lsquic_global_init(flags); r == 0) {
    return context::initialized_tag{}; // success
  }
  ec = make_error_code(error::global_init_failed);
  return {}; // failure
}

} // namespace detail

void context::log_to_stderr(const char* level)
{
  static lsquic_logger_if logger{detail::log};
  ::lsquic_logger_init(&logger, nullptr, LLTS_HHMMSSMS);
  ::lsquic_set_log_level(level);
}


context init_client(error_code& ec)
{
  return detail::init(LSQUIC_GLOBAL_CLIENT, ec);
}
context init_client()
{
  error_code ec;
  auto ctx = init_client(ec);
  if (ec) {
    throw system_error(ec);
  }
  return ctx;
}

context init_server(error_code& ec)
{
  return detail::init(LSQUIC_GLOBAL_SERVER, ec);
}
context init_server()
{
  error_code ec;
  auto ctx = init_server(ec);
  if (ec) {
    throw system_error(ec);
  }
  return ctx;
}

context init_client_server(error_code& ec)
{
  return detail::init(LSQUIC_GLOBAL_CLIENT | LSQUIC_GLOBAL_SERVER, ec);
}
context init_client_server()
{
  error_code ec;
  auto ctx = init_client_server(ec);
  if (ec) {
    throw system_error(ec);
  }
  return ctx;
}

} // namespace nexus::quic::global
