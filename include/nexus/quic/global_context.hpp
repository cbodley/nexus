#pragma once

#include <stdexcept>

#include <lsquic.h>

namespace nexus::quic::global {

class context;

context init_client();
context init_server();
context init_client_server();


namespace detail {

context init(int flags);

} // namespace detail

class context {
  bool initialized = false;
  friend context detail::init(int flags);
  struct initialized_tag {};
  context(initialized_tag) : initialized(true) {}
 public:
  context() : initialized(false) {}
  context(context&& o) : initialized(std::exchange(o.initialized, false)) {}
  context& operator=(context&& o) {
    std::swap(initialized, o.initialized);
    return *this;
  }
  ~context() {
    if (initialized) {
      lsquic_global_cleanup();
    }
  }
};

class init_exception : std::exception {
  const char* what() const noexcept override {
    return "quic library global initialization failed";
  }
};

namespace detail {

context init(int flags)
{
  if (int r = lsquic_global_init(flags); r != 0) {
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
