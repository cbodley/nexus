#pragma once

#include <stdexcept>
#include <utility>

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
  ~context();

  // emerg, alert, crit, error, warn, notice, info, debug
  void log_to_stderr(const char* level);
};

class init_exception : std::exception {
  const char* what() const noexcept override {
    return "quic library global initialization failed";
  }
};

} // namespace nexus::quic::global
