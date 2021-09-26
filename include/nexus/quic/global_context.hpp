#pragma once

#include <stdexcept>
#include <utility>

#include <nexus/quic/error.hpp>

namespace nexus::quic::global {

/// a context object representing the global initialization of the nexus
/// QUIC/HTTP library, and its consequent global cleanup on destruction
class context;

/// initialize the library for clients only
context init_client(error_code& ec);
/// initialize the library for clients only
context init_client();

/// initialize the library for server only
context init_server(error_code& ec);
/// initialize the library for server only
context init_server();

/// initialize the library for client and server use
context init_client_server(error_code& ec);
/// initialize the library for client and server use
context init_client_server();


namespace detail {

context init(int flags, error_code& ec);

} // namespace detail

class context {
  bool initialized = false;
  friend context detail::init(int flags, error_code& ec);
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

  /// return true if the context represents successful initialization
  operator bool() const { return initialized; }

  /// enable log output to stderr, where the log level is one of:
  /// emerg, alert, crit, error, warn, notice, info, debug
  void log_to_stderr(const char* level);
};

} // namespace nexus::quic::global
