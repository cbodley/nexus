#pragma once

#include <utility>

#include <nexus/global/error.hpp>

namespace nexus::global {

/// a context object representing the global initialization of the nexus
/// QUIC/HTTP library, and its consequent global cleanup on destruction
class context;


namespace detail {

context init(int flags, error_code& ec);

} // namespace detail

class context {
  friend context detail::init(int flags, error_code& ec);
  using cleanup_fn = void (*)();
  cleanup_fn cleanup;
  context(cleanup_fn cleanup) noexcept : cleanup(cleanup) {}
 public:
  /// construct an uninitialized context
  context() noexcept : cleanup(nullptr) {}
  /// move construct, claiming ownership of another context's cleanup
  context(context&& o) noexcept : cleanup(std::exchange(o.cleanup, nullptr)) {}
  /// move assign, swapping ownership with another context
  context& operator=(context&& o) noexcept {
    std::swap(cleanup, o.cleanup);
    return *this;
  }
  /// perform global shutdown if initialized
  ~context() {
    if (cleanup) {
      shutdown();
    }
  }

  /// return true if the context represents successful initialization
  operator bool() const { return cleanup; }

  /// enable log output to stderr, where the log level is one of:
  /// emerg, alert, crit, error, warn, notice, info, debug
  void log_to_stderr(const char* level);

  /// perform global shutdown of an initialized context
  void shutdown() {
    cleanup();
  }
};

} // namespace nexus::global
