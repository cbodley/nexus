#pragma once

#include <nexus/core/detail/semaphore_impl.hpp>

namespace nexus {

/**
 * A synchronization primitive that coordinates shared access to a limited
 * number of resources.
 *
 * Access is requested with wait() and async_wait(), which complete in FIFO
 * order as more resources are made available by calls to signal().
 *
 * Example use:
 *   basic_semaphore sem{ex, 2};
 *
 *   sem.wait(1, ec);
 *   sem.wait(1, ec);
 *   sem.wait(1, ec); // blocks until signal()
 */
template <typename Executor>
class basic_semaphore {
  Executor ex;
  std::mutex mutex;
  detail::semaphore_impl impl;
 public:
  basic_semaphore(const Executor& ex, size_t count)
    : ex(ex), impl(count) {}

  using executor_type = Executor;
  executor_type get_executor() { return ex; }

  /// wait until 'n' resources are available. fails with operation_aborted after
  /// a call to shutdown()
  void wait(size_t n, boost::system::error_code& ec)
  {
    std::unique_lock lock{mutex};
    impl.wait(n, lock, ec);
  }

  /// invoke the given completion handler once 'n' resources are available
  template <typename CompletionToken> // void(error_code)
  auto async_wait(size_t n, CompletionToken&& token)
  {
    using signature = void(boost::system::error_code);
    boost::asio::async_completion<CompletionToken, signature> init(token);
    {
      std::scoped_lock lock{mutex};
      impl.async_wait(n, ex, std::move(init.completion_handler));
    }
    return init.result.get();
  }

  /// return 'n' resources, unblocking any waiters that can be satisfied
  void signal(size_t n)
  {
    std::scoped_lock lock{mutex};
    impl.signal(n);
  }

  /// cancel any waiters with operation_aborted and fail later calls to wait()
  void shutdown()
  {
    std::scoped_lock lock{mutex};
    impl.shutdown();
  }
};

} // namespace nexus
