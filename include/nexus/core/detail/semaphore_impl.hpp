#pragma once

#include <condition_variable>
#include <limits>
#include <mutex>
#include <boost/intrusive/list.hpp>
#include <nexus/core/completion.hpp>

namespace nexus::detail {

// semaphore implementation that doesn't depend on the Executor type and does no
// internal locking
class semaphore_impl {
  size_t count; // number of resources available

  // reserved value for shutdown state
  static constexpr size_t shutdown_count = std::numeric_limits<size_t>::max();

  // waiter interface to support sync/async completions
  struct waiter : boost::intrusive::list_base_hook<> {
    size_t n;
    explicit waiter(size_t n) noexcept : n(n) {}
    virtual ~waiter() {}
    virtual void complete(boost::system::error_code ec) = 0;
  };
  using waiter_list = boost::intrusive::list<waiter>;
  waiter_list waiters;

  static constexpr auto complete(boost::system::error_code ec) {
    return [ec] (waiter* p) { p->complete(ec); };
  }
 public:
  semaphore_impl(size_t count) : count(count) {}
  ~semaphore_impl() {
    assert(waiters.empty());
  }

  void wait(size_t n, std::unique_lock<std::mutex>& lock,
            boost::system::error_code& ec)
  {
    class sync : public waiter {
      std::condition_variable cond;
      std::optional<boost::system::error_code> result;
     public:
      explicit sync(size_t n) noexcept : waiter(n) {}
      boost::system::error_code wait(std::unique_lock<std::mutex>& lock) {
        cond.wait(lock, [this] { return result; });
        return *result;
      }
      void complete(boost::system::error_code ec) override {
        result = ec;
        cond.notify_one();
      }
    };

    if (count == shutdown_count) {
      ec = boost::asio::error::operation_aborted;
    } else if (count >= n) {
      count -= n;
      ec.clear();
    } else {
      sync req{n};
      waiters.push_back(req);
      ec = req.wait(lock);
    }
  }

  template <typename Executor, typename Handler>
  void async_wait(size_t n, const Executor& ex, Handler&& handler)
  {
    using signature = void(boost::system::error_code);
    class async : public waiter {
     public:
      using completion_type = completion<signature, as_base<async>>;
      explicit async(size_t n) noexcept : waiter(n) {}
      void complete(boost::system::error_code ec) override {
        auto c = static_cast<completion_type*>(this);
        // cannot dispatch() here because we're holding the lock
        post(std::unique_ptr<completion_type>{c}, ec);
      }
    };

    if (count < n) {
      auto c = async::completion_type::create(ex, std::move(handler), n);
      waiters.push_back(*c.release());
    } else {
      boost::system::error_code ec;
      if (count == shutdown_count) {
        ec = boost::asio::error::operation_aborted;
      } else {
        count -= n;
      }
      // post immediate completion
      auto ex2 = boost::asio::get_associated_executor(handler, ex);
      auto alloc = boost::asio::get_associated_allocator(handler);
      ex2.post(bind_handler(std::move(handler), ec), alloc);
    }
  }

  void signal(size_t n)
  {
    if (count == shutdown_count) {
      return;
    }
    count += n;
    while (!waiters.empty() && (count >= waiters.front().n)) {
      waiter& req = waiters.front();
      count -= req.n;
      waiters.pop_front_and_dispose(complete(boost::system::error_code{}));
    }
  }

  void shutdown()
  {
    count = shutdown_count;
    waiters.clear_and_dispose(complete(boost::asio::error::operation_aborted));
  }
};

} // namespace nexus::detail
