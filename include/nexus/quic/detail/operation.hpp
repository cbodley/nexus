#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <sys/uio.h>
#include <asio/associated_executor.hpp>
#include <boost/intrusive/list.hpp>
#include <nexus/error_code.hpp>
#include <nexus/h3/fields.hpp>
#include <nexus/quic/detail/handler_ptr.hpp>

namespace nexus::quic::detail {

struct stream_state;

struct operation : boost::intrusive::list_base_hook<> {
  enum class completion_type { post, defer, dispatch, destroy };

  using complete_fn = void (*)(completion_type, operation*,
                               error_code, size_t);
  complete_fn complete_;

  operation(complete_fn complete) noexcept
      : complete_(complete) {}

  void post(error_code ec, size_t bytes = 0) {
    complete_(completion_type::post, this, ec, bytes);
  }
  void defer(error_code ec, size_t bytes = 0) {
    complete_(completion_type::defer, this, ec, bytes);
  }
  void dispatch(error_code ec, size_t bytes = 0) {
    complete_(completion_type::dispatch, this, ec, bytes);
  }
  void destroy() {
    complete_(completion_type::destroy, this, {}, 0);
  }
};

template <typename Operation>
struct sync_operation : Operation {
  using completion_type = typename Operation::completion_type;
  std::mutex mutex;
  std::condition_variable cond;
  std::optional<error_code> ec;
  size_t bytes_transferred = 0;

  template <typename ...Args>
  explicit sync_operation(Args&& ...args)
      : Operation(do_complete, std::forward<Args>(args)...) {}

  static void do_complete(completion_type type, operation* op,
                          error_code ec, size_t bytes) {
    auto self = static_cast<sync_operation*>(op);
    if (type != completion_type::destroy) {
      auto lock = std::scoped_lock{self->mutex};
      self->ec = ec;
      self->bytes_transferred = bytes;
      self->cond.notify_one();
    }
  }
  void wait() {
    auto lock = std::unique_lock{mutex};
    cond.wait(lock, [this] { return ec; });
  }
};

template <typename Operation, typename Handler,
          typename IoExecutor, bool IncludeBytes = false>
struct async_operation : Operation {
  using completion_type = typename Operation::completion_type;
  using Executor = asio::associated_executor_t<Handler, IoExecutor>;
  using Work = typename asio::prefer_result<Executor,
        asio::execution::outstanding_work_t::tracked_t>::type;
  using IoWork = typename asio::prefer_result<IoExecutor,
        asio::execution::outstanding_work_t::tracked_t>::type;
  Handler handler;
  std::pair<Work, IoWork> ex;

  template <typename ...Args>
  async_operation(Handler&& handler, const IoExecutor& io_ex, Args&& ...args)
      : Operation(do_complete, std::forward<Args>(args)...),
        handler(std::move(handler)),
        ex(asio::prefer(get_associated_executor(this->handler, io_ex),
                        asio::execution::outstanding_work.tracked),
           asio::prefer(io_ex, asio::execution::outstanding_work.tracked))
  {}

  static void do_complete(completion_type type, operation* op,
                          error_code ec, size_t bytes) {
    auto self = static_cast<async_operation*>(op);
    auto p = handler_ptr<async_operation, Handler>{self, &self->handler}; // take ownership
    auto ex = std::move(self->ex);
    auto handler = std::move(self->handler); // may throw
    p.get_deleter().handler = &handler; // update deleter
    p.reset(); // delete the op
    if (type == completion_type::destroy) {
      return;
    }
    auto alloc = asio::get_associated_allocator(handler);
    auto f = [&] { // immediately invoked lambda
        if constexpr (IncludeBytes) {
          return std::bind(std::move(handler), ec, bytes); // may throw
        } else {
          return std::bind(std::move(handler), ec); // may throw
        }
      }();
    switch (type) {
      case completion_type::post:
        asio::execution::execute(
            asio::require(
                asio::prefer(ex.first,
                             asio::execution::relationship.fork,
                             asio::execution::allocator(alloc)),
                asio::execution::blocking.never),
            std::move(f));
        break;
      case completion_type::defer:
        asio::execution::execute(
            asio::require(
                asio::prefer(ex.first,
                             asio::execution::relationship.continuation,
                             asio::execution::allocator(alloc)),
                asio::execution::blocking.never),
            std::move(f));
        break;
      case completion_type::dispatch:
        asio::execution::execute(
            asio::prefer(ex.first,
                         asio::execution::blocking.possibly,
                         asio::execution::allocator(alloc)),
            std::move(f));
        break;
      case completion_type::destroy: // handled above
        break;
    }
  }
};

struct accept_operation : operation {
  accept_operation(complete_fn complete) noexcept
      : operation(complete) {}
};
struct accept_sync : sync_operation<accept_operation> {
};
template <typename Handler, typename IoExecutor>
struct accept_async :
    async_operation<accept_operation, Handler, IoExecutor> {

  accept_async(Handler&& handler, const IoExecutor& io_ex)
      : async_operation<accept_operation, Handler, IoExecutor>(
          std::move(handler), io_ex)
  {}
};

struct stream_connect_operation : operation {
  std::unique_ptr<stream_state>& stream;

  stream_connect_operation(complete_fn complete,
                           std::unique_ptr<stream_state>& stream) noexcept
      : operation(complete), stream(stream)
  {}
};
struct stream_connect_sync : sync_operation<stream_connect_operation> {
  stream_connect_sync(std::unique_ptr<stream_state>& stream)
      : sync_operation<stream_connect_operation>(stream) {}
};
template <typename Handler, typename IoExecutor>
struct stream_connect_async :
    async_operation<stream_connect_operation, Handler, IoExecutor> {

  stream_connect_async(Handler&& handler, const IoExecutor& io_ex,
                       std::unique_ptr<stream_state>& stream)
      : async_operation<stream_connect_operation, Handler, IoExecutor>(
          std::move(handler), io_ex, stream)
  {}
};

struct stream_accept_operation : operation {
  std::unique_ptr<stream_state>& stream;

  stream_accept_operation(complete_fn complete,
                          std::unique_ptr<stream_state>& stream) noexcept
      : operation(complete), stream(stream)
  {}
};
struct stream_accept_sync : sync_operation<stream_accept_operation> {
  stream_accept_sync(std::unique_ptr<stream_state>& stream)
      : sync_operation<stream_accept_operation>(stream) {}
};
template <typename Handler, typename IoExecutor>
struct stream_accept_async :
    async_operation<stream_accept_operation, Handler, IoExecutor> {

  stream_accept_async(Handler&& handler, const IoExecutor& io_ex,
                      std::unique_ptr<stream_state>& stream)
      : async_operation<stream_accept_operation, Handler, IoExecutor>(
          std::move(handler), io_ex, stream)
  {}
};

struct stream_data_operation : operation {
  static constexpr uint16_t max_iovs = 128;
  iovec iovs[max_iovs];
  uint16_t num_iovs = 0;
  size_t bytes_transferred = 0;

  stream_data_operation(complete_fn complete) noexcept
      : operation(complete) {}
};
struct stream_data_sync : sync_operation<stream_data_operation> {
};
template <typename Handler, typename IoExecutor>
struct stream_data_async :
    async_operation<stream_data_operation, Handler, IoExecutor, true> {

  stream_data_async(Handler&& handler, const IoExecutor& io_ex)
      : async_operation<stream_data_operation, Handler, IoExecutor, true>(
          std::move(handler), io_ex)
  {}
};

struct stream_header_read_operation : operation {
  h3::fields& fields;

  stream_header_read_operation(complete_fn complete,
                               h3::fields& fields) noexcept
      : operation(complete), fields(fields)
  {}
};
struct stream_header_read_sync : sync_operation<stream_header_read_operation> {
  explicit stream_header_read_sync(h3::fields& fields) noexcept
      : sync_operation<stream_header_read_operation>(fields)
  {}
};
template <typename Handler, typename IoExecutor>
struct stream_header_read_async :
    async_operation<stream_header_read_operation, Handler, IoExecutor> {

  stream_header_read_async(Handler&& handler, const IoExecutor& io_ex,
                           h3::fields& fields)
      : async_operation<stream_header_read_operation, Handler, IoExecutor>(
          std::move(handler), io_ex, fields)
  {}
};

struct stream_header_write_operation : operation {
  const h3::fields& fields;

  stream_header_write_operation(complete_fn complete,
                                const h3::fields& fields) noexcept
      : operation(complete), fields(fields)
  {}
};
struct stream_header_write_sync : sync_operation<stream_header_write_operation> {
  explicit stream_header_write_sync(const h3::fields& fields) noexcept
      : sync_operation<stream_header_write_operation>(fields)
  {}
};
template <typename Handler, typename IoExecutor>
struct stream_header_write_async :
    async_operation<stream_header_write_operation, Handler, IoExecutor> {

  stream_header_write_async(Handler&& handler, const IoExecutor& io_ex,
                            const h3::fields& fields)
      : async_operation<stream_header_write_operation, Handler, IoExecutor>(
          std::move(handler), io_ex, fields)
  {}
};

} // namespace nexus::quic::detail
