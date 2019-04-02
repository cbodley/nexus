#pragma once

#include <condition_variable>
#include <mutex>
#include <optional>

#include <boost/asio/buffer.hpp>

#include <nexus/detail/completion.hpp>

namespace nexus::test::detail {

template <typename DynamicBuffer>
class echo_impl {
  DynamicBuffer buffer;
  std::mutex mutex;
  bool closed = false;

  struct waiter {
    virtual ~waiter() {}
    virtual void complete(boost::system::error_code ec) = 0;
    virtual void destroy() = 0;
  };
  waiter* reader = nullptr;
 public:
  template <typename ...Args>
  echo_impl(std::in_place_t, Args&& ...args)
    : buffer(std::forward<Args>(args)...)
  {}
  ~echo_impl() {
    if (reader) {
      reader->destroy();
    }
  }

  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers,
                    boost::system::error_code& ec) {
    ec.clear();
    size_t bytes = 0;
    waiter* r = nullptr;
    {
      auto lock = std::scoped_lock(mutex);
      if (closed) {
        ec = boost::asio::error::connection_aborted;
        return 0;
      }
      auto target = buffer.prepare(boost::asio::buffer_size(buffers));
      bytes = boost::asio::buffer_copy(target, buffers);
      buffer.commit(bytes);
      if (buffer.size()) {
        r = std::exchange(reader, nullptr);
      }
    }
    if (r) {
      r->complete(ec);
    }
    return bytes;
  }

  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers,
                   boost::system::error_code& ec) {
    ec.clear();
    struct sync_waiter : waiter {
      std::mutex& mutex;
      std::condition_variable cond;
      std::optional<boost::system::error_code> ec;
      sync_waiter(std::mutex& mutex) : mutex(mutex) {}
      void complete(boost::system::error_code ec) override {
        auto lock = std::scoped_lock(mutex);
        this->ec = ec;
        cond.notify_one();
      }
      void destroy() override {} // noop, destroyed by the stack
    };
    auto lock = std::unique_lock(mutex);
    if (!buffer.size()) {
      if (closed) {
        ec = boost::asio::error::eof;
        return 0;
      }
      assert(reader == nullptr);
      sync_waiter w(mutex);
      reader = &w;
      w.cond.wait(lock, [&w] { return w.ec; });
      ec = *w.ec;
      if (ec) {
        return 0;
      }
    }
    const auto bytes = boost::asio::buffer_copy(buffers, buffer.data());
    buffer.consume(bytes);
    return bytes;
  }

  template <typename Executor, typename MutableBufferSequence,
            typename ReadHandler>
  void async_read_some(const Executor& ex,
                       const MutableBufferSequence& buffers,
                       ReadHandler&& handler) {
    using Signature = void(boost::system::error_code);
    using namespace nexus::detail; // completion, as_base
    struct async_waiter : waiter {
      using Completion = completion<Signature, as_base<async_waiter>>;
      void complete(boost::system::error_code ec) override {
        auto c = static_cast<Completion*>(this);
        Completion::dispatch(std::unique_ptr<Completion>{c}, ec);
      }
      void destroy() override {
        delete static_cast<Completion*>(this);
      }
    };
    auto lock = std::scoped_lock(mutex);
    if (buffer.size()) {
      const size_t bytes = boost::asio::buffer_copy(buffers, buffer.data());
      buffer.consume(bytes);
      boost::system::error_code ec;
      std::move(handler)(ec, bytes);
    } else if (closed) {
      std::move(handler)(boost::asio::error::eof, 0);
    } else {
      auto c = async_waiter::Completion::create(ex, std::move(handler));
      assert(reader == nullptr);
      reader = c.release();
    }
  }

  void cancel() {
    waiter* r = nullptr;
    {
      auto lock = std::scoped_lock(mutex);
      r = std::exchange(reader, nullptr);
    }
    if (r) {
      r->complete(boost::asio::error::operation_aborted);
    }
  }
  void close() {
    waiter* r = nullptr;
    {
      auto lock = std::scoped_lock(mutex);
      closed = true;
      r = std::exchange(reader, nullptr);
    }
    if (r) {
      r->complete(boost::asio::error::eof);
    }
  }
};

template <typename DynamicBuffer, typename MutableBufferSequence,
          typename Executor1, typename Handler>
class echo_read_op {
  echo_impl<DynamicBuffer>& impl;
  const MutableBufferSequence buffers;
  using Executor2 = boost::asio::associated_executor_t<Handler, Executor1>;
  using Work1 = boost::asio::executor_work_guard<Executor1>;
  using Work2 = boost::asio::executor_work_guard<Executor2>;
  std::pair<Work1, Work2> work;
 public:
  Handler handler;
  echo_read_op(echo_impl<DynamicBuffer>& impl,
               const MutableBufferSequence& buffers,
               const Executor1& ex1, Handler&& handler)
    : impl(impl), buffers(buffers),
      work(ex1, boost::asio::make_work_guard(handler, ex1)),
      handler(std::move(handler))
  {}
  using executor_type = Executor2;
  using allocator_type = boost::asio::associated_allocator_t<Handler>;
  allocator_type get_allocator() const noexcept {
    return boost::asio::get_associated_allocator(handler);
  }
  void operator()(boost::system::error_code ec = boost::system::error_code()) {
    if (ec) {
      std::move(handler)(ec, 0);
    } else {
      impl.async_read_some(work.first.get_executor(),
                           buffers, std::move(*this));
    }
  }
  void operator()(boost::system::error_code ec, size_t bytes) {
    std::move(handler)(ec, bytes);
  }
};

template <typename DynamicBuffer, typename ConstBufferSequence,
          typename Executor1, typename Handler>
class echo_write_op {
  echo_impl<DynamicBuffer>& impl;
  const ConstBufferSequence buffers;
  using Executor2 = boost::asio::associated_executor_t<Handler, Executor1>;
  using Work1 = boost::asio::executor_work_guard<Executor1>;
  using Work2 = boost::asio::executor_work_guard<Executor2>;
  std::pair<Work1, Work2> work;
 public:
  Handler handler;
  echo_write_op(echo_impl<DynamicBuffer>& impl,
                const ConstBufferSequence& buffers,
                const Executor1& ex1, Handler&& handler)
    : impl(impl), buffers(buffers),
      work(ex1, boost::asio::make_work_guard(handler, ex1)),
      handler(std::move(handler))
  {}
  using executor_type = Executor2;
  using allocator_type = boost::asio::associated_allocator_t<Handler>;
  allocator_type get_allocator() const noexcept {
    return boost::asio::get_associated_allocator(handler);
  }
  void operator()() {
    auto w = std::move(work);
    boost::system::error_code ec;
    const size_t bytes = impl.write_some(buffers, ec);
    std::move(handler)(ec, bytes);
  }
};

} // namespace nexus::test::detail

namespace boost::asio {

// specialize boost::asio::associated_executor<> for read/write_op
template <typename DynamicBuffer, typename ConstBufferSequence,
          typename Handler, typename Executor1, typename Executor2>
struct associated_executor<nexus::test::detail::echo_read_op<
    DynamicBuffer, ConstBufferSequence, Handler, Executor1>, Executor2>
{
  using type = boost::asio::associated_executor_t<Handler, Executor2>;
  static type get(const nexus::test::detail::echo_read_op<DynamicBuffer,
                      ConstBufferSequence, Handler, Executor1>& handler,
                  const Executor2& ex = Executor2()) noexcept {
    return boost::asio::get_associated_executor(handler.handler, ex);
  }
};
template <typename DynamicBuffer, typename ConstBufferSequence,
          typename Handler, typename Executor1, typename Executor2>
struct associated_executor<nexus::test::detail::echo_write_op<
    DynamicBuffer, ConstBufferSequence, Handler, Executor1>, Executor2>
{
  using type = boost::asio::associated_executor_t<Handler, Executor2>;
  static type get(const nexus::test::detail::echo_write_op<DynamicBuffer,
                      ConstBufferSequence, Handler, Executor1>& handler,
                  const Executor2& ex = Executor2()) noexcept {
    return boost::asio::get_associated_executor(handler.handler, ex);
  }
};

} // namespace boost::asio
