#pragma once

#include <memory>
#include <boost/asio/associated_executor.hpp>
#include <boost/asio/associated_allocator.hpp>
#include <nexus/http/connection.hpp>
#include <nexus/http/detail/connection_pool_impl.hpp>

namespace nexus::http::detail {

template <typename Handler>
struct pool_available_op {
  std::weak_ptr<connection_pool_impl> pool;
  Handler handler;

  explicit pool_available_op(const std::shared_ptr<connection_pool_impl>& pool,
                             Handler&& handler)
    : pool(pool), handler(std::move(handler))
  {}

  // WaitHandler
  void operator()(boost::system::error_code ec)
  {
    if (!ec) {
      auto p = pool.lock();
      if (p) {
        p->on_available(std::move(handler));
        return;
      }
      // connection pool was destroyed
      ec = boost::asio::error::operation_aborted;
    }
    handler(ec, connection{nullptr});
  }

  using allocator_type = boost::asio::associated_allocator_t<Handler>;
  allocator_type get_allocator() const noexcept {
    return boost::asio::get_associated_allocator(handler);
  }
};

} // namespace nexus::http::detail

namespace boost::asio {

// specialize boost::asio::associated_executor<> for pool_available_op
template <typename Handler, typename Executor>
struct associated_executor<nexus::http::detail::pool_available_op<Handler>, Executor> {
  using type = boost::asio::associated_executor_t<Handler, Executor>;

  static type get(const nexus::http::detail::pool_available_op<Handler>& handler,
                  const Executor& ex = Executor()) noexcept {
    return boost::asio::get_associated_executor(handler.handler, ex);
  }
};

} // namespace boost::asio
