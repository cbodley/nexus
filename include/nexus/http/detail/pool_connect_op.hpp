#pragma once

#include <memory>
#include <boost/asio/associated_executor.hpp>
#include <boost/asio/associated_allocator.hpp>
#include <nexus/http/connection.hpp>
#include <nexus/http/detail/connection_pool_impl.hpp>
#include <nexus/http/detail/shutdown_op.hpp>

namespace nexus::http::detail {

template <typename Handler>
struct pool_connect_op {
  std::weak_ptr<connection_pool_impl> pool;
  boost::intrusive_ptr<connection_impl> impl;
  Handler handler;

  explicit pool_connect_op(const std::shared_ptr<connection_pool_impl>& pool,
                           boost::intrusive_ptr<connection_impl> impl,
                           Handler&& handler)
    : pool(pool), impl(std::move(impl)), handler(std::move(handler))
  {}

  // ConnectHandler
  void operator()(boost::system::error_code ec)
  {
    const bool connected = !ec;
    auto conn = connection{nullptr};
    auto p = pool.lock();
    if (!p) {
      // connection pool was destroyed
      ec = boost::asio::error::operation_aborted;
    } else {
      p->on_connect(impl.get(), ec);
    }
    if (!ec) {
      conn = connection{std::move(impl)};
    } else if (connected) {
      auto ex = impl->get_executor();
      impl->async_shutdown(shutdown_op{std::move(impl), ex});
    }
    handler(ec, std::move(conn));
  }

  using allocator_type = boost::asio::associated_allocator_t<Handler>;
  allocator_type get_allocator() const noexcept {
    return boost::asio::get_associated_allocator(handler);
  }
};

} // namespace nexus::http::detail

namespace boost::asio {

// specialize boost::asio::associated_executor<> for pool_connect_op
template <typename Handler, typename Executor>
struct associated_executor<nexus::http::detail::pool_connect_op<Handler>, Executor> {
  using type = boost::asio::associated_executor_t<Handler, Executor>;

  static type get(const nexus::http::detail::pool_connect_op<Handler>& handler,
                  const Executor& ex = Executor()) noexcept {
    return boost::asio::get_associated_executor(handler.handler, ex);
  }
};

} // namespace boost::asio
