#pragma once

#include <boost/asio/associated_executor.hpp>
#include <boost/asio/associated_allocator.hpp>
#include <nexus/http/detail/connection_impl.hpp>

namespace nexus::http::detail {

template <typename Handler>
struct ssl_shutdown_op {
  connection_impl* conn;
  Handler handler;

  explicit ssl_shutdown_op(connection_impl* conn, Handler&& handler)
    : conn(conn), handler(std::move(handler))
  {}

  // ShutdownHandler
  void operator()(boost::system::error_code ec)
  {
    conn->on_shutdown(ec, std::move(handler));
  }

  using allocator_type = boost::asio::associated_allocator_t<Handler>;
  allocator_type get_allocator() const noexcept {
    return boost::asio::get_associated_allocator(handler);
  }
};

} // namespace nexus::http::detail

namespace boost::asio {

// specialize boost::asio::associated_executor<> for ssl_shutdown_op
template <typename Handler, typename Executor>
struct associated_executor<nexus::http::detail::ssl_shutdown_op<Handler>, Executor> {
  using type = boost::asio::associated_executor_t<Handler, Executor>;

  static type get(const nexus::http::detail::ssl_shutdown_op<Handler>& op,
                  const Executor& ex = Executor()) noexcept {
    return boost::asio::get_associated_executor(op.handler, ex);
  }
};

} // namespace boost::asio
