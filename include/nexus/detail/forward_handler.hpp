#pragma once

#include <boost/asio/associated_allocator.hpp>
#include <boost/asio/associated_executor.hpp>

namespace nexus {

template <typename Handler>
struct forwarding_handler {
  Handler handler;

  forwarding_handler(Handler&& handler)
    : handler(std::move(handler))
  {}

  template <typename ...Args>
  void operator()(Args&& ...args) {
    std::move(handler)(std::forward<Args>(args)...);
  }

  using allocator_type = boost::asio::associated_allocator_t<Handler>;
  allocator_type get_allocator() const noexcept {
    return boost::asio::get_associated_allocator(handler);
  }
};

template <typename Handler>
auto forward_handler(Handler&& h)
{
  return forwarding_handler{std::forward<Handler>(h)};
}

} // namespace nexus

namespace boost::asio {

// specialize boost::asio::associated_executor<> for forwarding_handler
template <typename Handler, typename Executor>
struct associated_executor<nexus::forwarding_handler<Handler>, Executor> {
  using type = boost::asio::associated_executor_t<Handler, Executor>;

  static type get(const nexus::forwarding_handler<Handler>& handler,
                  const Executor& ex = Executor()) noexcept {
    return boost::asio::get_associated_executor(handler.handler, ex);
  }
};

} // namespace boost::asio
