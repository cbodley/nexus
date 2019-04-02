#pragma once

#include <tuple>
#include <boost/asio/associated_allocator.hpp>
#include <boost/asio/associated_executor.hpp>

namespace nexus {

template <typename Handler, typename ...Args>
struct completion_handler {
  using handler_type = Handler;
  using tuple_type = std::tuple<Args...>;
  handler_type handler;
  tuple_type args;

  completion_handler(handler_type&& handler, tuple_type&& args)
    : handler(std::move(handler)),
      args(std::move(args))
  {}

  void operator()() & {
    std::apply(handler, args);
  }
  void operator()() const & {
    std::apply(handler, args);
  }
  void operator()() && {
    std::apply(std::move(handler), std::move(args));
  }

  using allocator_type = boost::asio::associated_allocator_t<handler_type>;
  allocator_type get_allocator() const noexcept {
    return boost::asio::get_associated_allocator(handler);
  }
};

template <typename Handler, typename ...Args>
auto bind_handler(Handler&& h, Args&& ...args)
{
  return completion_handler(std::forward<Handler>(h),
                            std::make_tuple(std::forward<Args>(args)...));
}

} // namespace nexus

namespace boost::asio {

// specialize boost::asio::associated_executor<> for completion_handler
template <typename Handler, typename Tuple, typename Executor>
struct associated_executor<nexus::completion_handler<Handler, Tuple>, Executor> {
  using type = boost::asio::associated_executor_t<Handler, Executor>;

  static type get(const nexus::completion_handler<Handler, Tuple>& handler,
                  const Executor& ex = Executor()) noexcept {
    return boost::asio::get_associated_executor(handler.handler, ex);
  }
};

} // namespace boost::asio
