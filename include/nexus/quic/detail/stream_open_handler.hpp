#pragma once

#include <memory>
#include <asio/associated_allocator.hpp>
#include <asio/associated_executor.hpp>
#include <nexus/error_code.hpp>

namespace nexus::quic::detail {

struct stream_state;

template <typename Stream>
struct stream_factory {
  static Stream create(std::unique_ptr<stream_state> sstate) { return sstate; }
};

/// the generic stream handler returns a unique_ptr<stream_state>. wrap that
/// completion with one that returns a Stream constructed with that state
template <typename Stream, typename Handler>
struct stream_open_handler {
  Handler handler;
  explicit stream_open_handler(Handler&& handler)
      : handler(std::move(handler))
  {}
  void operator()(error_code ec, std::unique_ptr<stream_state> sstate) &
  {
    handler(ec, stream_factory<Stream>::create(std::move(sstate)));
  }
  void operator()(error_code ec, std::unique_ptr<stream_state> sstate) &&
  {
    std::move(handler)(ec, stream_factory<Stream>::create(std::move(sstate)));
  }

  using allocator_type = asio::associated_allocator_t<Handler>;
  allocator_type get_allocator() const noexcept {
    return asio::get_associated_allocator(handler);
  }
};

} // namespace nexus::quic::detail

namespace asio {

// specialize asio::associated_executor<> for stream_open_handler
template <typename Stream, typename Handler, typename Executor>
struct associated_executor<nexus::quic::detail::stream_open_handler<Stream, Handler>, Executor> {
  using type = asio::associated_executor_t<Handler, Executor>;

  static type get(const nexus::quic::detail::stream_open_handler<Stream, Handler>& handler,
                  const Executor& ex = Executor()) noexcept {
    return asio::get_associated_executor(handler.handler, ex);
  }
};

} // namespace asio
