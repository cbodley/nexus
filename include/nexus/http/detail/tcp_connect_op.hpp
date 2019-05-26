#pragma once

#include <string_view>
#include <boost/asio/associated_executor.hpp>
#include <boost/asio/associated_allocator.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace nexus::http::detail {

// a handler wrapper that composes dns resolution and ranged connect
template <typename Handler>
struct tcp_connect_op {
  boost::asio::ip::tcp::resolver& resolver;
  boost::asio::ip::tcp::socket& stream;
  bool& resolving;
  bool& connected;
  Handler handler;

  explicit tcp_connect_op(boost::asio::ip::tcp::resolver& resolver,
                          boost::asio::ip::tcp::socket& stream,
                          bool& resolving,
                          bool& connected,
                          Handler&& handler)
    : resolver(resolver), stream(stream),
      resolving(resolving), connected(connected),
      handler(std::move(handler))
  {}

  // ResolveHandler
  void operator()(boost::system::error_code ec,
                  boost::asio::ip::tcp::resolver::results_type results)
  {
    if (ec) {
      handler(ec);
    } else if (!resolving) { // canceled
      handler(boost::asio::error::operation_aborted);
    } else {
      boost::asio::async_connect(stream, results, std::move(*this));
    }
  }

  // RangeConnectHandler
  void operator()(boost::system::error_code ec,
                  const boost::asio::ip::tcp::endpoint&)
  {
    if (!ec) {
      connected = true;
    }
    handler(ec);
  }

  using allocator_type = boost::asio::associated_allocator_t<Handler>;
  allocator_type get_allocator() const noexcept {
    return boost::asio::get_associated_allocator(handler);
  }
};

template <typename CompletionToken> // void(error_code)
auto async_tcp_connect(boost::asio::ip::tcp::resolver& resolver,
                       boost::asio::ip::tcp::socket& stream,
                       bool& resolving,
                       bool& connected,
                       std::string_view host,
                       std::string_view service,
                       CompletionToken&& token)
{
  using Signature = void(boost::system::error_code);
  boost::asio::async_completion<CompletionToken, Signature> init(token);
  auto& handler = init.completion_handler;
  resolving = true;
  resolver.async_resolve({host.data(), host.size()},
                         {service.data(), service.size()},
                         tcp_connect_op{resolver, stream, resolving, connected,
                                        std::move(handler)});
  return init.result.get();
}

} // namespace nexus::http::detail

namespace boost::asio {

// specialize boost::asio::associated_executor<> for tcp_connect_op
template <typename Handler, typename Executor>
struct associated_executor<nexus::http::detail::tcp_connect_op<Handler>, Executor> {
  using type = boost::asio::associated_executor_t<Handler, Executor>;

  static type get(const nexus::http::detail::tcp_connect_op<Handler>& handler,
                  const Executor& ex = Executor()) noexcept {
    return boost::asio::get_associated_executor(handler.handler, ex);
  }
};

} // namespace boost::asio
