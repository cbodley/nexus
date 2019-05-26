#pragma once

#include <boost/beast/experimental/core/ssl_stream.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace nexus::http::detail {

template <typename Handler>
struct ssl_shutdown_op {
  using stream_type = boost::beast::ssl_stream<boost::asio::ip::tcp::socket>;
  stream_type& stream;
  bool& connected;
  bool& secure;
  Handler handler;
  boost::asio::executor_work_guard<stream_type::executor_type> work;

  explicit ssl_shutdown_op(stream_type& stream, bool& connected,
                           bool& secure, Handler&& handler)
    : stream(stream), connected(connected), secure(secure),
      handler(std::move(handler)), work(stream.get_executor())
  {}

  // HandshakeHandler
  void operator()(boost::system::error_code ec)
  {
    if (ec == boost::asio::error::operation_aborted) {
      handler(ec);
      return;
    }
    boost::system::error_code ec_ignored;
    auto& socket = stream.next_layer();
    socket.shutdown(socket.shutdown_both, ec_ignored);
    connected = false;
    secure = false;
    handler(ec);
  }

  using allocator_type = boost::asio::associated_allocator_t<Handler>;
  allocator_type get_allocator() const noexcept {
    return boost::asio::get_associated_allocator(handler);
  }
};

template <typename CompletionToken> // void(error_code)
auto async_ssl_shutdown(boost::beast::ssl_stream<boost::asio::ip::tcp::socket>& stream,
                        bool& connected, bool& secure, CompletionToken&& token)
{
  using Signature = void(boost::system::error_code);
  boost::asio::async_completion<CompletionToken, Signature> init(token);
  auto& handler = init.completion_handler;
  stream.async_shutdown(ssl_shutdown_op{stream, connected, secure,
                                        std::move(handler)});
  return init.result.get();
}

} // namespace nexus::http::detail

namespace boost::asio {

// specialize boost::asio::associated_executor<> for ssl_shutdown_op
template <typename Handler, typename Executor>
struct associated_executor<nexus::http::detail::ssl_shutdown_op<Handler>, Executor> {
  using type = boost::asio::associated_executor_t<Handler, Executor>;

  static type get(const nexus::http::detail::ssl_shutdown_op<Handler>& handler,
                  const Executor& ex = Executor()) noexcept {
    return boost::asio::get_associated_executor(handler.handler, ex);
  }
};

} // namespace boost::asio
