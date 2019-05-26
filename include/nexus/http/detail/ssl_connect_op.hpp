#pragma once

#include <boost/asio/coroutine.hpp>
#include <boost/beast/experimental/core/ssl_stream.hpp>
#include <nexus/http/detail/tcp_connect_op.hpp>

namespace nexus::http::detail {

// a ConnectHandler coroutine that attempts a ssl client handshake
template <typename Handler>
struct ssl_connect_op : boost::asio::coroutine {
  using stream_type = boost::beast::ssl_stream<boost::asio::ip::tcp::socket>;
  stream_type& stream;
  bool& secure;
  Handler handler;
  boost::asio::executor_work_guard<stream_type::executor_type> work;

  explicit ssl_connect_op(stream_type& stream, bool& secure,
                          Handler&& handler)
    : stream(stream), secure(secure), handler(std::move(handler)),
      work(stream.get_executor())
  {}

#include <boost/asio/yield.hpp>
  void operator()(boost::system::error_code ec)
  {
    reenter(*this) {
      if (ec) {
        handler(ec);
        break;
      }
      yield stream.async_handshake(stream.client, std::move(*this));
      if (ec) {
        // on failure, close the connection before returning the error
        boost::system::error_code ec_ignored;
        auto& socket = stream.next_layer();
        socket.shutdown(socket.shutdown_both, ec_ignored);
        socket.close(ec_ignored);
      } else {
        secure = true;
      }
      handler(ec);
    }
  }
#include <boost/asio/unyield.hpp>

  using allocator_type = boost::asio::associated_allocator_t<Handler>;
  allocator_type get_allocator() const noexcept {
    return boost::asio::get_associated_allocator(handler);
  }
};

template <typename CompletionToken> // void(error_code)
auto async_ssl_connect(boost::asio::ip::tcp::resolver& resolver,
                       boost::beast::ssl_stream<boost::asio::ip::tcp::socket>& stream,
                       bool& resolving,
                       bool& connected,
                       bool& secure,
                       std::string_view host,
                       std::string_view service,
                       CompletionToken&& token)
{
  using Signature = void(boost::system::error_code);
  boost::asio::async_completion<CompletionToken, Signature> init(token);
  auto& handler = init.completion_handler;
  async_tcp_connect(resolver, stream.next_layer(),
                    resolving, connected, host, service,
                    ssl_connect_op{stream, secure, std::move(handler)});
  return init.result.get();
}

} // namespace nexus::http::detail

namespace boost::asio {

// specialize boost::asio::associated_executor<> for ssl_connect_op
template <typename Handler, typename Executor>
struct associated_executor<nexus::http::detail::ssl_connect_op<Handler>, Executor> {
  using type = boost::asio::associated_executor_t<Handler, Executor>;

  static type get(const nexus::http::detail::ssl_connect_op<Handler>& handler,
                  const Executor& ex = Executor()) noexcept {
    return boost::asio::get_associated_executor(handler.handler, ex);
  }
};

} // namespace boost::asio
