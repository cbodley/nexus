#pragma once

#include <boost/asio/associated_executor.hpp>
#include <boost/asio/associated_allocator.hpp>
#include <boost/asio/coroutine.hpp>
#include <nexus/http/detail/connection_impl.hpp>

namespace nexus::http::detail {

// a ConnectHandler coroutine that attempts a ssl client handshake
template <typename Handler>
struct ssl_connect_op : boost::asio::coroutine {
  connection_impl* conn;
  using stream_type = boost::beast::ssl_stream<boost::asio::ip::tcp::socket>;
  stream_type& stream;
  Handler handler;
  boost::asio::executor_work_guard<stream_type::executor_type> work;

  explicit ssl_connect_op(connection_impl* conn,
                          stream_type& stream,
                          Handler&& handler)
    : conn(conn), stream(stream),
      handler(std::move(handler)),
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

      conn->on_handshake(ec, std::move(handler));
    }
  }
#include <boost/asio/unyield.hpp>

  using allocator_type = boost::asio::associated_allocator_t<Handler>;
  allocator_type get_allocator() const noexcept {
    return boost::asio::get_associated_allocator(handler);
  }
};

} // namespace nexus::http::detail

namespace boost::asio {

// specialize boost::asio::associated_executor<> for ssl_connect_op
template <typename Handler, typename Executor>
struct associated_executor<nexus::http::detail::ssl_connect_op<Handler>, Executor> {
  using type = boost::asio::associated_executor_t<Handler, Executor>;

  static type get(const nexus::http::detail::ssl_connect_op<Handler>& op,
                  const Executor& ex = Executor()) noexcept {
    return boost::asio::get_associated_executor(op.handler, ex);
  }
};

} // namespace boost::asio
