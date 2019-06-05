#pragma once

#include <chrono>
#include <optional>
#include <string_view>
#include <boost/asio/basic_waitable_timer.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core/multi_buffer.hpp>
#include <boost/beast/experimental/core/ssl_stream.hpp>
#include <boost/intrusive/list.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>

#include <nexus/core/bind_handler.hpp>
#include <nexus/core/forward_handler.hpp>

namespace nexus::http::detail {

// a reference-counted connection type that can represent either a raw tcp
// socket or one wrapped by a ssl stream. operations on the same connection are
// not thread-safe
class connection_impl : public boost::intrusive_ref_counter<connection_impl>,
                        public boost::intrusive::list_base_hook<> {
  using tcp = boost::asio::ip::tcp;
  boost::asio::executor ex;
  tcp::resolver resolver;
  boost::beast::ssl_stream<tcp::socket> stream;
  using Clock = std::chrono::steady_clock;
  boost::asio::basic_waitable_timer<Clock> timer;
  boost::beast::multi_buffer parse_buffer;
  bool resolving = false;
  bool connected = false;
  bool secure = false;
  bool timed_out = false;
 public:
  explicit connection_impl(boost::asio::io_context& context,
                           const boost::asio::executor& ex,
                           boost::asio::ssl::context& ssl)
    : ex(ex), resolver(context), stream(context, ssl), timer(context) {}

  boost::beast::multi_buffer& get_parse_buffer() { return parse_buffer; }

  using executor_type = boost::asio::executor;
  executor_type get_executor() { return ex; }

  void connect(std::string_view host,
               std::string_view service,
               boost::system::error_code& ec);

  template <typename CompletionToken> // void(error_code)
  auto async_connect(std::string_view host,
                     std::string_view service,
                     std::optional<Clock::duration> timeout,
                     CompletionToken&& token);

  void connect_ssl(std::string_view host,
                   std::string_view service,
                   boost::system::error_code& ec);

  template <typename CompletionToken> // void(error_code)
  auto async_connect_ssl(std::string_view host,
                         std::string_view service,
                         std::optional<Clock::duration> timeout,
                         CompletionToken&& token);

  size_t available(boost::system::error_code& ec)
  {
    return stream.next_layer().available(ec);
  }

  void shutdown(boost::system::error_code& ec);

  template <typename CompletionToken> // void(error_code)
  auto async_shutdown(CompletionToken&& token);

  void close(boost::system::error_code& ec)
  {
    stream.next_layer().close(ec);
  }

  void cancel()
  {
    if (resolving) {
      resolver.cancel();
      resolving = false;
    }
    if (stream.next_layer().is_open()) {
      stream.next_layer().cancel();
    }
  }

  // SyncReadStream
  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers)
  {
    if (secure) {
      return stream.read_some(buffers);
    } else {
      return stream.next_layer().read_some(buffers);
    }
  }
  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers,
                   boost::system::error_code& ec)
  {
    if (secure) {
      return stream.read_some(buffers, ec);
    } else {
      return stream.next_layer().read_some(buffers, ec);
    }
  }

  // SyncWriteStream
  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers)
  {
    if (secure) {
      return stream.write_some(buffers);
    } else {
      return stream.next_layer().write_some(buffers);
    }
  }
  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers,
                    boost::system::error_code& ec)
  {
    if (secure) {
      return stream.write_some(buffers, ec);
    } else {
      return stream.next_layer().write_some(buffers, ec);
    }
  }

  // AsyncReadStream
  template <typename MutableBufferSequence,
            typename CompletionToken> // void(error_code, size_t)
  auto async_read_some(const MutableBufferSequence& buffers,
                       CompletionToken&& token)
  {
    if (secure) {
      return stream.async_read_some(
          buffers, std::forward<CompletionToken>(token));
    } else {
      return stream.next_layer().async_read_some(
          buffers, std::forward<CompletionToken>(token));
    }
  }

  // AsyncWriteStream
  template <typename ConstBufferSequence,
            typename CompletionToken> // void(error_code, size_t)
  auto async_write_some(const ConstBufferSequence& buffers,
                        CompletionToken&& token)
  {
    if (secure) {
      return stream.async_write_some(
          buffers, std::forward<CompletionToken>(token));
    } else {
      return stream.next_layer().async_write_some(
          buffers, std::forward<CompletionToken>(token));
    }
  }

  template <typename Handler>
  void on_resolve(boost::system::error_code ec,
                  const tcp::resolver::results_type& results,
                  Handler&& handler);

  template <typename Handler>
  void on_connect(boost::system::error_code ec,
                  Handler&& handler);

  template <typename Handler>
  void on_handshake(boost::system::error_code ec,
                    Handler&& handler);

  template <typename Handler>
  void on_shutdown(boost::system::error_code ec,
                    Handler&& handler);
};

} // namespace nexus::http::detail

#include <nexus/http/detail/ssl_connect_op.hpp>
#include <nexus/http/detail/ssl_shutdown_op.hpp>
#include <nexus/http/detail/tcp_connect_op.hpp>
#include <nexus/http/detail/tcp_resolve_op.hpp>

namespace nexus::http::detail {

void connection_impl::connect(std::string_view host,
                              std::string_view service,
                              boost::system::error_code& ec)
{
  auto endpoints = resolver.resolve({host.data(), host.size()},
                                    {service.data(), service.size()},
                                    ec);
  if (ec) {
    return;
  }
  boost::asio::connect(stream.next_layer(), endpoints, ec);
  if (ec) {
    return;
  }
  connected = true;
}

template <typename CompletionToken>
auto connection_impl::async_connect(std::string_view host,
                                    std::string_view service,
                                    std::optional<Clock::duration> timeout,
                                    CompletionToken&& token)
{
  using Signature = void(boost::system::error_code);
  boost::asio::async_completion<CompletionToken, Signature> init(token);
  auto& handler = init.completion_handler;
  timed_out = false;
  if (timeout) {
    timer.expires_after(*timeout);
    auto ex2 = boost::asio::get_associated_executor(handler, ex);
    auto h = [this] (boost::system::error_code ec) {
      if (ec != boost::asio::error::operation_aborted) {
        timed_out = true;
        cancel();
      }
    };
    timer.async_wait(boost::asio::bind_executor(ex2, std::move(h)));
  }
  resolving = true;
  resolver.async_resolve({host.data(), host.size()},
                         {service.data(), service.size()},
                         tcp_resolve_op{this, std::move(handler)});
  return init.result.get();
}

void connection_impl::connect_ssl(std::string_view host,
                                  std::string_view service,
                                  boost::system::error_code& ec)
{
  connect(host, service, ec);
  if (ec) {
    return;
  }
  stream.handshake(stream.client, ec);
  if (ec) {
    boost::system::error_code ec_ignored;
    auto& socket = stream.next_layer();
    socket.shutdown(socket.shutdown_both, ec_ignored);
    socket.close(ec_ignored);
    connected = false;
    return;
  }
  secure = true;
}

template <typename CompletionToken>
auto connection_impl::async_connect_ssl(std::string_view host,
                                        std::string_view service,
                                        std::optional<Clock::duration> timeout,
                                        CompletionToken&& token)
{
  using Signature = void(boost::system::error_code);
  boost::asio::async_completion<CompletionToken, Signature> init(token);
  auto& handler = init.completion_handler;
  timed_out = false;
  if (timeout) {
    timer.expires_after(*timeout);
    auto ex2 = boost::asio::get_associated_executor(handler, ex);
    auto h = [this] (boost::system::error_code ec) {
      if (ec != boost::asio::error::operation_aborted) {
        timed_out = true;
        cancel();
      }
    };
    timer.async_wait(boost::asio::bind_executor(ex2, std::move(h)));
  }
  ssl_connect_op handshake_op{this, stream, std::move(handler)};
  resolving = true;
  resolver.async_resolve({host.data(), host.size()},
                         {service.data(), service.size()},
                         tcp_resolve_op{this, std::move(handshake_op)});
  return init.result.get();
}

void connection_impl::shutdown(boost::system::error_code& ec)
{
  if (secure) {
    stream.shutdown(ec);
    secure = false;
  }
  if (connected) {
    auto& socket = stream.next_layer();
    socket.shutdown(socket.shutdown_both, ec);
    connected = false;
  }
}

template <typename CompletionToken>
auto connection_impl::async_shutdown(CompletionToken&& token)
{
  using Signature = void(boost::system::error_code);
  boost::asio::async_completion<CompletionToken, Signature> init(token);
  auto& handler = init.completion_handler;
  if (secure) {
    stream.async_shutdown(ssl_shutdown_op{this, std::move(handler)});
  } else {
    auto& socket = stream.next_layer();
    boost::system::error_code ec;
    socket.shutdown(socket.shutdown_both, ec);
    connected = false;
    auto ex2 = boost::asio::get_associated_executor(handler, ex);
    auto alloc = boost::asio::get_associated_allocator(handler);
    ex2.post(bind_handler(std::move(handler), ec), alloc);
  }
  return init.result.get();
}

template <typename Handler>
void connection_impl::on_resolve(boost::system::error_code ec,
                                 const tcp::resolver::results_type& results,
                                 Handler&& handler)
{
  bool canceled = !resolving;
  resolving = false;

  if (timed_out) {
    ec = boost::asio::error::timed_out;
  } else if (canceled) {
    ec = boost::asio::error::operation_aborted;
  }
  if (ec) {
    handler(ec);
  } else {
    boost::asio::async_connect(stream.next_layer(), results,
                               tcp_connect_op{this, std::move(handler)});
  }
}

template <typename Handler>
void connection_impl::on_connect(boost::system::error_code ec,
                                 Handler&& handler)
{
  if (timed_out) {
    if (!ec) {
      auto& socket = stream.next_layer();
      boost::system::error_code ec_ignored;
      socket.shutdown(socket.shutdown_both, ec_ignored);
    }
    handler(boost::asio::error::timed_out);
  } else {
    connected = !ec;
    handler(ec);
  }
}

template <typename Handler>
void connection_impl::on_handshake(boost::system::error_code ec,
                                   Handler&& handler)
{
  if (timed_out) {
    ec = boost::asio::error::timed_out;
  }
  if (ec) {
    // on failure, close the connection before returning the error
    boost::system::error_code ec_ignored;
    auto& socket = stream.next_layer();
    socket.shutdown(socket.shutdown_both, ec_ignored);
    socket.close(ec_ignored);
    connected = false;
  } else {
    secure = true;
  }
  handler(ec);
}

template <typename Handler>
void connection_impl::on_shutdown(boost::system::error_code ec,
                                  Handler&& handler)
{
  boost::system::error_code ec_ignored;
  auto& socket = stream.next_layer();
  socket.shutdown(socket.shutdown_both, ec_ignored);
  connected = false;
  secure = false;
  handler(ec);
}

} // namespace nexus::http::detail
