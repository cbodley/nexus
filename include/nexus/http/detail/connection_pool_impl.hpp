#pragma once

#include <memory>
#include <mutex>
#include <boost/asio/io_context_strand.hpp>
#include <nexus/core/detail/semaphore_impl.hpp>
#include <nexus/http/detail/connection_impl.hpp>

namespace nexus::http::detail {

// connection pool state is shared with handlers as a weak_ptr so they're able
// to run after the pool is destroyed
class connection_pool_impl :
    public std::enable_shared_from_this<connection_pool_impl>
{
  boost::asio::io_context& context;
  boost::asio::io_context::strand executor;
  boost::asio::ssl::context& ssl;
  std::string_view host;
  std::string_view service;
  bool secure;
  size_t max_connections;
  nexus::detail::semaphore_impl semaphore;
  boost::intrusive::list<connection_impl> connecting;
  boost::intrusive::list<connection_impl> outstanding;
  boost::intrusive::list<connection_impl> idle;
  bool closed = false;
  std::mutex mutex;

  static constexpr auto release = [] (connection_impl* p) {
    intrusive_ptr_release(p);
  };

  boost::intrusive_ptr<connection_impl> pop_idle() {
    while (!idle.empty()) {
      boost::intrusive_ptr impl{&idle.back(), false}; // take ownership
      idle.pop_back();
      boost::system::error_code ec;
      impl->available(ec);
      if (!ec) {
        intrusive_ptr_add_ref(impl.get());
        outstanding.push_back(*impl);
        return impl;
      }
      // let impl destruct
    }
    return {};
  }
  static void shutdown(boost::intrusive::list<connection_impl>& conns,
                       boost::system::error_code& ec) {
    while (!conns.empty()) {
      boost::intrusive_ptr impl{&conns.back(), false}; // take ownership
      conns.pop_back();
      impl->shutdown(ec);
      impl->close(ec);
    }
  }
 public:
  connection_pool_impl(boost::asio::io_context& context,
                       boost::asio::ssl::context& ssl,
                       std::string_view host,
                       std::string_view service,
                       bool secure,
                       size_t max_connections)
    : context(context), executor(context), ssl(ssl),
      host(host), service(service), secure(secure),
      semaphore(max_connections)
  {}
  ~connection_pool_impl() {
    semaphore.shutdown();
    connecting.clear_and_dispose(release);
    outstanding.clear_and_dispose(release);
    idle.clear_and_dispose(release);
  }

  using executor_type = boost::asio::io_context::strand;
  executor_type get_executor() { return executor; }

  connection get(boost::system::error_code& ec)
  {
    std::unique_lock lock{mutex};
    if (closed) {
      ec = boost::asio::error::operation_aborted;
      return {nullptr};
    }
    semaphore.wait(1, lock, ec);
    if (ec) {
      return {nullptr};
    }
    auto impl = pop_idle();
    if (impl) {
      return {std::move(impl)};
    }
    impl.reset(new connection_impl(context, executor, ssl));
    intrusive_ptr_add_ref(impl.get());
    connecting.push_back(*impl);
    lock.unlock();
    if (secure) {
      impl->connect_ssl(host, service, ec);
    } else {
      impl->connect(host, service, ec);
    }
    on_connect(impl.get(), ec);
    if (ec) {
      impl.reset();
    }
    return {std::move(impl)};
  }

  template <typename CompletionToken> // void(error_code, connection)
  auto async_get(CompletionToken&& token);

  void put(connection conn, boost::system::error_code ec)
  {
    std::scoped_lock lock{mutex};
    semaphore.signal(1);
    auto impl = std::move(conn.impl);
    if (closed) {
      ec = boost::asio::error::operation_aborted;
      impl->close(ec);
      return;
    }
    outstanding.erase(outstanding.iterator_to(*impl));
    if (!ec) {
      impl->available(ec); // test socket
    }
    if (!ec) {
      // transfer ownership from outstanding
      idle.push_back(*impl);
    } else {
      // release ownership from outstanding
      intrusive_ptr_release(impl.get());
      impl->close(ec);
    }
  }

  void shutdown()
  {
    boost::intrusive::list<connection_impl> c, o, i;
    {
      std::scoped_lock lock{mutex};
      closed = true;
      semaphore.shutdown();
      c = std::move(connecting);
      o = std::move(outstanding);
      i = std::move(idle);
    }
    boost::system::error_code ec;
    shutdown(c, ec);
    shutdown(o, ec);
    shutdown(i, ec);
  }

  template <typename Handler>
  void on_available(Handler&& handler);

  void on_connect(connection_impl* impl,
                  boost::system::error_code& ec)
  {
    std::unique_lock lock{mutex};
    if (closed) {
      ec = boost::asio::error::operation_aborted;
      boost::system::error_code ec_ignored;
      impl->close(ec_ignored);
      return;
    }
    connecting.erase(connecting.iterator_to(*impl));
    if (ec) {
      // release ownership from connecting
      intrusive_ptr_release(impl);
      semaphore.signal(1);
    } else {
      // transfer ownership from connecting
      outstanding.push_back(*impl);
    }
  }
};

} // namespace nexus::http::detail

#include <nexus/http/detail/pool_available_op.hpp>
#include <nexus/http/detail/pool_connect_op.hpp>

namespace nexus::http::detail {

template <typename CompletionToken> // void(error_code, connection)
auto connection_pool_impl::async_get(CompletionToken&& token)
{
  using Signature = void(boost::system::error_code, connection);
  boost::asio::async_completion<CompletionToken, Signature> init(token);
  auto& handler = init.completion_handler;
  {
    std::scoped_lock lock{mutex};
    if (closed) {
      boost::system::error_code ec = boost::asio::error::operation_aborted;
      auto ex2 = boost::asio::get_associated_executor(handler, executor);
      auto alloc = boost::asio::get_associated_allocator(handler);
      auto b = bind_handler(std::move(handler), ec, connection{nullptr});
      ex2.post(forward_handler(std::move(b)), alloc);
    } else {
      semaphore.async_wait(1, executor,
                           pool_available_op{shared_from_this(),
                                             std::move(handler)});
    }
  }
  return init.result.get();
}

template <typename Handler>
void connection_pool_impl::on_available(Handler&& handler)
{
  std::unique_lock lock{mutex};
  if (closed) {
    lock.unlock();
    handler(boost::asio::error::operation_aborted, connection{nullptr});
    return;
  }
  auto impl = pop_idle();
  if (impl) {
    lock.unlock();
    handler(boost::system::error_code{}, connection{std::move(impl)});
    return;
  }
  impl.reset(new connection_impl(context, executor, ssl));
  intrusive_ptr_add_ref(impl.get());
  connecting.push_back(*impl);
  detail::pool_connect_op op{shared_from_this(), impl, std::move(handler)};
  if (secure) {
    impl->async_connect_ssl(host, service, std::nullopt, std::move(op));
  } else {
    impl->async_connect(host, service, std::nullopt, std::move(op));
  }
}

} // namespace nexus::http::detail
