#pragma once

#include <memory>
#include <mutex>
#include <boost/asio/io_context_strand.hpp>
#include <nexus/http/detail/connection_impl.hpp>
#include <nexus/http/detail/pool_connect_op.hpp>

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
  boost::intrusive::list<connection_impl> connecting;
  boost::intrusive::list<connection_impl> outstanding;
  boost::intrusive::list<connection_impl> idle;
  bool closed = false;

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
        return impl;
      }
      // let impl destruct
    }
    return {};
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
      max_connections(max_connections)
  {}
  ~connection_pool_impl() {
    connecting.clear_and_dispose(release);
    outstanding.clear_and_dispose(release);
    idle.clear_and_dispose(release);
  }

  using executor_type = boost::asio::io_context::strand;
  executor_type get_executor() { return executor; }

  connection get(boost::system::error_code& ec)
  {
    auto impl = pop_idle();
    if (closed) {
      ec = boost::asio::error::operation_aborted;
    } else if (!impl) {
      impl.reset(new connection_impl(context, executor, ssl));
      intrusive_ptr_add_ref(impl.get());
      connecting.push_back(*impl);
      if (secure) {
        impl->connect_ssl(host, service, ec);
      } else {
        impl->connect(host, service, ec);
      }
      connecting.erase(connecting.iterator_to(*impl));
      intrusive_ptr_release(impl.get());
      if (closed) {
        impl->shutdown(ec);
        ec = boost::asio::error::operation_aborted;
      }
    }
    if (ec) {
      impl.reset();
    } else {
      intrusive_ptr_add_ref(impl.get());
      outstanding.push_back(*impl);
    }
    return {std::move(impl)};
  }

  template <typename CompletionToken> // void(error_code, connection)
  auto async_get(CompletionToken&& token)
  {
    using Signature = void(boost::system::error_code, connection);
    boost::asio::async_completion<CompletionToken, Signature> init(token);
    auto& handler = init.completion_handler;
    auto ex2 = boost::asio::get_associated_executor(handler, executor);
    auto alloc = boost::asio::get_associated_allocator(handler);

    auto impl = pop_idle();
    if (closed) {
      boost::system::error_code ec = boost::asio::error::operation_aborted;
      auto b = bind_handler(std::move(handler), ec, connection{nullptr});
      ex2.post(forward_handler(std::move(b)), alloc);
    } else if (impl) {
      boost::system::error_code ec;
      auto b = bind_handler(std::move(handler), ec, connection{std::move(impl)});
      ex2.post(forward_handler(std::move(b)), alloc);
    //} else if (connecting.size() + outstanding.size() >= max_connections) {
      // TODO: wait for outstanding to be returned, or connecting to fail
    } else {
      impl.reset(new connection_impl(context, executor, ssl));
      connecting.push_back(*impl);
      intrusive_ptr_add_ref(impl.get());

      if (secure) {
        impl->async_connect_ssl(host, service, std::nullopt,
                                pool_connect_op{shared_from_this(), impl,
                                                std::move(handler)});
      } else {
        impl->async_connect(host, service, std::nullopt,
                            pool_connect_op{shared_from_this(), impl,
                                            std::move(handler)});
      }
    }
    return init.result.get();
  }

  void put(connection conn, boost::system::error_code ec)
  {
    auto impl = std::move(conn.impl);
    outstanding.erase(outstanding.iterator_to(*impl));
    if (closed) {
      ec = boost::asio::error::operation_aborted;
    } else if (!ec) {
      impl->available(ec); // test socket
    }
    if (!ec) {
      idle.push_back(*impl);
    } else {
      intrusive_ptr_release(impl.get());
      impl->close(ec);
    }
  }

  void shutdown()
  {
    closed = true;

    boost::system::error_code ec;
    for (auto& impl : connecting) {
      impl.shutdown(ec);
      impl.close(ec);
    }
    for (auto& impl : outstanding) {
      impl.shutdown(ec);
      impl.close(ec);
    }
    while (!idle.empty()) {
      boost::intrusive_ptr impl{&idle.back(), false}; // take ownership
      idle.pop_back();
      impl->shutdown(ec);
      impl->close(ec);
    }
  }

  void on_connect(connection_impl* conn,
                  boost::system::error_code& ec)
  {
    if (closed) {
      ec = boost::asio::error::operation_aborted;
    }
    connecting.erase(connecting.iterator_to(*conn));
    if (ec) {
      // release ownership from connecting
      intrusive_ptr_release(conn);
    } else {
      // transfer ownership from connecting
      outstanding.push_back(*conn);
    }
  }
};

} // namespace nexus::http::detail
