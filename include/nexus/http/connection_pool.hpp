#pragma once

#include <memory>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/asio/io_context_strand.hpp>
#include <nexus/core/bind_handler.hpp>
#include <nexus/core/forward_handler.hpp>
#include <nexus/http/connection.hpp>
#include <nexus/http/detail/connection_pool_impl.hpp>
#include <nexus/http/detail/pool_connect_op.hpp>
#include <nexus/http/uri_view.hpp>

namespace nexus::http {

class connection_pool {
  boost::asio::io_context& context;
  boost::asio::io_context::strand executor;
  boost::asio::ssl::context& ssl;
  std::string_view host;
  std::string_view service;
  bool secure;
  size_t max_connections;
  std::shared_ptr<detail::connection_pool_impl> pool;

 public:
  connection_pool(boost::asio::io_context& context,
                  boost::asio::ssl::context& ssl,
                  std::string_view host,
                  std::string_view service,
                  bool secure,
                  size_t max_connections)
    : context(context), executor(context), ssl(ssl),
      host(host), service(service),
      secure(secure), max_connections(max_connections),
      pool(std::make_unique<detail::connection_pool_impl>())
  {}

  connection_pool(boost::asio::io_context& context,
                  boost::asio::ssl::context& ssl,
                  const uri_view& uri,
                  size_t max_connections)
    : context(context), executor(context), ssl(ssl),
      host(uri.host()), service(uri.port()),
      secure(boost::iequals(uri.scheme(), "https")),
      max_connections(max_connections),
      pool(std::make_unique<detail::connection_pool_impl>())
  {}

  using executor_type = boost::asio::io_context::strand;
  executor_type get_executor() { return executor; }

  connection get(boost::system::error_code& ec)
  {
    auto impl = pool->pop_idle();
    if (pool->closed) {
      ec = boost::asio::error::operation_aborted;
    } else if (!impl) {
      impl.reset(new detail::connection_impl(context, executor, ssl));
      intrusive_ptr_add_ref(impl.get());
      pool->connecting.push_back(*impl);
      if (secure) {
        impl->connect_ssl(host, service, ec);
      } else {
        impl->connect(host, service, ec);
      }
      pool->connecting.erase(pool->connecting.iterator_to(*impl));
      intrusive_ptr_release(impl.get());
      if (pool->closed) {
        impl->shutdown(ec);
        ec = boost::asio::error::operation_aborted;
      }
    }
    if (ec) {
      impl.reset();
    } else {
      intrusive_ptr_add_ref(impl.get());
      pool->outstanding.push_back(*impl);
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

    auto impl = pool->pop_idle();
    if (pool->closed) {
      boost::system::error_code ec = boost::asio::error::operation_aborted;
      auto b = bind_handler(std::move(handler), ec, connection{nullptr});
      ex2.post(forward_handler(std::move(b)), alloc);
    } else if (impl) {
      boost::system::error_code ec;
      auto b = bind_handler(std::move(handler), ec, connection{std::move(impl)});
      ex2.post(forward_handler(std::move(b)), alloc);
    } else if (pool->connecting.size() + pool->outstanding.size() >= max_connections) {
      abort();
    } else {
      impl.reset(new detail::connection_impl(context, executor, ssl));
      pool->connecting.push_back(*impl);
      intrusive_ptr_add_ref(impl.get());

      if (secure) {
        impl->async_connect_ssl(host, service, std::nullopt,
                                detail::pool_connect_op{pool, impl,
                                                        std::move(handler)});
      } else {
        impl->async_connect(host, service, std::nullopt,
                            detail::pool_connect_op{pool, impl,
                                                    std::move(handler)});
      }
    }
    return init.result.get();
  }

  void put(connection conn, boost::system::error_code ec)
  {
    auto impl = std::move(conn.impl);
    pool->outstanding.erase(pool->outstanding.iterator_to(*impl));
    if (pool->closed) {
      ec = boost::asio::error::operation_aborted;
    } else if (!ec) {
      impl->available(ec); // test socket
    }
    if (!ec) {
      pool->idle.push_back(*impl);
    } else {
      intrusive_ptr_release(impl.get());
      impl->close(ec);
    }
  }

  void shutdown()
  {
    pool->closed = true;

    boost::system::error_code ec;
    for (auto& impl : pool->connecting) {
      impl.shutdown(ec);
      impl.close(ec);
    }
    for (auto& impl : pool->outstanding) {
      impl.shutdown(ec);
      impl.close(ec);
    }
    while (!pool->idle.empty()) {
      boost::intrusive_ptr impl{&pool->idle.back(), false}; // take ownership
      pool->idle.pop_back();
      impl->shutdown(ec);
      impl->close(ec);
    }
  }
};

} // namespace nexus::http
