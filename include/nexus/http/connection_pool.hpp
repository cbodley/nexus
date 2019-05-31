#pragma once

#include <memory>
#include <boost/algorithm/string/predicate.hpp>
#include <nexus/core/bind_handler.hpp>
#include <nexus/core/forward_handler.hpp>
#include <nexus/http/connection.hpp>
#include <nexus/http/detail/connection_pool_impl.hpp>
#include <nexus/http/uri_view.hpp>

namespace nexus::http {

class connection_pool {
  std::shared_ptr<detail::connection_pool_impl> impl;
 public:
  connection_pool(boost::asio::io_context& context,
                  boost::asio::ssl::context& ssl,
                  std::string_view host,
                  std::string_view service,
                  bool secure,
                  size_t max_connections)
    : impl(std::make_unique<detail::connection_pool_impl>(
            context, ssl, host, service, secure, max_connections))
  {}
  connection_pool(boost::asio::io_context& context,
                  boost::asio::ssl::context& ssl,
                  const uri_view& uri,
                  size_t max_connections)
    : connection_pool(context, ssl, uri.host(), uri.port(),
                      boost::iequals(uri.scheme(), "https"), // bool secure
                      max_connections)
  {}

  // move-only
  connection_pool(const connection_pool&) = delete;
  connection_pool& operator=(const connection_pool&) = delete;
  connection_pool(connection_pool&&) = default;
  connection_pool& operator=(connection_pool&&) = default;

  using executor_type = boost::asio::io_context::strand;
  executor_type get_executor() { return impl->get_executor(); }

  connection get(boost::system::error_code& ec)
  {
    return impl->get(ec);
  }

  template <typename CompletionToken> // void(error_code, connection)
  auto async_get(CompletionToken&& token)
  {
    return impl->async_get(std::forward<CompletionToken>(token));
  }

  void put(connection conn, boost::system::error_code ec)
  {
    impl->put(std::move(conn), ec);
  }

  void shutdown()
  {
    impl->shutdown();
  }
};

} // namespace nexus::http
