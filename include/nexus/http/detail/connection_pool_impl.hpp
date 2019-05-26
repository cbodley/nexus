#pragma once

#include <nexus/http/detail/connection_impl.hpp>

namespace nexus::http::detail {

struct connection_pool_impl {
  boost::intrusive::list<connection_impl> connecting;
  boost::intrusive::list<connection_impl> outstanding;
  boost::intrusive::list<connection_impl> idle;
  bool closed = false;

  static constexpr auto cancel_and_release = [] (connection_impl* p) {
    intrusive_ptr_release(p);
  };

  ~connection_pool_impl() {
    connecting.clear_and_dispose(cancel_and_release);
    outstanding.clear_and_dispose(cancel_and_release);
    idle.clear_and_dispose(cancel_and_release);
  }

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
};

} // namespace nexus::http::detail
