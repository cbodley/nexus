#pragma once

#include <mutex>
#include <boost/intrusive/list.hpp>
#include <asio/execution_context.hpp>

namespace nexus::quic::detail {

struct service_tag {};
using service_list_base_hook = boost::intrusive::list_base_hook<
    boost::intrusive::tag<service_tag>>;

/// service for two-phase execution_context shutdown, which breaks ownership
/// cycles between completion handlers and their io objects. tracks objects
/// which may have outstanding completion handlers, and calls their member
/// function service_shutdown() when the execution_context is shutting down.
/// this member function should destroy any memory associated with its
/// outstanding completion handlers
///
/// requirements for IoObject:
/// * inherits publicly from service_list_base_hook
/// * has public member function service_shutdown()
template <typename IoObject>
class service : public asio::execution_context::service {
  using base_hook = boost::intrusive::base_hook<service_list_base_hook>;
  boost::intrusive::list<IoObject, base_hook> entries;
  std::mutex mutex;

  /// called by the execution_context on shutdown
  void shutdown() override {
    while (!entries.empty()) {
      auto& entry = entries.front();
      entries.pop_front();
      entry.service_shutdown();
    }
  }
 public:
  using key_type = service;
  static inline asio::execution_context::id id;

  explicit service(asio::execution_context& ctx)
      : asio::execution_context::service(ctx) {}

  /// register an io object for notification of service_shutdown()
  void add(IoObject& entry) {
    auto lock = std::scoped_lock{mutex};
    entries.push_back(entry);
  }
  /// unregister an object
  void remove(IoObject& entry) {
    auto lock = std::scoped_lock{mutex};
    if (entries.empty()) {
      // already shut down
    } else {
      entries.erase(entries.iterator_to(entry));
    }
  }
};

} // namespace nexus::quic::detail
