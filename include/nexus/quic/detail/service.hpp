#pragma once

#include <boost/intrusive/list.hpp>
#include <asio.hpp>

namespace nexus::quic::detail {

struct service_tag {};
using service_list_base_hook = boost::intrusive::list_base_hook<
    boost::intrusive::tag<service_tag>>;

// requirements for T:
// inherits publicly from service_list_base_hook
// has member function service_shutdown()
template <typename T>
class service : public asio::execution_context::service {
  using base_hook = boost::intrusive::base_hook<service_list_base_hook>;
  boost::intrusive::list<T, base_hook> entries;
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

  void add(T& entry) {
    entries.push_back(entry);
  }
  void remove(T& entry) {
    if (entries.empty()) {
      // already shut down
    } else {
      entries.erase(entries.iterator_to(entry));
    }
  }
};

} // namespace nexus::quic::detail
