#pragma once

#include <memory>
#include <asio/associated_allocator.hpp>

namespace nexus::quic::detail {

template <typename Handler>
struct handler_ptr_deleter {
  Handler* handler;
  handler_ptr_deleter(Handler* handler) : handler(handler) {}

  template <typename T>
  void operator()(T* p) {
    using Alloc = asio::associated_allocator_t<Handler>;
    using Traits = std::allocator_traits<Alloc>;
    using Rebind = typename Traits::template rebind_alloc<T>;
    auto alloc = Rebind{asio::get_associated_allocator(*handler)};
    using RebindTraits = std::allocator_traits<Rebind>;
    RebindTraits::destroy(alloc, p);
    RebindTraits::deallocate(alloc, p, 1);
  }
};

template <typename T, typename Handler>
using handler_ptr = std::unique_ptr<T, handler_ptr_deleter<Handler>>;

template <typename T, typename Handler, typename ...Args>
T* handler_allocate(Handler& handler, Args&& ...args)
{
  using Alloc = asio::associated_allocator_t<Handler>;
  using Traits = std::allocator_traits<Alloc>;
  using Rebind = typename Traits::template rebind_alloc<T>;
  auto alloc = Rebind{asio::get_associated_allocator(handler)};
  using RebindTraits = std::allocator_traits<Rebind>;
  auto p = RebindTraits::allocate(alloc, 1);
  try {
    RebindTraits::construct(alloc, p, std::forward<Args>(args)...);
    return p;
  } catch (const std::exception&) {
    RebindTraits::deallocate(alloc, p, 1);
    throw;
  }
}

} // namespace nexus::quic::detail
