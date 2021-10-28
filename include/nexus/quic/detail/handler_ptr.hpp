#pragma once

#include <memory>
#include <boost/asio/associated_allocator.hpp>

namespace nexus::quic::detail {

/// allocate a T using the allocator associated with the given handler,
/// forwarding additional arguments to T's constructor
//
/// handler_allocate() returns a raw pointer instead of handler_ptr, because it
/// doesn't necessarily know what handler to use for its deleter. the Handler
/// itself is commonly stored in T and moved into T's constructor, so only the
/// caller knows where the handler's ends up
///
/// example usage:
///     using T = handler_wrapper<Handler>;
///     auto t = handler_allocate<T>(handler, std::move(handler));
///     auto p = handler_ptr<T, Handler>{t, &t->handler}; // take ownership
///
template <typename T, typename Handler, typename ...Args>
T* handler_allocate(Handler& handler, Args&& ...args)
{
  using Alloc = boost::asio::associated_allocator_t<Handler>;
  using Traits = std::allocator_traits<Alloc>;
  using Rebind = typename Traits::template rebind_alloc<T>;
  using RebindTraits = std::allocator_traits<Rebind>;
  auto alloc = Rebind{boost::asio::get_associated_allocator(handler)};
  auto p = RebindTraits::allocate(alloc, 1);
  try {
    RebindTraits::construct(alloc, p, std::forward<Args>(args)...);
    return p;
  } catch (const std::exception&) {
    RebindTraits::deallocate(alloc, p, 1);
    throw;
  }
}

/// unique_ptr deleter that uses the Handler's associated allocator
///
/// handler-allocated memory must be released before invoking the handler. if
/// the handler itself is stored in this memory, it must be moved out before
/// release. whenever the handler is moved, the deleter's handler pointer must
/// be updated to its new memory location
///
/// example usage:
///     auto p = handler_ptr<T, Handler>{t, &t->handler};
///     auto handler2 = std::move(p->handler);
///     p.get_deleter().handler = &handler2;
///     p.reset(); // delete t using handler2's allocator
///
template <typename Handler>
struct handler_ptr_deleter {
  using Alloc = boost::asio::associated_allocator_t<Handler>;
  using Traits = std::allocator_traits<Alloc>;

  /// public handler pointer, must be updated whenever the handler moves
  Handler* handler;
  handler_ptr_deleter(Handler* handler) noexcept : handler(handler) {}

  template <typename T>
  void operator()(T* p) {
    using Rebind = typename Traits::template rebind_alloc<T>;
    using RebindTraits = std::allocator_traits<Rebind>;
    auto alloc = Rebind{boost::asio::get_associated_allocator(*handler)};
    RebindTraits::destroy(alloc, p);
    RebindTraits::deallocate(alloc, p, 1);
  }
};

/// unique_ptr alias for handler-allocated memory
template <typename T, typename Handler>
using handler_ptr = std::unique_ptr<T, handler_ptr_deleter<Handler>>;

} // namespace nexus::quic::detail
