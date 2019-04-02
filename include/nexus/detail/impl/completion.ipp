#pragma once

#include <boost/asio/executor_work_guard.hpp>
#include <nexus/detail/bind_handler.hpp>
#include <nexus/detail/forward_handler.hpp>

namespace nexus::detail {

template <typename Executor1, typename Handler, typename T, typename ...Args>
class completion_impl final : public completion<void(Args...), T> {
  using Executor2 = boost::asio::associated_executor_t<Handler, Executor1>;
  using Work1 = boost::asio::executor_work_guard<Executor1>;
  using Work2 = boost::asio::executor_work_guard<Executor2>;
  std::pair<Work1, Work2> work;
  Handler handler;

  using Alloc = boost::asio::associated_allocator_t<Handler>;
  using Traits = std::allocator_traits<Alloc>;
  using RebindAlloc = typename Traits::template rebind_alloc<completion_impl>;
  using RebindTraits = std::allocator_traits<RebindAlloc>;

  static void* operator new(size_t, RebindAlloc alloc) {
    return RebindTraits::allocate(alloc, 1);
  }
  static void operator delete(void *p, RebindAlloc alloc) {
    RebindTraits::deallocate(alloc, static_cast<completion_impl*>(p), 1);
  }

  void destroy_defer(std::tuple<Args...>&& args) override {
    auto w = std::move(work);
    auto h = std::move(handler);
    RebindAlloc alloc = boost::asio::get_associated_allocator(h);
    RebindTraits::destroy(alloc, this);
    RebindTraits::deallocate(alloc, this, 1);
    auto f = forward_handler(completion_handler(std::move(h), std::move(args)));
    w.second.get_executor().defer(std::move(f), alloc);
  }
  void destroy_dispatch(std::tuple<Args...>&& args) override {
    auto w = std::move(work);
    auto h = std::move(handler);
    RebindAlloc alloc = boost::asio::get_associated_allocator(h);
    RebindTraits::destroy(alloc, this);
    RebindTraits::deallocate(alloc, this, 1);
    auto f = forward_handler(completion_handler(std::move(h), std::move(args)));
    w.second.get_executor().dispatch(std::move(f), alloc);
  }
  void destroy_post(std::tuple<Args...>&& args) override {
    auto w = std::move(work);
    auto h = std::move(handler);
    RebindAlloc alloc = boost::asio::get_associated_allocator(h);
    RebindTraits::destroy(alloc, this);
    RebindTraits::deallocate(alloc, this, 1);
    auto f = forward_handler(completion_handler(std::move(h), std::move(args)));
    w.second.get_executor().post(std::move(f), alloc);
  }
  void destroy() override {
    RebindAlloc alloc = boost::asio::get_associated_allocator(handler);
    RebindTraits::destroy(alloc, this);
    RebindTraits::deallocate(alloc, this, 1);
  }

  template <typename ...TArgs>
  completion_impl(const Executor1& ex1, Handler&& handler, TArgs&& ...args)
    : completion<void(Args...), T>(std::forward<TArgs>(args)...),
      work(ex1, boost::asio::make_work_guard(handler, ex1)),
      handler(std::move(handler))
  {}
 public:
  template <typename ...TArgs>
  static std::unique_ptr<completion_impl>
  create(const Executor1& ex1, Handler&& handler, TArgs&& ...args)
  {
    auto alloc = boost::asio::get_associated_allocator(handler);
    using Ptr = std::unique_ptr<completion_impl>;
    return Ptr{new (alloc) completion_impl(ex1, std::move(handler),
                                           std::forward<TArgs>(args)...)};
  }

  static void operator delete(void *p) {
    static_cast<completion_impl*>(p)->destroy();
  }
};


template <typename T, typename ...Args>
template <typename Executor1, typename Handler, typename ...TArgs>
std::unique_ptr<completion<void(Args...), T>>
completion<void(Args...), T>::create(const Executor1& ex1,
                                     Handler&& handler,
                                     TArgs&& ...args)
{
  using impl = detail::completion_impl<Executor1, Handler, T, Args...>;
  return impl::create(ex1, std::forward<Handler>(handler),
                      std::forward<TArgs>(args)...);
}

template <typename T, typename ...Args>
template <typename ...UArgs>
void completion<void(Args...), T>::defer(std::unique_ptr<completion>&& completion,
                                         UArgs&& ...args)
{
  auto c = completion.release();
  c->destroy_defer(std::make_tuple(std::forward<UArgs>(args)...));
}

template <typename T, typename ...Args>
template <typename ...UArgs>
void completion<void(Args...), T>::dispatch(std::unique_ptr<completion>&& completion,
                                            UArgs&& ...args)
{
  auto c = completion.release();
  c->destroy_dispatch(std::make_tuple(std::forward<UArgs>(args)...));
}

template <typename T, typename ...Args>
template <typename ...UArgs>
void completion<void(Args...), T>::post(std::unique_ptr<completion>&& completion,
                                        UArgs&& ...args)
{
  auto c = completion.release();
  c->destroy_post(std::make_tuple(std::forward<UArgs>(args)...));
}

} // namespace nexus::detail
