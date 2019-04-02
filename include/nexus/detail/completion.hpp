#pragma once

#include <memory>
#include <tuple>

namespace nexus::detail {

template <typename Signature, typename T = void>
class completion;


template <typename T>
struct as_base {};

template <typename T>
struct user_data {
  T user;
  template <typename ...Args>
  user_data(Args&& ...args) : user(std::forward<Args>(args)...) {}
};
template <typename T>
struct user_data<as_base<T>> : T {
  template <typename ...Args>
  user_data(Args&& ...args) : T(std::forward<Args>(args)...) {}
};
template <>
struct user_data<void> {};


template <typename T, typename ...Args>
class completion<void(Args...), T> : public user_data<T> {
 public:
  template <typename Executor1, typename Handler, typename ...TArgs>
  static std::unique_ptr<completion>
  create(const Executor1& ex1, Handler&& handler, TArgs&& ...args);

  template <typename ...UArgs>
  static void defer(std::unique_ptr<completion>&& ptr, UArgs&& ...args);

  template <typename ...UArgs>
  static void dispatch(std::unique_ptr<completion>&& ptr, UArgs&& ...args);

  template <typename ...UArgs>
  static void post(std::unique_ptr<completion>&& ptr, UArgs&& ...args);

  static void operator delete(void *p) {
    static_cast<completion*>(p)->destroy();
  }
 protected:
  template <typename ...TArgs>
  completion(TArgs&& ...args) : user_data<T>(std::forward<TArgs>(args)...) {}

  virtual void destroy_defer(std::tuple<Args...>&& args) = 0;
  virtual void destroy_dispatch(std::tuple<Args...>&& args) = 0;
  virtual void destroy_post(std::tuple<Args...>&& args) = 0;
  virtual void destroy() = 0;
};

} // namespace nexus::detail

#include <nexus/detail/impl/completion.ipp>
