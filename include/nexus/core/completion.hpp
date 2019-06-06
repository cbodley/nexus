#pragma once

#include <memory>
#include <tuple>

namespace nexus {

/**
 * Asynchronous completion handler wrapper for use with boost::asio.
 *
 * Memory management is performed using the Handler's 'associated allocator',
 * which carries the additional requirement that its memory be released before
 * the Handler is invoked. This allows memory allocated for one asynchronous
 * operation to be reused in its continuation. Because of this requirement, any
 * calls to invoke the completion must first release ownership of it. To enforce
 * this, the static functions defer()/dispatch()/post() take the completion by
 * rvalue-reference to std::unique_ptr<completion>, i.e. std::move(completion).
 *
 * Handlers may also have an 'associated executor', so the calls to defer(),
 * dispatch(), and post() are forwarded to that executor. If there is no
 * associated executor (which is generally the case unless one was bound with
 * boost::asio::bind_executor()), the executor passed to completion::create()
 * is used as a default.
 *
 * Example use:
 *
 *   // declare a completion type with Signature = void(int, string)
 *   using MyCompletion = nexus::completion<void(int, string)>;
 *
 *   // create a completion with the given callback:
 *   std::unique_ptr<MyCompletion> c;
 *   c = MyCompletion::create(ex, [] (int a, const string& b) {});
 *
 *   // bind arguments to the callback and post to its associated executor:
 *   MyCompletion::post(std::move(c), 5, "hello");
 *
 *
 * Additional user data may be stored along with the completion to take
 * advantage of the handler allocator optimization. This is accomplished by
 * specifying its type in the template parameter T. For example, the type
 * completion<void(), int> contains a public member variable 'int user_data'.
 * Any additional arguments to completion::create() will be forwarded to type
 * T's constructor.
 *
 * If the as_base<T> type tag is used, as in completion<void(), as_base<T>>,
 * the completion will inherit from T instead of declaring it as a member
 * variable.
 *
 * When invoking the completion handler via defer(), dispatch(), or post(),
 * care must be taken when passing arguments that refer to user data, because
 * its memory is destroyed prior to invocation. In such cases, the user data
 * should be moved/copied out of the completion first.
 */
template <typename Signature, typename T = void>
class completion;


/// type tag for user_data
template <typename T>
struct as_base {};

/// optional user data to be stored with the completion
template <typename T>
struct user_data {
  T user;
  template <typename ...Args>
  user_data(Args&& ...args) : user(std::forward<Args>(args)...) {}
};
// as_base specialization inherits from T
template <typename T>
struct user_data<as_base<T>> : T {
  template <typename ...Args>
  user_data(Args&& ...args) : T(std::forward<Args>(args)...) {}
};
// void specialization
template <>
struct user_data<void> {};


// template specialization to pull the Signature's args apart
template <typename T, typename ...Args>
class completion<void(Args...), T> : public user_data<T> {
 public:
  virtual ~completion() = default;

  /// completion factory function that uses the handler's associated allocator.
  /// any additional arguments are forwared to T's constructor
  template <typename Executor1, typename Handler, typename ...TArgs>
  static std::unique_ptr<completion>
  create(const Executor1& ex1, Handler&& handler, TArgs&& ...args);

  /// take ownership of the completion, bind any arguments to the completion
  /// handler, then defer() it on its associated executor
  template <typename ...UArgs>
  static void defer(std::unique_ptr<completion>&& ptr, UArgs&& ...args);

  /// take ownership of the completion, bind any arguments to the completion
  /// handler, then dispatch() it on its associated executor
  template <typename ...UArgs>
  static void dispatch(std::unique_ptr<completion>&& ptr, UArgs&& ...args);

  /// take ownership of the completion, bind any arguments to the completion
  /// handler, then post() it to its associated executor
  template <typename ...UArgs>
  static void post(std::unique_ptr<completion>&& ptr, UArgs&& ...args);

  // use the virtual destroy() interface on delete. this allows the completion
  // to be managed by std::unique_ptr<> without a custom Deleter
  static void operator delete(void *p) {
    static_cast<completion*>(p)->deallocate();
  }
 protected:
  // constructor is protected, use create(). any constructor arguments are
  // forwarded to user_data
  template <typename ...TArgs>
  completion(TArgs&& ...args) : user_data<T>(std::forward<TArgs>(args)...) {}

  // internal interfaces for type-erasure on the Handler/Executor. uses
  // tuple<Args...> to provide perfect forwarding because you can't make
  // virtual function templates
  virtual void destroy_defer(std::tuple<Args...>&& args) = 0;
  virtual void destroy_dispatch(std::tuple<Args...>&& args) = 0;
  virtual void destroy_post(std::tuple<Args...>&& args) = 0;
  virtual void deallocate() = 0;
};

/// completion factory function that uses the handler's associated allocator.
/// any additional arguments are forwared to T's constructor
template <typename Signature, typename T, typename Executor1,
          typename Handler, typename ...TArgs>
std::unique_ptr<completion<Signature, T>>
create_completion(const Executor1& ex, Handler&& handler, TArgs&& ...args)
{
  return completion<Signature, T>::create(ex, std::forward<Handler>(handler),
                                          std::forward<TArgs>(args)...);
}

/// take ownership of the completion, bind any arguments to the completion
/// handler, then defer() it on its associated executor
template <typename Signature, typename T, typename ...Args>
void defer(std::unique_ptr<completion<Signature, T>>&& ptr, Args&& ...args)
{
  completion<Signature, T>::defer(std::move(ptr), std::forward<Args>(args)...);
}

/// take ownership of the completion, bind any arguments to the completion
/// handler, then dispatch() it on its associated executor
template <typename Signature, typename T, typename ...Args>
void dispatch(std::unique_ptr<completion<Signature, T>>&& ptr, Args&& ...args)
{
  completion<Signature, T>::dispatch(std::move(ptr), std::forward<Args>(args)...);
}

/// take ownership of the completion, bind any arguments to the completion
/// handler, then post() it to its associated executor
template <typename Signature, typename T, typename ...Args>
void post(std::unique_ptr<completion<Signature, T>>&& ptr, Args&& ...args)
{
  completion<Signature, T>::post(std::move(ptr), std::forward<Args>(args)...);
}

} // namespace nexus

#include <nexus/core/impl/completion.ipp>
