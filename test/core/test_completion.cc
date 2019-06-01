#include <nexus/core/completion.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/bind_executor.hpp>
#include <gtest/gtest.h>

namespace nexus {

using boost::system::error_code;
static const error_code ok;
constexpr auto null_handler = [] (error_code) {};

TEST(Completion, no_user_data)
{
  boost::asio::io_context ioctx;
  auto ex = ioctx.get_executor();
  using signature = void(error_code);
  {
    using completion_type = completion<signature>;
    auto c = completion_type::create(ex, null_handler);
  }
  {
    using completion_type = completion<signature, void>;
    auto c = completion_type::create(ex, null_handler);
  }
  {
    auto c = create_completion<signature, void>(ex, null_handler);
  }
}

TEST(Completion, user_data)
{
  boost::asio::io_context ioctx;
  auto ex = ioctx.get_executor();
  using signature = void(error_code);
  {
    using completion_type = completion<signature, int>;
    auto c = completion_type::create(ex, null_handler, 42);
    ASSERT_EQ(42, c->user);
  }
  {
    auto c = create_completion<signature, int>(ex, null_handler, 42);
    ASSERT_EQ(42, c->user);
  }
}

TEST(Completion, user_data_as_base)
{
  boost::asio::io_context ioctx;
  auto ex = ioctx.get_executor();
  using signature = void(error_code);
  struct base {
    int value;
    base(int value) : value(value) {}
  };
  {
    using completion_type = completion<signature, as_base<base>>;
    auto c = completion_type::create(ex, null_handler, 42);
    ASSERT_EQ(42, c->value);
  }
  {
    auto c = create_completion<signature, as_base<base>>(ex, null_handler, 42);
    ASSERT_EQ(42, c->value);
  }
}

template <typename T>
auto capture(std::optional<T>& result) {
  return [&] (T r) { result = std::move(r); };
}

TEST(Completion, defer)
{
  boost::asio::io_context ioctx;
  auto ex = ioctx.get_executor();

  using signature = void(error_code);
  std::optional<error_code> ec;
  auto c = create_completion<signature, void>(ex, capture(ec));

  ioctx.post([&] {
    ASSERT_FALSE(ec);
    defer(std::move(c), ok); // defer within ex
    ASSERT_FALSE(ec); // change is not visible immediately
  });
  EXPECT_EQ(2, ioctx.poll());
}

TEST(Completion, dispatch)
{
  boost::asio::io_context ioctx;
  auto ex = ioctx.get_executor();

  using signature = void(error_code);
  std::optional<error_code> ec;
  auto c = create_completion<signature, void>(ex, capture(ec));

  ioctx.post([&] {
    ASSERT_FALSE(ec);
    dispatch(std::move(c), ok); // dispatch within ex
    ASSERT_TRUE(ec); // change is visible immediately
  });
  EXPECT_EQ(1, ioctx.poll());
}

TEST(Completion, post)
{
  boost::asio::io_context ioctx;
  auto ex = ioctx.get_executor();

  using signature = void(error_code);
  std::optional<error_code> ec;
  auto c = create_completion<signature, void>(ex, capture(ec));

  ioctx.post([&] {
    ASSERT_FALSE(ec);
    post(std::move(c), ok); // post within ex
    ASSERT_FALSE(ec); // change is not visible immediately
  });
  EXPECT_EQ(2, ioctx.poll());
}

TEST(Completion, move_only_signature)
{
  boost::asio::io_context ioctx;
  auto ex = ioctx.get_executor();

  using signature = void(std::unique_ptr<int>);
  std::optional<std::unique_ptr<int>> result;
  auto c = create_completion<signature, void>(ex, capture(result));

  ASSERT_FALSE(result); // no result before invoking
  EXPECT_EQ(0, ioctx.poll());
  EXPECT_FALSE(ioctx.stopped()); // maintains work on the executor
  ASSERT_FALSE(result);

  post(std::move(c), std::make_unique<int>(42));

  ASSERT_FALSE(result); // no result before polling
  EXPECT_EQ(1, ioctx.poll()); // ran handler
  EXPECT_TRUE(ioctx.stopped());
  ASSERT_TRUE(result);
  ASSERT_TRUE(*result);
  EXPECT_EQ(42, **result);
}

template <typename ...Args>
struct capturer {
  std::optional<std::tuple<Args...>>& result;
  capturer(std::optional<std::tuple<Args...>>& result) : result(result) {}
  template <typename ...UArgs>
  void operator()(UArgs&& ...args) {
    result = std::make_tuple(std::forward<UArgs>(args)...);
  }
};
template <typename ...Args>
auto capture(std::optional<std::tuple<Args...>>& result) {
  return capturer{result};
}

TEST(Completion, triple_signature)
{
  boost::asio::io_context ioctx;
  auto ex = ioctx.get_executor();

  using signature = void(int, std::string, double);
  std::optional<std::tuple<int, std::string, double>> result;
  auto c = create_completion<signature, void>(ex, capture(result));

  ASSERT_FALSE(result); // no result before invoking
  EXPECT_EQ(0, ioctx.poll());
  EXPECT_FALSE(ioctx.stopped()); // maintains work on the executor
  ASSERT_FALSE(result);

  post(std::move(c), 42, "foo", 3.14);

  ASSERT_FALSE(result); // no result before polling
  EXPECT_EQ(1, ioctx.poll()); // ran handler
  EXPECT_TRUE(ioctx.stopped());
  ASSERT_TRUE(result);
  EXPECT_EQ(42, std::get<0>(*result));
  EXPECT_EQ("foo", std::get<1>(*result));
  EXPECT_EQ(3.14, std::get<2>(*result));
}

TEST(Completion, executor_work)
{
  boost::asio::io_context ioctx;
  auto ex = ioctx.get_executor();

  using signature = void(error_code);
  auto c = create_completion<signature, void>(ex, null_handler);

  EXPECT_EQ(0, ioctx.poll());
  EXPECT_FALSE(ioctx.stopped()); // maintains work on the executor

  post(std::move(c), ok);

  EXPECT_EQ(1, ioctx.poll()); // ran handler
  EXPECT_TRUE(ioctx.stopped()); // no more work
}

TEST(Completion, multi_executor_work)
{
  boost::asio::io_context ioctx1;
  auto ex1 = ioctx1.get_executor();

  boost::asio::io_context ioctx2;
  auto ex2 = ioctx2.get_executor();

  using signature = void(error_code);
  auto handler = boost::asio::bind_executor(ex2, null_handler);
  // default executor is ex1 but the handler is bound to ex2
  auto c = create_completion<signature, void>(ex1, std::move(handler));

  EXPECT_EQ(0, ioctx1.poll());
  EXPECT_FALSE(ioctx1.stopped()); // maintains work on ex1
  EXPECT_EQ(0, ioctx2.poll());
  EXPECT_FALSE(ioctx2.stopped()); // maintains work on ex2

  post(std::move(c), ok);

  EXPECT_EQ(0, ioctx1.poll());
  EXPECT_TRUE(ioctx1.stopped()); // no more work on ex1

  EXPECT_EQ(1, ioctx2.poll()); // ran handler on ex2
  EXPECT_TRUE(ioctx2.stopped()); // no more work on ex2
}

} // namespace nexus
