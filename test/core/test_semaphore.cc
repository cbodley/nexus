#include <nexus/core/semaphore.hpp>
#include <boost/asio/io_context.hpp>
#include <condition_variable>
#include <optional>
#include <mutex>
#include <thread>
#include <gtest/gtest.h>

namespace nexus {

static const boost::system::error_code ok;
using namespace std::chrono_literals;

TEST(Semaphore, wait_signal)
{
  boost::asio::io_context ioctx;
  basic_semaphore sem{ioctx.get_executor(), 0};

  std::optional<boost::system::error_code> ec;
  std::mutex mutex;
  std::condition_variable cond;

  std::thread thread{[&] {
    boost::system::error_code ec_wait;
    sem.wait(1, ec_wait);

    std::scoped_lock lock{mutex};
    ec = ec_wait;
    cond.notify_one();
  }};
  {
    std::unique_lock lock{mutex};
    cond.wait_for(lock, 10ms, [&ec] { return static_cast<bool>(ec); });
    ASSERT_FALSE(ec);
  }
  sem.signal(1);
  {
    std::unique_lock lock{mutex};
    cond.wait_for(lock, 10ms, [&ec] { return static_cast<bool>(ec); });
    ASSERT_TRUE(ec);
    EXPECT_EQ(ok, *ec);
  }
  thread.join();
}

TEST(Semaphore, wait_shutdown)
{
  boost::asio::io_context ioctx;

  std::optional<boost::system::error_code> ec;
  std::mutex mutex;
  std::condition_variable cond;

  basic_semaphore sem{ioctx.get_executor(), 0};
  std::thread thread{[&] {
    boost::system::error_code ec_wait;
    sem.wait(1, ec_wait);

    std::scoped_lock lock{mutex};
    ec = ec_wait;
    cond.notify_one();
  }};
  {
    std::unique_lock lock{mutex};
    cond.wait_for(lock, 10ms, [&ec] { return static_cast<bool>(ec); });
    ASSERT_FALSE(ec);
  }
  sem.shutdown();
  {
    std::unique_lock lock{mutex};
    cond.wait_for(lock, 10ms, [&ec] { return static_cast<bool>(ec); });
    ASSERT_TRUE(ec);
    EXPECT_EQ(boost::asio::error::operation_aborted, *ec);
  }
  thread.join();
}

auto capture(std::optional<boost::system::error_code>& ec) {
  return [&] (boost::system::error_code e) { ec = e; };
}

TEST(Semaphore, async_wait_signal)
{
  boost::asio::io_context ioctx;
  basic_semaphore sem{ioctx.get_executor(), 0};

  std::optional<boost::system::error_code> ec;
  sem.async_wait(1, capture(ec));
  ASSERT_FALSE(ec);
  EXPECT_EQ(0, ioctx.poll());
  ASSERT_FALSE(ec);
  sem.signal(1);
  ASSERT_FALSE(ec);
  EXPECT_EQ(1, ioctx.poll());
  ASSERT_TRUE(ec);
  EXPECT_EQ(ok, *ec);
}

TEST(Semaphore, async_wait_shutdown)
{
  boost::asio::io_context ioctx;
  basic_semaphore sem{ioctx.get_executor(), 0};

  std::optional<boost::system::error_code> ec;
  sem.async_wait(1, capture(ec));
  EXPECT_FALSE(ec);
  EXPECT_EQ(0, ioctx.poll());
  EXPECT_FALSE(ec);
  sem.shutdown();
  EXPECT_FALSE(ec);
  EXPECT_EQ(1, ioctx.poll());
  ASSERT_TRUE(ec);
  EXPECT_EQ(boost::asio::error::operation_aborted, *ec);
}

TEST(Semaphore, async_wait_destroy)
{
  boost::asio::io_context ioctx;
  basic_semaphore sem{ioctx.get_executor(), 0};

  std::optional<boost::system::error_code> ec;
  sem.async_wait(1, capture(ec));
  EXPECT_FALSE(ec);
  EXPECT_EQ(0, ioctx.poll());
  sem.shutdown();
  EXPECT_FALSE(ec);
  // destroy sem before the async_wait continuation runs
}

TEST(Semaphore, async_wait_signal_in_handler)
{
  boost::asio::io_context ioctx;
  basic_semaphore sem{ioctx.get_executor(), 0};

  // test that signals inside the executor don't lock recursively
  sem.async_wait(1, [&] (boost::system::error_code) { sem.signal(1); });
  EXPECT_EQ(0, ioctx.poll());
  ioctx.post([&] { sem.signal(1); });
  EXPECT_EQ(2, ioctx.poll());
  EXPECT_TRUE(ioctx.stopped());
}

TEST(Semaphore, async_wait_signal_order)
{
  boost::asio::io_context ioctx;
  basic_semaphore sem{ioctx.get_executor(), 0};

  // test that a wait for 2 is satisfied before a later wait for 1
  std::optional<boost::system::error_code> ec1;
  sem.async_wait(2, capture(ec1));

  std::optional<boost::system::error_code> ec2;
  sem.async_wait(1, capture(ec2));

  EXPECT_EQ(0, ioctx.poll());
  sem.signal(1);
  EXPECT_EQ(0, ioctx.poll());
  sem.signal(1);
  EXPECT_EQ(1, ioctx.poll());
  EXPECT_TRUE(ec1);
  EXPECT_FALSE(ec2);
  sem.signal(1);
  EXPECT_EQ(1, ioctx.poll());
  EXPECT_TRUE(ioctx.stopped());
  EXPECT_TRUE(ec2);
}

} // namespace nexus
