#include <nexus/http2/detail/stream_buffer.hpp>
#include <gtest/gtest.h>

namespace nexus::http2 {

TEST(StreamBuffer, make)
{
  auto buffer = detail::make_stream_buffer(16);
  ASSERT_TRUE(buffer);
  EXPECT_EQ(16, buffer->max_size());
}

TEST(StreamBufferPool, set_max_buffers)
{
  const size_t buffer_size = 16;
  const size_t max_buffers = 2;
  auto pool = detail::stream_buffer_pool{buffer_size, max_buffers};
  auto b1 = pool.get();
  ASSERT_TRUE(b1);
  EXPECT_EQ(buffer_size, b1->max_size());
  auto b2 = pool.get();
  ASSERT_TRUE(b2);
  EXPECT_EQ(buffer_size, b2->max_size());
  auto b3 = pool.get();
  EXPECT_FALSE(b3) << "get() over max fails";
  pool.put(std::move(b1));
  auto b4 = pool.get();
  ASSERT_TRUE(b4) << "get() after put() succeeds";
  EXPECT_EQ(buffer_size, b4->max_size());
  pool.set_max_buffers(1);
  auto b5 = pool.get();
  EXPECT_FALSE(b5) << "get() after set_max_buffers(1) fails";
  pool.set_max_buffers(3);
  auto b6 = pool.get();
  ASSERT_TRUE(b6) << "get() after set_max_buffers(3) succeeds";
  EXPECT_EQ(buffer_size, b6->max_size());
}

TEST(StreamBufferPool, set_buffer_size)
{
  const size_t initial_buffer_size = 16;
  const size_t new_buffer_size = 32;
  const size_t max_buffers = 2;
  auto pool = detail::stream_buffer_pool{initial_buffer_size, max_buffers};
  auto b1 = pool.get();
  ASSERT_TRUE(b1);
  EXPECT_EQ(initial_buffer_size, b1->max_size());
  pool.set_buffer_size(new_buffer_size);
  auto b2 = pool.get();
  ASSERT_TRUE(b2);
  EXPECT_EQ(new_buffer_size, b2->max_size());
  pool.put(std::move(b1));
  auto b3 = pool.get();
  ASSERT_TRUE(b3);
  EXPECT_EQ(new_buffer_size, b3->max_size());
  auto b4 = pool.get();
  EXPECT_FALSE(b4) << "get() over max fails";
}

} // namespace nexus::http2
