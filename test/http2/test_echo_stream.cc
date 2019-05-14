#include <echo_stream.hpp>
#include <optional>
#include <boost/asio/io_context.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <gtest/gtest.h>

namespace nexus {

static const boost::system::error_code ok;

TEST(EchoStream, Sync)
{
  boost::asio::io_context ioctx;
  test::echo_stream stream(ioctx.get_executor());
  boost::system::error_code ec;
  boost::asio::write(stream, boost::asio::buffer("123", 3), ec);
  EXPECT_EQ(ok, ec);
  std::string input(3, '\0');
  boost::asio::read(stream, boost::asio::buffer(input), ec);
  ASSERT_EQ(ok, ec);
  EXPECT_EQ(std::string_view("123", 3), input);
}

struct result {
  boost::system::error_code ec;
  size_t bytes_transferred;
};
auto capture(std::optional<result>& r) {
  return [&r] (boost::system::error_code e, size_t b) { r = result{e, b}; };
}

TEST(EchoStream, AsyncWriteRead)
{
  boost::asio::io_context ioctx;
  test::echo_stream stream(ioctx.get_executor());

  std::optional<result> write_res;
  boost::asio::async_write(stream, boost::asio::const_buffer("123", 3),
                           capture(write_res));

  EXPECT_EQ(1u, ioctx.poll());
  EXPECT_TRUE(ioctx.stopped());

  ASSERT_TRUE(write_res);
  EXPECT_EQ(ok, write_res->ec);
  EXPECT_EQ(3u, write_res->bytes_transferred);

  std::optional<result> read_res;
  std::string input(3, '\0');
  boost::asio::async_read(stream, boost::asio::buffer(input),
                          capture(read_res));

  ioctx.restart();
  EXPECT_EQ(1u, ioctx.poll());
  EXPECT_TRUE(ioctx.stopped());

  ASSERT_TRUE(read_res);
  ASSERT_EQ(ok, read_res->ec);
  EXPECT_EQ(3u, read_res->bytes_transferred);
  EXPECT_EQ(std::string_view("123", 3), input);
}

TEST(EchoStream, AsyncReadWrite)
{
  boost::asio::io_context ioctx;
  test::echo_stream stream(ioctx.get_executor());

  std::optional<result> read_res;
  std::string input(3, '\0');
  boost::asio::async_read(stream, boost::asio::buffer(input),
                          capture(read_res));

  EXPECT_EQ(1u, ioctx.poll());
  EXPECT_FALSE(ioctx.stopped());
  ASSERT_FALSE(read_res);

  std::optional<result> write_res;
  boost::asio::async_write(stream, boost::asio::const_buffer("123", 3),
                           capture(write_res));

  EXPECT_EQ(1u, ioctx.poll());
  EXPECT_TRUE(ioctx.stopped());

  ASSERT_TRUE(write_res);
  EXPECT_EQ(ok, write_res->ec);
  EXPECT_EQ(3u, write_res->bytes_transferred);
  ASSERT_TRUE(read_res);
  ASSERT_EQ(ok, read_res->ec);
  EXPECT_EQ(3u, read_res->bytes_transferred);
  EXPECT_EQ(std::string_view("123", 3), input);
}

TEST(EchoStream, AsyncReadCancel)
{
  boost::asio::io_context ioctx;
  test::echo_stream stream(ioctx.get_executor());

  std::optional<result> read_res;
  std::string input(3, '\0');
  boost::asio::async_read(stream, boost::asio::buffer(input),
                          capture(read_res));

  EXPECT_EQ(1u, ioctx.poll());
  EXPECT_FALSE(ioctx.stopped());

  stream.cancel();

  EXPECT_EQ(1u, ioctx.poll());
  EXPECT_TRUE(ioctx.stopped());

  ASSERT_TRUE(read_res);
  ASSERT_EQ(boost::asio::error::operation_aborted, read_res->ec);
}

TEST(EchoStream, AsyncReadClose)
{
  boost::asio::io_context ioctx;
  test::echo_stream stream(ioctx.get_executor());

  std::optional<result> read_res;
  std::string input(3, '\0');
  boost::asio::async_read(stream, boost::asio::buffer(input),
                          capture(read_res));

  EXPECT_EQ(1u, ioctx.poll());
  EXPECT_FALSE(ioctx.stopped());

  stream.close();

  EXPECT_EQ(1u, ioctx.poll());
  EXPECT_TRUE(ioctx.stopped());

  ASSERT_TRUE(read_res);
  ASSERT_EQ(boost::asio::error::eof, read_res->ec);
}

TEST(EchoStream, AsyncCloseRead)
{
  boost::asio::io_context ioctx;
  test::echo_stream stream(ioctx.get_executor());

  stream.close();

  std::optional<result> read_res;
  std::string input(3, '\0');
  boost::asio::async_read(stream, boost::asio::buffer(input),
                          capture(read_res));

  EXPECT_EQ(1u, ioctx.poll());
  EXPECT_TRUE(ioctx.stopped());

  ASSERT_TRUE(read_res);
  ASSERT_EQ(boost::asio::error::eof, read_res->ec);
}

TEST(EchoStream, AsyncCloseWrite)
{
  boost::asio::io_context ioctx;
  test::echo_stream stream(ioctx.get_executor());

  stream.close();

  std::optional<result> write_res;
  boost::asio::async_write(stream, boost::asio::const_buffer("123", 3),
                           capture(write_res));

  EXPECT_EQ(1u, ioctx.poll());
  EXPECT_TRUE(ioctx.stopped());

  ASSERT_TRUE(write_res);
  ASSERT_EQ(boost::asio::error::connection_aborted, write_res->ec);
}

TEST(EchoStream, AsyncWriteCloseRead)
{
  boost::asio::io_context ioctx;
  test::echo_stream stream(ioctx.get_executor());

  std::optional<result> write_res;
  boost::asio::async_write(stream, boost::asio::const_buffer("123", 3),
                           capture(write_res));

  EXPECT_EQ(1u, ioctx.poll());
  EXPECT_TRUE(ioctx.stopped());

  ASSERT_TRUE(write_res);
  EXPECT_EQ(ok, write_res->ec);
  EXPECT_EQ(3u, write_res->bytes_transferred);

  stream.close();

  std::optional<result> read_res;
  std::string input(3, '\0');
  boost::asio::async_read(stream, boost::asio::buffer(input),
                          capture(read_res));

  ioctx.restart();
  EXPECT_EQ(1u, ioctx.poll());
  EXPECT_TRUE(ioctx.stopped());

  ASSERT_TRUE(read_res);
  ASSERT_EQ(ok, read_res->ec);
  EXPECT_EQ(3u, read_res->bytes_transferred);
  EXPECT_EQ(std::string_view("123", 3), input);

  std::optional<result> reread_res;
  boost::asio::async_read(stream, boost::asio::buffer(input),
                          capture(reread_res));

  ioctx.restart();
  EXPECT_EQ(1u, ioctx.poll());
  EXPECT_TRUE(ioctx.stopped());

  ASSERT_TRUE(reread_res);
  ASSERT_EQ(boost::asio::error::eof, reread_res->ec);
}

} // namespace nexus
