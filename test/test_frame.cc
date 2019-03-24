#include <http2/detail/frame.hpp>
#include <gtest/gtest.h>

namespace nexus::http2 {

TEST(Frame, encode)
{
  protocol::frame_header header;
  header.length = 0x01020304;
  header.type = 0x05;
  header.flags = 0x06;
  header.stream_id = 0x0708090a;

  std::string encoded;
  auto buffers = boost::asio::dynamic_buffer(encoded);
  auto buf = buffers.prepare(9);
  auto pos = boost::asio::buffers_begin(buf);
  auto end = boost::asio::buffers_end(buf);
  ASSERT_EQ(end, protocol::detail::encode_frame_header(header, pos));
  buffers.commit(9);
  ASSERT_EQ(9, encoded.size());
  EXPECT_EQ("\x2\x3\x4\x5\x6\x7\x8\x9\xa", encoded);
}

TEST(Frame, decode)
{
  uint8_t encoded[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9};
  auto buf = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buf);
  auto end = boost::asio::buffers_end(buf);
  protocol::frame_header header;
  ASSERT_EQ(end, protocol::detail::decode_frame_header(pos, header));
  EXPECT_EQ(0x010203, header.length);
  EXPECT_EQ(0x4, header.type);
  EXPECT_EQ(0x5, header.flags);
  EXPECT_EQ(0x06070809, header.stream_id);
}

} // namespace nexus::http2
