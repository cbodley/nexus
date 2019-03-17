#include <http2/detail/frame.hpp>
#include <gtest/gtest.h>

namespace http2 {

TEST(Frame, encode)
{
  std::vector<uint8_t> encoded;
  auto buf = boost::asio::dynamic_buffer(encoded);
  protocol::frame_header header;
  header.length = 0;
  header.type = static_cast<uint8_t>(protocol::frame_type::ping);
  header.flags = 0;
  header.stream_id = 1;
  ASSERT_EQ(9, detail::encode_frame_header(header, buf));
  ASSERT_EQ(9, encoded.size());
  EXPECT_STREQ("\x0\x0\x6\x0\x0\x0\x0\x1", (const char*)encoded.data());
}

TEST(Frame, decode)
{
  uint8_t encoded[] = {0x1, 0x0, 0x0, 0x6, 0x8, 0x1, 0x1, 0x0, 0x0};
  auto in = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(in);
  auto end = boost::asio::buffers_end(in);
  protocol::frame_header header;
  ASSERT_EQ(end, detail::decode_frame_header(pos, header));
  EXPECT_EQ(0x010000, header.length);
  EXPECT_EQ(static_cast<uint8_t>(protocol::frame_type::ping), header.type);
  EXPECT_EQ(protocol::frame_flag_padded, header.flags);
  EXPECT_EQ(0x01010000, header.stream_id);
}

} // namespace http2
