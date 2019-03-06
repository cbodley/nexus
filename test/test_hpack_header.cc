#include <http2/detail/hpack/header.hpp>
#include <gtest/gtest.h>

namespace http2::detail::hpack {

TEST(HPACKHeader, encode)
{
  dynamic_table table(4096);
  std::vector<uint8_t> encoded;
  auto buf = boost::asio::dynamic_buffer(encoded);

  ASSERT_EQ(12u, encode_header("name", "value", table, buf));
  ASSERT_EQ(12u, encoded.size());

  // decode
  const auto in = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(in);
  auto end = boost::asio::buffers_end(in);
  std::string name, value;
  ASSERT_TRUE(decode_header(pos, end, table, name, value));
  EXPECT_EQ("name", name);
  EXPECT_EQ("value", value);
}

} // namespace http2::detail::hpack
