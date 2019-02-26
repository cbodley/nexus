#include <http2/hpack.hpp>
#include <optional>
#include <random>
#include <gtest/gtest.h>

namespace http2::hpack {

static std::string encode_string(std::string_view str)
{
  std::string encoded;
  auto buf = boost::asio::dynamic_buffer(encoded);
  encode_string(str, buf);
  return encoded;
}

struct HPACKString : ::testing::Test {};

TEST(HPACKString, encode)
{
  EXPECT_EQ("\x3ooo", encode_string("ooo"));
  EXPECT_EQ("\xfwww.example.com", encode_string("www.example.com"));
}

TEST(HPACKString, encode_empty)
{
  std::vector<uint8_t> encoded;
  auto buf = boost::asio::dynamic_buffer(encoded);
  const uint8_t expected[] = { 0x0 };
  const auto count = encode_string("", buf);
  ASSERT_EQ(count, sizeof(expected));
  EXPECT_EQ(expected[0], encoded[0]);
}

} // namespace http2::hpack
