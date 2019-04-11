#include <nexus/http2/hpack/string.hpp>
#include <optional>
#include <random>
#include <gtest/gtest.h>

namespace nexus::http2::hpack {

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

TEST(HPACKString, decode)
{
  {
    const auto in = boost::asio::buffer("\x3ooo");
    auto pos = boost::asio::buffers_begin(in);
    auto end = boost::asio::buffers_end(in);

    std::string decoded;
    auto out = boost::asio::dynamic_buffer(decoded);
    ASSERT_TRUE(decode_string(pos, end, out));
    EXPECT_EQ("ooo", decoded);
  }
  {
    const auto in = boost::asio::buffer("\xfwww.example.com");
    auto pos = boost::asio::buffers_begin(in);
    auto end = boost::asio::buffers_end(in);

    std::string decoded;
    auto out = boost::asio::dynamic_buffer(decoded);
    ASSERT_TRUE(decode_string(pos, end, out));
    EXPECT_EQ("www.example.com", decoded);
  }
}

} // namespace nexus::http2::hpack
