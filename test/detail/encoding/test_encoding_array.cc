#include <nexus/detail/encoding/array.hpp>
#include <nexus/detail/encoding/network_order.hpp>
#include <vector>
#include <gtest/gtest.h>

namespace nexus::detail {

struct char_encoder { char c; };
size_t encoded_size(const char_encoder&) { return 1; }
template <typename OutputIterator>
void encode(OutputIterator& out, const char_encoder& e) { *out++ = e.c; }

struct char_decoder { char& c; };
template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, char_decoder&& d)
{
  if (!remaining) {
    return false;
  }
  d.c = *in++;
  remaining--;
  return true;
}

TEST(encoding, char_array)
{
  const char initial[] = "abc";
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, make_array_encoder<char_encoder>(initial));
  ASSERT_EQ(4u, encoded.size());
  EXPECT_EQ('a', encoded.front());
  char decoded[] = "xyz";
  auto in = encoded.begin();
  size_t remaining = encoded.size();
  ASSERT_TRUE(decode(in, remaining, make_array_decoder<char_decoder>(decoded)));
  EXPECT_EQ(initial[0], decoded[0]);
  EXPECT_EQ(initial[1], decoded[1]);
  EXPECT_EQ(initial[2], decoded[2]);
  EXPECT_EQ(initial[3], decoded[3]);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(encoding, empty_char_array)
{
  const std::vector<char> initial;
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, make_array_encoder<char_encoder>(initial));
  ASSERT_EQ(0u, encoded.size());
  std::vector<char> decoded;
  auto in = encoded.begin();
  size_t remaining = encoded.size();
  ASSERT_TRUE(decode(in, remaining, make_array_decoder<char_decoder>(decoded)));
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(encoding, network_order_array)
{
  const uint32_t initial[] = {1024, 2048, 4096};
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, make_array_encoder<network_order_encoder<uint32_t>>(initial));
  ASSERT_EQ(12u, encoded.size());
  EXPECT_EQ(0x0, encoded.front());
  std::array<uint32_t, 3> decoded = {};
  auto in = encoded.begin();
  size_t remaining = encoded.size();
  ASSERT_TRUE(decode(in, remaining, make_array_decoder<network_order_decoder<uint32_t>>(decoded)));
  EXPECT_EQ(initial[0], decoded[0]);
  EXPECT_EQ(initial[1], decoded[1]);
  EXPECT_EQ(initial[2], decoded[2]);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

} // namespace nexus::detail
