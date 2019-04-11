#include <nexus/http2/detail/hpack/integer.hpp>
#include <optional>
#include <random>
#include <gtest/gtest.h>

namespace nexus::http2::hpack {

using uint128_t = unsigned __int128;

template <> struct numeric_traits<uint128_t> {
  static constexpr int digits = 128;
  static constexpr bool is_signed = false;
  static constexpr bool is_integer = true;
  static constexpr uint128_t min() {
    return 0;
  }
  static constexpr uint128_t max() {
    constexpr uint128_t ffs = 0xffffffffffffffffllu;
    return (ffs << 64) | ffs;
  }
};

using IntegerTypes_8_16_32_64 = ::testing::Types<
    uint8_t, uint16_t, uint32_t, uint64_t>;
using IntegerTypes_16_32_64 = ::testing::Types<
    uint16_t, uint32_t, uint64_t>;

// C.1.1. Example 1: Encoding 10 Using a 5-Bit Prefix
template <typename T> struct HPACKInteger1 : ::testing::Test {};
TYPED_TEST_SUITE(HPACKInteger1, IntegerTypes_8_16_32_64);

TYPED_TEST(HPACKInteger1, encode)
{
  const TypeParam value = 10u;

  std::vector<uint8_t> encoded;
  auto buf = boost::asio::dynamic_buffer(encoded);

  constexpr uint8_t pad_zeroes = 0;
  ASSERT_EQ(1u, encode_integer<5>(value, pad_zeroes, buf));
  ASSERT_EQ(1u, encoded.size());
  EXPECT_EQ(0b00001010, encoded[0]);

  constexpr uint8_t pad_ones = 0xff;
  ASSERT_EQ(1u, encode_integer<5>(value, pad_ones, buf));
  ASSERT_EQ(2u, encoded.size());
  EXPECT_EQ(0b11101010, encoded[1]);
}

TYPED_TEST(HPACKInteger1, decode)
{
  const uint8_t encoded[] = {
    0b00001010, // padded with zeroes
    0b11101010, // padded with ones
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  TypeParam value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<5>(pos, end, value, padding));
  EXPECT_EQ(10u, value);
  EXPECT_EQ(0b00000000, padding);

  ASSERT_TRUE(decode_integer<5>(pos, end, value, padding));
  EXPECT_EQ(10u, value);
  EXPECT_EQ(0b11100000, padding);
}

// C.1.2.  Example 2: Encoding 1337 Using a 5-Bit Prefix
template <typename T> struct HPACKInteger2 : ::testing::Test {};
TYPED_TEST_SUITE(HPACKInteger2, IntegerTypes_16_32_64);

TYPED_TEST(HPACKInteger2, encode)
{
  const TypeParam value = 1337u;

  std::vector<uint8_t> encoded;
  auto buf = boost::asio::dynamic_buffer(encoded);

  constexpr uint8_t pad_zeroes = 0;
  ASSERT_EQ(3u, encode_integer<5>(value, pad_zeroes, buf));
  ASSERT_EQ(3u, encoded.size());
  EXPECT_EQ(0b00011111, encoded[0]);
  EXPECT_EQ(0b10011010, encoded[1]);
  EXPECT_EQ(0b00001010, encoded[2]);

  constexpr uint8_t pad_ones = 0xff;
  ASSERT_EQ(3u, encode_integer<5>(value, pad_ones, buf));
  ASSERT_EQ(6u, encoded.size());
  EXPECT_EQ(0b11111111, encoded[3]);
  EXPECT_EQ(0b10011010, encoded[4]);
  EXPECT_EQ(0b00001010, encoded[5]);
}

TYPED_TEST(HPACKInteger2, decode)
{
  const uint8_t encoded[] = {
    0b00011111, 0b10011010, 0b00001010, // padded with zeroes
    0b11111111, 0b10011010, 0b00001010, // padded with ones
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  TypeParam value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<5>(pos, end, value, padding));
  EXPECT_EQ(1337u, value);
  EXPECT_EQ(0b00000000, padding);

  ASSERT_TRUE(decode_integer<5>(pos, end, value, padding));
  EXPECT_EQ(1337u, value);
  EXPECT_EQ(0b11100000, padding);
}

// C.1.3.  Example 3: Encoding 42 Starting at an Octet Boundary
template <typename T> struct HPACKInteger3 : ::testing::Test {};
TYPED_TEST_SUITE(HPACKInteger3, IntegerTypes_8_16_32_64);

TYPED_TEST(HPACKInteger3, encode)
{
  const TypeParam value = 42u;

  std::vector<uint8_t> encoded;
  auto buf = boost::asio::dynamic_buffer(encoded);

  constexpr uint8_t pad_zeroes = 0;
  ASSERT_EQ(1u, encode_integer<8>(value, pad_zeroes, buf));
  ASSERT_EQ(1u, encoded.size());
  EXPECT_EQ(0b00101010, encoded[0]);

  constexpr uint8_t pad_ones = 0xff;
  ASSERT_EQ(1u, encode_integer<8>(value, pad_ones, buf));
  ASSERT_EQ(2u, encoded.size());
  EXPECT_EQ(0b00101010, encoded[1]);
}

TYPED_TEST(HPACKInteger3, decode)
{
  const uint8_t encoded[] = {0b00101010};
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  TypeParam value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<8>(pos, end, value, padding));
  EXPECT_EQ(42u, value);
  EXPECT_EQ(0b00000000, padding);
}

template <typename T>
class FuzzingFixture : public ::testing::Test {
  static std::optional<std::default_random_engine> rng;
 protected:
  static T generate_value() {
    return std::uniform_int_distribution(
        std::numeric_limits<T>::min(),
        std::numeric_limits<T>::max())(*rng);
  }

  static void SetUpTestSuite() {
    std::random_device r;
    rng.emplace(r());
  }
  static void TearDownTestSuite() {
    rng.reset();
  }
};
template <typename T> std::optional<std::default_random_engine> FuzzingFixture<T>::rng;

template <typename T> using HPACKFuzz = FuzzingFixture<T>;
TYPED_TEST_SUITE(HPACKFuzz, IntegerTypes_8_16_32_64);

TYPED_TEST(HPACKFuzz, encode_decode_prefix_8)
{
  std::vector<uint8_t> encoded;

  for (int i = 0; i < 10000; i++) {
    const auto value = this->generate_value();
    // encode
    {
      encoded.clear();
      auto buf = boost::asio::dynamic_buffer(encoded);
      const auto len = encode_integer<8>(value, 0, buf);
      encoded.resize(len);
    }
    // decode
    {
      auto buffer = boost::asio::buffer(encoded);
      auto pos = boost::asio::buffers_begin(buffer);
      auto end = boost::asio::buffers_end(buffer);
      TypeParam decoded = 0;
      uint8_t padding = 0;
      EXPECT_TRUE(decode_integer<8>(pos, end, decoded, padding));
      EXPECT_EQ(value, decoded);
    }
  }
}

TYPED_TEST(HPACKFuzz, encode_decode_prefix_7)
{
  std::vector<uint8_t> encoded;

  for (int i = 0; i < 10000; i++) {
    const auto value = this->generate_value();
    // encode
    {
      encoded.clear();
      auto buf = boost::asio::dynamic_buffer(encoded);
      const auto len = encode_integer<7>(value, 0, buf);
      encoded.resize(len);
    }
    // decode
    {
      auto buffer = boost::asio::buffer(encoded);
      auto pos = boost::asio::buffers_begin(buffer);
      auto end = boost::asio::buffers_end(buffer);
      TypeParam decoded = 0;
      uint8_t padding = 0;
      EXPECT_TRUE(decode_integer<7>(pos, end, decoded, padding));
      EXPECT_EQ(value, decoded);
    }
  }
}

TYPED_TEST(HPACKFuzz, encode_decode_prefix_6)
{
  std::vector<uint8_t> encoded;

  for (int i = 0; i < 10000; i++) {
    const auto value = this->generate_value();
    // encode
    {
      encoded.clear();
      auto buf = boost::asio::dynamic_buffer(encoded);
      const auto len = encode_integer<6>(value, 0, buf);
      encoded.resize(len);
    }
    // decode
    {
      auto buffer = boost::asio::buffer(encoded);
      auto pos = boost::asio::buffers_begin(buffer);
      auto end = boost::asio::buffers_end(buffer);
      TypeParam decoded = 0;
      uint8_t padding = 0;
      EXPECT_TRUE(decode_integer<6>(pos, end, decoded, padding));
      EXPECT_EQ(value, decoded);
    }
  }
}

TYPED_TEST(HPACKFuzz, encode_decode_prefix_5)
{
  std::vector<uint8_t> encoded;

  for (int i = 0; i < 10000; i++) {
    const auto value = this->generate_value();
    // encode
    {
      encoded.clear();
      auto buf = boost::asio::dynamic_buffer(encoded);
      const auto len = encode_integer<5>(value, 0, buf);
      encoded.resize(len);
    }
    // decode
    {
      auto buffer = boost::asio::buffer(encoded);
      auto pos = boost::asio::buffers_begin(buffer);
      auto end = boost::asio::buffers_end(buffer);
      TypeParam decoded = 0;
      uint8_t padding = 0;
      EXPECT_TRUE(decode_integer<5>(pos, end, decoded, padding));
      EXPECT_EQ(value, decoded);
    }
  }
}

TYPED_TEST(HPACKFuzz, encode_decode_prefix_4)
{
  std::vector<uint8_t> encoded;

  for (int i = 0; i < 10000; i++) {
    const auto value = this->generate_value();
    // encode
    {
      encoded.clear();
      auto buf = boost::asio::dynamic_buffer(encoded);
      const auto len = encode_integer<4>(value, 0, buf);
      encoded.resize(len);
    }
    // decode
    {
      auto buffer = boost::asio::buffer(encoded);
      auto pos = boost::asio::buffers_begin(buffer);
      auto end = boost::asio::buffers_end(buffer);
      TypeParam decoded = 0;
      uint8_t padding = 0;
      EXPECT_TRUE(decode_integer<4>(pos, end, decoded, padding));
      EXPECT_EQ(value, decoded);
    }
  }
}

TYPED_TEST(HPACKFuzz, encode_decode_prefix_3)
{
  std::vector<uint8_t> encoded;

  for (int i = 0; i < 10000; i++) {
    const auto value = this->generate_value();
    // encode
    {
      encoded.clear();
      auto buf = boost::asio::dynamic_buffer(encoded);
      const auto len = encode_integer<3>(value, 0, buf);
      encoded.resize(len);
    }
    // decode
    {
      auto buffer = boost::asio::buffer(encoded);
      auto pos = boost::asio::buffers_begin(buffer);
      auto end = boost::asio::buffers_end(buffer);
      TypeParam decoded = 0;
      uint8_t padding = 0;
      EXPECT_TRUE(decode_integer<3>(pos, end, decoded, padding));
      EXPECT_EQ(value, decoded);
    }
  }
}

TYPED_TEST(HPACKFuzz, encode_decode_prefix_2)
{
  std::vector<uint8_t> encoded;

  for (int i = 0; i < 10000; i++) {
    const auto value = this->generate_value();
    // encode
    {
      encoded.clear();
      auto buf = boost::asio::dynamic_buffer(encoded);
      const auto len = encode_integer<2>(value, 0, buf);
      encoded.resize(len);
    }
    // decode
    {
      auto buffer = boost::asio::buffer(encoded);
      auto pos = boost::asio::buffers_begin(buffer);
      auto end = boost::asio::buffers_end(buffer);
      TypeParam decoded = 0;
      uint8_t padding = 0;
      EXPECT_TRUE(decode_integer<2>(pos, end, decoded, padding));
      EXPECT_EQ(value, decoded);
    }
  }
}

TYPED_TEST(HPACKFuzz, encode_decode_prefix_1)
{
  std::vector<uint8_t> encoded;

  for (int i = 0; i < 10000; i++) {
    const auto value = this->generate_value();
    // encode
    {
      encoded.clear();
      auto buf = boost::asio::dynamic_buffer(encoded);
      const auto len = encode_integer<1>(value, 0, buf);
      encoded.resize(len);
    }
    // decode
    {
      auto buffer = boost::asio::buffer(encoded);
      auto pos = boost::asio::buffers_begin(buffer);
      auto end = boost::asio::buffers_end(buffer);
      TypeParam decoded = 0;
      uint8_t padding = 0;
      EXPECT_TRUE(decode_integer<1>(pos, end, decoded, padding));
      EXPECT_EQ(value, decoded);
    }
  }
}

TEST(HPACKIntegerOverflow, decode_prefix_8_uint8)
{
  const uint8_t encoded[] = {
    0b11111111, 0b00000000, // 255
    0b11111111, 0b00000001, // 256
    0b11111111, 0b00000001, // 256
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint8_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<8>(pos, end, value, padding));
  EXPECT_EQ(255u, value);
  uint16_t value16 = 0;
  ASSERT_TRUE(decode_integer<8>(pos, end, value16, padding));
  EXPECT_EQ(256u, value16);
  EXPECT_FALSE(decode_integer<8>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_7_uint8)
{
  const uint8_t encoded[] = {
    0b01111111, 0b10000000, 0b00000001, // 255
    0b01111111, 0b10000001, 0b00000001, // 256
    0b01111111, 0b10000001, 0b00000001, // 256
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint8_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<7>(pos, end, value, padding));
  EXPECT_EQ(255u, value);
  uint16_t value16 = 0;
  ASSERT_TRUE(decode_integer<7>(pos, end, value16, padding));
  EXPECT_EQ(256u, value16);
  EXPECT_FALSE(decode_integer<7>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_6_uint8)
{
  const uint8_t encoded[] = {
    0b00111111, 0b11000000, 0b00000001, // 255
    0b00111111, 0b11000001, 0b00000001, // 256
    0b00111111, 0b11000001, 0b00000001, // 256
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint8_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<6>(pos, end, value, padding));
  EXPECT_EQ(255u, value);
  uint16_t value16 = 0;
  ASSERT_TRUE(decode_integer<6>(pos, end, value16, padding));
  EXPECT_EQ(256u, value16);
  EXPECT_FALSE(decode_integer<6>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_5_uint8)
{
  const uint8_t encoded[] = {
    0b00011111, 0b11100000, 0b00000001, // 255
    0b00011111, 0b11100001, 0b00000001, // 256
    0b00011111, 0b11100001, 0b00000001, // 256
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint8_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<5>(pos, end, value, padding));
  EXPECT_EQ(255u, value);
  uint16_t value16 = 0;
  ASSERT_TRUE(decode_integer<5>(pos, end, value16, padding));
  EXPECT_EQ(256u, value16);
  EXPECT_FALSE(decode_integer<5>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_4_uint8)
{
  const uint8_t encoded[] = {
    0b00001111, 0b11110000, 0b00000001, // 255
    0b00001111, 0b11110001, 0b00000001, // 256
    0b00001111, 0b11110001, 0b00000001, // 256
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint8_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<4>(pos, end, value, padding));
  EXPECT_EQ(255u, value);
  uint16_t value16 = 0;
  ASSERT_TRUE(decode_integer<4>(pos, end, value16, padding));
  EXPECT_EQ(256u, value16);
  EXPECT_FALSE(decode_integer<4>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_3_uint8)
{
  const uint8_t encoded[] = {
    0b00000111, 0b11111000, 0b00000001, // 255
    0b00000111, 0b11111001, 0b00000001, // 256
    0b00000111, 0b11111001, 0b00000001, // 256
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint8_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<3>(pos, end, value, padding));
  EXPECT_EQ(255u, value);
  uint16_t value16 = 0;
  ASSERT_TRUE(decode_integer<3>(pos, end, value16, padding));
  EXPECT_EQ(256u, value16);
  EXPECT_FALSE(decode_integer<3>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_2_uint8)
{
  const uint8_t encoded[] = {
    0b00000011, 0b11111100, 0b00000001, // 255
    0b00000011, 0b11111101, 0b00000001, // 256
    0b00000011, 0b11111101, 0b00000001, // 256
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint8_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<2>(pos, end, value, padding));
  EXPECT_EQ(255u, value);
  uint16_t value16 = 0;
  ASSERT_TRUE(decode_integer<2>(pos, end, value16, padding));
  EXPECT_EQ(256u, value16);
  EXPECT_FALSE(decode_integer<2>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_1_uint8)
{
  const uint8_t encoded[] = {
    0b00000001, 0b11111110, 0b00000001, // 255
    0b00000001, 0b11111111, 0b00000001, // 256
    0b00000001, 0b11111111, 0b00000001, // 256
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint8_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<1>(pos, end, value, padding));
  EXPECT_EQ(255u, value);
  uint16_t value16 = 0;
  ASSERT_TRUE(decode_integer<1>(pos, end, value16, padding));
  EXPECT_EQ(256u, value16);
  EXPECT_FALSE(decode_integer<1>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_8_uint16)
{
  const uint8_t encoded[] = {
    0b11111111, 0b10000000, 0b11111110, 0b00000011, // 65535
    0b11111111, 0b10000001, 0b11111110, 0b00000011, // 65536
    0b11111111, 0b10000001, 0b11111110, 0b00000011, // 65536
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint16_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<8>(pos, end, value, padding));
  EXPECT_EQ(65535u, value);
  uint32_t value32 = 0;
  ASSERT_TRUE(decode_integer<8>(pos, end, value32, padding));
  EXPECT_EQ(65536u, value32);
  EXPECT_FALSE(decode_integer<8>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_7_uint16)
{
  const uint8_t encoded[] = {
    0b01111111, 0b10000000, 0b11111111, 0b00000011, // 65535
    0b01111111, 0b10000001, 0b11111111, 0b00000011, // 65536
    0b01111111, 0b10000001, 0b11111111, 0b00000011, // 65536
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint16_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<7>(pos, end, value, padding));
  EXPECT_EQ(65535u, value);
  uint32_t value32 = 0;
  ASSERT_TRUE(decode_integer<7>(pos, end, value32, padding));
  EXPECT_EQ(65536u, value32);
  EXPECT_FALSE(decode_integer<7>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_6_uint16)
{
  const uint8_t encoded[] = {
    0b00111111, 0b11000000, 0b11111111, 0b00000011, // 65535
    0b00111111, 0b11000001, 0b11111111, 0b00000011, // 65536
    0b00111111, 0b11000001, 0b11111111, 0b00000011, // 65536
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint16_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<6>(pos, end, value, padding));
  EXPECT_EQ(65535u, value);
  uint32_t value32 = 0;
  ASSERT_TRUE(decode_integer<6>(pos, end, value32, padding));
  EXPECT_EQ(65536u, value32);
  EXPECT_FALSE(decode_integer<6>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_5_uint16)
{
  const uint8_t encoded[] = {
    0b00011111, 0b11100000, 0b11111111, 0b00000011, // 65535
    0b00011111, 0b11100001, 0b11111111, 0b00000011, // 65536
    0b00011111, 0b11100001, 0b11111111, 0b00000011, // 65536
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint16_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<5>(pos, end, value, padding));
  EXPECT_EQ(65535u, value);
  uint32_t value32 = 0;
  ASSERT_TRUE(decode_integer<5>(pos, end, value32, padding));
  EXPECT_EQ(65536u, value32);
  EXPECT_FALSE(decode_integer<5>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_4_uint16)
{
  const uint8_t encoded[] = {
    0b00001111, 0b11110000, 0b11111111, 0b00000011, // 65535
    0b00001111, 0b11110001, 0b11111111, 0b00000011, // 65536
    0b00001111, 0b11110001, 0b11111111, 0b00000011, // 65536
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint16_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<4>(pos, end, value, padding));
  EXPECT_EQ(65535u, value);
  uint32_t value32 = 0;
  ASSERT_TRUE(decode_integer<4>(pos, end, value32, padding));
  EXPECT_EQ(65536u, value32);
  EXPECT_FALSE(decode_integer<4>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_3_uint16)
{
  const uint8_t encoded[] = {
    0b00000111, 0b11111000, 0b11111111, 0b00000011, // 65535
    0b00000111, 0b11111001, 0b11111111, 0b00000011, // 65536
    0b00000111, 0b11111001, 0b11111111, 0b00000011, // 65536
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint16_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<3>(pos, end, value, padding));
  EXPECT_EQ(65535u, value);
  uint32_t value32 = 0;
  ASSERT_TRUE(decode_integer<3>(pos, end, value32, padding));
  EXPECT_EQ(65536u, value32);
  EXPECT_FALSE(decode_integer<3>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_2_uint16)
{
  const uint8_t encoded[] = {
    0b00000011, 0b11111100, 0b11111111, 0b00000011, // 65535
    0b00000011, 0b11111101, 0b11111111, 0b00000011, // 65536
    0b00000011, 0b11111101, 0b11111111, 0b00000011, // 65536
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint16_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<2>(pos, end, value, padding));
  EXPECT_EQ(65535u, value);
  uint32_t value32 = 0;
  ASSERT_TRUE(decode_integer<2>(pos, end, value32, padding));
  EXPECT_EQ(65536u, value32);
  EXPECT_FALSE(decode_integer<2>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_1_uint16)
{
  const uint8_t encoded[] = {
    0b00000001, 0b11111110, 0b11111111, 0b00000011, // 65535
    0b00000001, 0b11111111, 0b11111111, 0b00000011, // 65536
    0b00000001, 0b11111111, 0b11111111, 0b00000011, // 65536
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint16_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<1>(pos, end, value, padding));
  EXPECT_EQ(65535u, value);
  uint32_t value32 = 0;
  ASSERT_TRUE(decode_integer<1>(pos, end, value32, padding));
  EXPECT_EQ(65536u, value32);
  EXPECT_FALSE(decode_integer<1>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_8_uint32)
{
  const uint8_t encoded[] = {
    0b11111111, 0b10000000, 0b11111110, 0b11111111, 0b11111111, 0b00001111, // 4294967295
    0b11111111, 0b10000001, 0b11111110, 0b11111111, 0b11111111, 0b00001111, // 4294967296
    0b11111111, 0b10000001, 0b11111110, 0b11111111, 0b11111111, 0b00001111, // 4294967296
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint32_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<8>(pos, end, value, padding));
  EXPECT_EQ(4294967295u, value);
  uint64_t value64 = 0;
  ASSERT_TRUE(decode_integer<8>(pos, end, value64, padding));
  EXPECT_EQ(4294967296u, value64);
  EXPECT_FALSE(decode_integer<8>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_7_uint32)
{
  const uint8_t encoded[] = {
    0b01111111, 0b10000000, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967295
    0b01111111, 0b10000001, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967296
    0b01111111, 0b10000001, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967296
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint32_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<7>(pos, end, value, padding));
  EXPECT_EQ(4294967295u, value);
  uint64_t value64 = 0;
  ASSERT_TRUE(decode_integer<7>(pos, end, value64, padding));
  EXPECT_EQ(4294967296u, value64);
  EXPECT_FALSE(decode_integer<7>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_6_uint32)
{
  const uint8_t encoded[] = {
    0b00111111, 0b11000000, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967295
    0b00111111, 0b11000001, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967296
    0b00111111, 0b11000001, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967296
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint32_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<6>(pos, end, value, padding));
  EXPECT_EQ(4294967295u, value);
  uint64_t value64 = 0;
  ASSERT_TRUE(decode_integer<6>(pos, end, value64, padding));
  EXPECT_EQ(4294967296u, value64);
  EXPECT_FALSE(decode_integer<6>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_5_uint32)
{
  const uint8_t encoded[] = {
    0b00011111, 0b11100000, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967295
    0b00011111, 0b11100001, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967296
    0b00011111, 0b11100001, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967296
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint32_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<5>(pos, end, value, padding));
  EXPECT_EQ(4294967295u, value);
  uint64_t value64 = 0;
  ASSERT_TRUE(decode_integer<5>(pos, end, value64, padding));
  EXPECT_EQ(4294967296u, value64);
  EXPECT_FALSE(decode_integer<5>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_4_uint32)
{
  const uint8_t encoded[] = {
    0b00001111, 0b11110000, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967295
    0b00001111, 0b11110001, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967296
    0b00001111, 0b11110001, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967296
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint32_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<4>(pos, end, value, padding));
  EXPECT_EQ(4294967295u, value);
  uint64_t value64 = 0;
  ASSERT_TRUE(decode_integer<4>(pos, end, value64, padding));
  EXPECT_EQ(4294967296u, value64);
  EXPECT_FALSE(decode_integer<4>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_3_uint32)
{
  const uint8_t encoded[] = {
    0b00000111, 0b11111000, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967295
    0b00000111, 0b11111001, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967296
    0b00000111, 0b11111001, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967296
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint32_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<3>(pos, end, value, padding));
  EXPECT_EQ(4294967295u, value);
  uint64_t value64 = 0;
  ASSERT_TRUE(decode_integer<3>(pos, end, value64, padding));
  EXPECT_EQ(4294967296u, value64);
  EXPECT_FALSE(decode_integer<3>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_2_uint32)
{
  const uint8_t encoded[] = {
    0b00000011, 0b11111100, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967295
    0b00000011, 0b11111101, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967296
    0b00000011, 0b11111101, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967296
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint32_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<2>(pos, end, value, padding));
  EXPECT_EQ(4294967295u, value);
  uint64_t value64 = 0;
  ASSERT_TRUE(decode_integer<2>(pos, end, value64, padding));
  EXPECT_EQ(4294967296u, value64);
  EXPECT_FALSE(decode_integer<2>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_1_uint32)
{
  const uint8_t encoded[] = {
    0b00000001, 0b11111110, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967295
    0b00000001, 0b11111111, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967296
    0b00000001, 0b11111111, 0b11111111, 0b11111111, 0b11111111, 0b00001111, // 4294967296
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint32_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<1>(pos, end, value, padding));
  EXPECT_EQ(4294967295u, value);
  uint64_t value64 = 0;
  ASSERT_TRUE(decode_integer<1>(pos, end, value64, padding));
  EXPECT_EQ(4294967296u, value64);
  EXPECT_FALSE(decode_integer<1>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_8_uint64)
{
  const uint8_t encoded[] = {
    // 0xffff'ffff'ffff'ffff
    0b11111111, 0b10000000, 0b11111110, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
    // 0x1'0000'0000'0000'0000
    0b11111111, 0b10000001, 0b11111110, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
    // 0x1'0000'0000'0000'0000
    0b11111111, 0b10000001, 0b11111110, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint64_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<8>(pos, end, value, padding));
  EXPECT_EQ(0xffffffffffffffff, value);
  uint128_t value128 = 0;
  ASSERT_TRUE(decode_integer<8>(pos, end, value128, padding));
  EXPECT_EQ(static_cast<uint128_t>(1) << 64, value128);
  EXPECT_FALSE(decode_integer<8>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_7_uint64)
{
  const uint8_t encoded[] = {
    // 0xffff'ffff'ffff'ffff
    0b01111111, 0b10000000, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
    // 0x1'0000'0000'0000'0000
    0b01111111, 0b10000001, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
    // 0x1'0000'0000'0000'0000
    0b01111111, 0b10000001, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint64_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<7>(pos, end, value, padding));
  EXPECT_EQ(0xffffffffffffffff, value);
  uint128_t value128 = 0;
  ASSERT_TRUE(decode_integer<7>(pos, end, value128, padding));
  EXPECT_EQ(static_cast<uint128_t>(1) << 64, value128);
  EXPECT_FALSE(decode_integer<7>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_6_uint64)
{
  const uint8_t encoded[] = {
    // 0xffff'ffff'ffff'ffff
    0b00111111, 0b11000000, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
    // 0x1'0000'0000'0000'0000
    0b00111111, 0b11000001, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
    // 0x1'0000'0000'0000'0000
    0b00111111, 0b11000001, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint64_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<6>(pos, end, value, padding));
  EXPECT_EQ(0xffffffffffffffff, value);
  uint128_t value128 = 0;
  ASSERT_TRUE(decode_integer<6>(pos, end, value128, padding));
  EXPECT_EQ(static_cast<uint128_t>(1) << 64, value128);
  EXPECT_FALSE(decode_integer<6>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_5_uint64)
{
  const uint8_t encoded[] = {
    // 0xffff'ffff'ffff'ffff
    0b00011111, 0b11100000, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
    // 0x1'0000'0000'0000'0000
    0b00011111, 0b11100001, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
    // 0x1'0000'0000'0000'0000
    0b00011111, 0b11100001, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint64_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<5>(pos, end, value, padding));
  EXPECT_EQ(0xffffffffffffffff, value);
  uint128_t value128 = 0;
  ASSERT_TRUE(decode_integer<5>(pos, end, value128, padding));
  EXPECT_EQ(static_cast<uint128_t>(1) << 64, value128);
  EXPECT_FALSE(decode_integer<5>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_4_uint64)
{
  const uint8_t encoded[] = {
    // 0xffff'ffff'ffff'ffff
    0b00001111, 0b11110000, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
    // 0x1'0000'0000'0000'0000
    0b00001111, 0b11110001, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
    // 0x1'0000'0000'0000'0000
    0b00001111, 0b11110001, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint64_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<4>(pos, end, value, padding));
  EXPECT_EQ(0xffffffffffffffff, value);
  uint128_t value128 = 0;
  ASSERT_TRUE(decode_integer<4>(pos, end, value128, padding));
  EXPECT_EQ(static_cast<uint128_t>(1) << 64, value128);
  EXPECT_FALSE(decode_integer<4>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_3_uint64)
{
  const uint8_t encoded[] = {
    // 0xffff'ffff'ffff'ffff
    0b00000111, 0b11111000, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
    // 0x1'0000'0000'0000'0000
    0b00000111, 0b11111001, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
    // 0x1'0000'0000'0000'0000
    0b00000111, 0b11111001, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint64_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<3>(pos, end, value, padding));
  EXPECT_EQ(0xffffffffffffffff, value);
  uint128_t value128 = 0;
  ASSERT_TRUE(decode_integer<3>(pos, end, value128, padding));
  EXPECT_EQ(static_cast<uint128_t>(1) << 64, value128);
  EXPECT_FALSE(decode_integer<3>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_2_uint64)
{
  const uint8_t encoded[] = {
    // 0xffff'ffff'ffff'ffff
    0b00000011, 0b11111100, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
    // 0x1'0000'0000'0000'0000
    0b00000011, 0b11111101, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
    // 0x1'0000'0000'0000'0000
    0b00000011, 0b11111101, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint64_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<2>(pos, end, value, padding));
  EXPECT_EQ(0xffffffffffffffff, value);
  uint128_t value128 = 0;
  ASSERT_TRUE(decode_integer<2>(pos, end, value128, padding));
  EXPECT_EQ(static_cast<uint128_t>(1) << 64, value128);
  EXPECT_FALSE(decode_integer<2>(pos, end, value, padding));
}

TEST(HPACKIntegerOverflow, decode_prefix_1_uint64)
{
  const uint8_t encoded[] = {
    // 0xffff'ffff'ffff'ffff
    0b00000001, 0b11111110, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
    // 0x1'0000'0000'0000'0000
    0b00000001, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
    // 0x1'0000'0000'0000'0000
    0b00000001, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b11111111, 0b11111111,
    0b11111111, 0b11111111, 0b00000001,
  };
  auto buffer = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buffer);
  auto end = boost::asio::buffers_end(buffer);

  uint64_t value = 0;
  uint8_t padding = 0;
  ASSERT_TRUE(decode_integer<1>(pos, end, value, padding));
  EXPECT_EQ(0xffffffffffffffff, value);
  uint128_t value128 = 0;
  ASSERT_TRUE(decode_integer<1>(pos, end, value128, padding));
  EXPECT_EQ(static_cast<uint128_t>(1) << 64, value128);
  EXPECT_FALSE(decode_integer<1>(pos, end, value, padding));
}

} // namespace nexus::http2::hpack
