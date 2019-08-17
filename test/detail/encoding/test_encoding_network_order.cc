#include <nexus/detail/encoding/network_order.hpp>
#include <vector>
#include <gtest/gtest.h>

namespace nexus::detail {

TEST(encoding, network_order_uint8)
{
  const uint8_t initial = 0x10;
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, network_order_encoder{initial});
  ASSERT_EQ(1u, encoded.size());
  EXPECT_EQ(0x10, encoded.front());
  uint8_t decoded = 0xff;
  auto in = encoded.begin();
  size_t remaining = encoded.size();
  ASSERT_TRUE(decode(in, remaining, network_order_decoder{decoded}));
  EXPECT_EQ(initial, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(encoding, network_order_uint8_8)
{
  const uint8_t initial = 0x10;
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, network_order_encoder{initial, 1});
  ASSERT_EQ(1u, encoded.size());
  EXPECT_EQ(0x10, encoded.front());
  uint8_t decoded = 0xff;
  auto in = encoded.begin();
  size_t remaining = encoded.size();
  ASSERT_TRUE(decode(in, remaining, network_order_decoder{decoded, 1}));
  EXPECT_EQ(initial, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(encoding, network_order_uint16)
{
  const uint16_t initial = 0x1020;
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, network_order_encoder{initial});
  ASSERT_EQ(2u, encoded.size());
  EXPECT_EQ(0x10, encoded.front());
  EXPECT_EQ(0x20, encoded.back());
  uint16_t decoded = 0xffff;
  auto in = encoded.begin();
  size_t remaining = encoded.size();
  ASSERT_TRUE(decode(in, remaining, network_order_decoder{decoded}));
  EXPECT_EQ(initial, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(encoding, network_order_uint16_8)
{
  const uint16_t initial = 0x1020;
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, network_order_encoder{initial, 1});
  ASSERT_EQ(1u, encoded.size());
  EXPECT_EQ(0x20, encoded.front());
  uint16_t decoded = 0xffff;
  auto in = encoded.begin();
  size_t remaining = encoded.size();
  ASSERT_TRUE(decode(in, remaining, network_order_decoder{decoded, 1}));
  EXPECT_EQ(0x20, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(encoding, network_order_uint16_16)
{
  const uint16_t initial = 0x1020;
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, network_order_encoder{initial, 2});
  ASSERT_EQ(2u, encoded.size());
  EXPECT_EQ(0x10, encoded.front());
  EXPECT_EQ(0x20, encoded.back());
  uint16_t decoded = 0xffff;
  auto in = encoded.begin();
  size_t remaining = encoded.size();
  ASSERT_TRUE(decode(in, remaining, network_order_decoder{decoded, 2}));
  EXPECT_EQ(initial, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(encoding, network_order_uint32)
{
  const uint32_t initial = 0x10203040;
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, network_order_encoder{initial});
  ASSERT_EQ(4u, encoded.size());
  EXPECT_EQ(0x10, encoded.front());
  uint32_t decoded = 0xffffffff;
  auto in = encoded.begin();
  size_t remaining = encoded.size();
  ASSERT_TRUE(decode(in, remaining, network_order_decoder{decoded}));
  EXPECT_EQ(initial, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(encoding, network_order_uint32_8)
{
  const uint32_t initial = 0x10203040;
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, network_order_encoder{initial, 1});
  ASSERT_EQ(1u, encoded.size());
  EXPECT_EQ(0x40, encoded.front());
  uint32_t decoded = 0xffffffff;
  auto in = encoded.begin();
  size_t remaining = encoded.size();
  ASSERT_TRUE(decode(in, remaining, network_order_decoder{decoded, 1}));
  EXPECT_EQ(0x40, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(encoding, network_order_uint32_16)
{
  const uint32_t initial = 0x10203040;
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, network_order_encoder{initial, 2});
  ASSERT_EQ(2u, encoded.size());
  EXPECT_EQ(0x30, encoded.front());
  EXPECT_EQ(0x40, encoded.back());
  uint32_t decoded = 0xffffffff;
  auto in = encoded.begin();
  size_t remaining = encoded.size();
  ASSERT_TRUE(decode(in, remaining, network_order_decoder{decoded, 2}));
  EXPECT_EQ(0x3040, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(encoding, network_order_uint32_24)
{
  const uint32_t initial = 0x10203040;
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, network_order_encoder{initial, 3});
  ASSERT_EQ(3u, encoded.size());
  EXPECT_EQ(0x20, encoded.front());
  EXPECT_EQ(0x40, encoded.back());
  uint32_t decoded = 0xffffffff;
  auto in = encoded.begin();
  size_t remaining = encoded.size();
  ASSERT_TRUE(decode(in, remaining, network_order_decoder{decoded, 3}));
  EXPECT_EQ(0x203040, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(encoding, network_order_uint32_32)
{
  const uint32_t initial = 0x10203040;
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, network_order_encoder{initial, 4});
  ASSERT_EQ(4u, encoded.size());
  EXPECT_EQ(0x10, encoded.front());
  EXPECT_EQ(0x40, encoded.back());
  uint32_t decoded = 0xffffffff;
  auto in = encoded.begin();
  size_t remaining = encoded.size();
  ASSERT_TRUE(decode(in, remaining, network_order_decoder{decoded, 4}));
  EXPECT_EQ(initial, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(encoding, network_order_uint64)
{
  const uint64_t initial = 0x1020304050607080;
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, network_order_encoder{initial});
  ASSERT_EQ(8u, encoded.size());
  EXPECT_EQ(0x10, encoded.front());
  EXPECT_EQ(0x80, encoded.back());
  uint64_t decoded = 0xffffffffffffffff;
  size_t remaining = encoded.size();
  auto in = encoded.begin();
  ASSERT_TRUE(decode(in, remaining, network_order_decoder{decoded}));
  EXPECT_EQ(initial, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(encoding, network_order_uint64_8)
{
  const uint64_t initial = 0x1020304050607080;
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, network_order_encoder{initial, 1});
  ASSERT_EQ(1u, encoded.size());
  EXPECT_EQ(0x80, encoded.front());
  uint64_t decoded = 0xffffffffffffffff;
  size_t remaining = encoded.size();
  auto in = encoded.begin();
  ASSERT_TRUE(decode(in, remaining, network_order_decoder{decoded, 1}));
  EXPECT_EQ(0x80, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(encoding, network_order_uint64_16)
{
  const uint64_t initial = 0x1020304050607080;
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, network_order_encoder{initial, 2});
  ASSERT_EQ(2u, encoded.size());
  EXPECT_EQ(0x70, encoded.front());
  EXPECT_EQ(0x80, encoded.back());
  uint64_t decoded = 0xffffffffffffffff;
  size_t remaining = encoded.size();
  auto in = encoded.begin();
  ASSERT_TRUE(decode(in, remaining, network_order_decoder{decoded, 2}));
  EXPECT_EQ(0x7080, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(encoding, network_order_uint64_24)
{
  const uint64_t initial = 0x1020304050607080;
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, network_order_encoder{initial, 3});
  ASSERT_EQ(3u, encoded.size());
  EXPECT_EQ(0x60, encoded.front());
  EXPECT_EQ(0x80, encoded.back());
  uint64_t decoded = 0xffffffffffffffff;
  size_t remaining = encoded.size();
  auto in = encoded.begin();
  ASSERT_TRUE(decode(in, remaining, network_order_decoder{decoded, 3}));
  EXPECT_EQ(0x607080, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(encoding, network_order_uint64_32)
{
  const uint64_t initial = 0x1020304050607080;
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, network_order_encoder{initial, 4});
  ASSERT_EQ(4u, encoded.size());
  EXPECT_EQ(0x50, encoded.front());
  EXPECT_EQ(0x80, encoded.back());
  uint64_t decoded = 0xffffffffffffffff;
  size_t remaining = encoded.size();
  auto in = encoded.begin();
  ASSERT_TRUE(decode(in, remaining, network_order_decoder{decoded, 4}));
  EXPECT_EQ(0x50607080, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(encoding, network_order_uint64_40)
{
  const uint64_t initial = 0x1020304050607080;
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, network_order_encoder{initial, 5});
  ASSERT_EQ(5u, encoded.size());
  EXPECT_EQ(0x40, encoded.front());
  EXPECT_EQ(0x80, encoded.back());
  uint64_t decoded = 0xffffffffffffffff;
  size_t remaining = encoded.size();
  auto in = encoded.begin();
  ASSERT_TRUE(decode(in, remaining, network_order_decoder{decoded, 5}));
  EXPECT_EQ(0x4050607080, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(encoding, network_order_uint64_48)
{
  const uint64_t initial = 0x1020304050607080;
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, network_order_encoder{initial, 6});
  ASSERT_EQ(6u, encoded.size());
  EXPECT_EQ(0x30, encoded.front());
  EXPECT_EQ(0x80, encoded.back());
  uint64_t decoded = 0xffffffffffffffff;
  size_t remaining = encoded.size();
  auto in = encoded.begin();
  ASSERT_TRUE(decode(in, remaining, network_order_decoder{decoded, 6}));
  EXPECT_EQ(0x304050607080, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(encoding, network_order_uint64_56)
{
  const uint64_t initial = 0x1020304050607080;
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, network_order_encoder{initial, 7});
  ASSERT_EQ(7u, encoded.size());
  EXPECT_EQ(0x20, encoded.front());
  EXPECT_EQ(0x80, encoded.back());
  uint64_t decoded = 0xffffffffffffffff;
  size_t remaining = encoded.size();
  auto in = encoded.begin();
  ASSERT_TRUE(decode(in, remaining, network_order_decoder{decoded, 7}));
  EXPECT_EQ(0x20304050607080, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(encoding, network_order_uint64_64)
{
  const uint64_t initial = 0x1020304050607080;
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, network_order_encoder{initial, 8});
  ASSERT_EQ(8u, encoded.size());
  EXPECT_EQ(0x10, encoded.front());
  EXPECT_EQ(0x80, encoded.back());
  uint64_t decoded = 0xffffffffffffffff;
  size_t remaining = encoded.size();
  auto in = encoded.begin();
  ASSERT_TRUE(decode(in, remaining, network_order_decoder{decoded, 8}));
  EXPECT_EQ(initial, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

} // namespace nexus::detail
