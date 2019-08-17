#include <nexus/quic/detail/encoding/varint.hpp>
#include <gtest/gtest.h>

namespace nexus::quic::detail {

TEST(quic_encoding, varint_length)
{
  EXPECT_EQ(1, varint_length(0x00));
  EXPECT_EQ(1, varint_length(0x3f));
  EXPECT_EQ(2, varint_length(0x40));
  EXPECT_EQ(2, varint_length(0x3fff));
  EXPECT_EQ(4, varint_length(0x4000));
  EXPECT_EQ(4, varint_length(0x3fffffff));
  EXPECT_EQ(8, varint_length(0x40000000));
  EXPECT_EQ(8, varint_length(varint_max));

  EXPECT_EQ(0b00, varint_length_mask(1));
  EXPECT_EQ(0b01, varint_length_mask(2));
  EXPECT_EQ(0b10, varint_length_mask(4));
  EXPECT_EQ(0b11, varint_length_mask(8));
}

TEST(quic_encoding, varint_8)
{
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, varint_encoder{0x3f});
  ASSERT_EQ(1, encoded.size());
  EXPECT_EQ(0x3f, encoded.front());

  varint_t decoded = 0;
  size_t remaining = encoded.size();
  auto in = encoded.begin();
  ASSERT_TRUE(decode(in, remaining, varint_decoder{decoded}));
  EXPECT_EQ(0x3f, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(quic_encoding, varint_16)
{
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, varint_encoder{0x3fff});
  ASSERT_EQ(2, encoded.size());
  EXPECT_EQ(0x7f, encoded.front());
  EXPECT_EQ(0xff, encoded.back());

  varint_t decoded = 0;
  size_t remaining = encoded.size();
  auto in = encoded.begin();
  ASSERT_TRUE(decode(in, remaining, varint_decoder{decoded}));
  EXPECT_EQ(0x3fff, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(quic_encoding, varint_32)
{
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, varint_encoder{0x3fffffff});
  ASSERT_EQ(4, encoded.size());
  EXPECT_EQ(0xbf, encoded.front());
  EXPECT_EQ(0xff, encoded.back());

  varint_t decoded = 0;
  size_t remaining = encoded.size();
  auto in = encoded.begin();
  ASSERT_TRUE(decode(in, remaining, varint_decoder{decoded}));
  EXPECT_EQ(0x3fffffff, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

TEST(quic_encoding, varint_64)
{
  std::vector<uint8_t> encoded;
  std::back_insert_iterator out{encoded};
  encode(out, varint_encoder{varint_max});
  ASSERT_EQ(8, encoded.size());
  EXPECT_EQ(0xff, encoded.front());
  EXPECT_EQ(0xff, encoded.back());

  varint_t decoded = 0;
  size_t remaining = encoded.size();
  auto in = encoded.begin();
  ASSERT_TRUE(decode(in, remaining, varint_decoder{decoded}));
  EXPECT_EQ(varint_max, decoded);
  EXPECT_EQ(encoded.end(), in);
  EXPECT_EQ(0, remaining);
}

} // namespace nexus::quic::detail
