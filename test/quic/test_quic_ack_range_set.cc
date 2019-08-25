#include <nexus/quic/detail/ack_range_set.hpp>
#include <nexus/quic/detail/packet.hpp>
#include <gtest/gtest.h>

namespace nexus::quic::detail {

std::ostream& operator<<(std::ostream& out, const ack_range& r) {
  return out << '{' << r.gap << ',' << r.ack << '}';
}
bool operator==(const ack_range& lhs, const ack_range& rhs) {
  return lhs.gap == rhs.gap && lhs.ack == rhs.ack;
}
bool operator!=(const ack_range& lhs, const ack_range& rhs) {
  return lhs.gap != rhs.gap || lhs.ack != rhs.ack;
}

TEST(quic, ack_range_set)
{
  ack_range_set<packet_number_t> ranges;
  ranges.insert(123, 4); // {123,124,125,126}
  EXPECT_EQ(123, ranges.lower());
  EXPECT_EQ(127, ranges.upper());
  ranges.insert(133); // {133}
  EXPECT_EQ(123, ranges.lower());
  EXPECT_EQ(134, ranges.upper());
  auto i = ranges.begin();
  ASSERT_NE(i, ranges.end());
  EXPECT_EQ(123, i->gap);
  EXPECT_EQ(4, i->ack);
  ASSERT_NE(ranges.end(), ++i);
  EXPECT_EQ(6, i->gap);
  EXPECT_EQ(1, i->ack);
  EXPECT_EQ(ranges.end(), ++i);
}

TEST(quic, ack_range_iterator_insert)
{
  ack_range_set<packet_number_t> ranges;
  const ack_range input[] = {{0, 1}, {4, 2}, {2, 1}};
  ranges.insert(0, std::begin(input), std::end(input));
  EXPECT_EQ(0, ranges.lower());
  EXPECT_EQ(10, ranges.upper());
  auto i = ranges.begin();
  ASSERT_NE(i, ranges.end());
  EXPECT_EQ(0, i->gap);
  EXPECT_EQ(1, i->ack);
  EXPECT_EQ(1, (i++)->ack);
  ASSERT_NE(i, ranges.end());
  EXPECT_EQ(4, i->gap);
  EXPECT_EQ(2, i->ack);
  EXPECT_EQ(1, (++i)->ack);
  ASSERT_NE(i, ranges.end());
  EXPECT_EQ(2, i->gap);
  EXPECT_EQ(1, i->ack);
  EXPECT_EQ(ranges.end(), ++i);
}

TEST(quic, ack_range_iterator_insert_reverse)
{
  ack_range_set<packet_number_t> ranges;
  const ack_range input[] = {{0, 1}, {4, 2}, {2, 1}};
  ranges.insert_reverse(10, std::rbegin(input), std::rend(input));
  EXPECT_EQ(0, ranges.lower());
  EXPECT_EQ(10, ranges.upper());
  auto i = ranges.begin();
  ASSERT_NE(i, ranges.end());
  EXPECT_EQ(0, i->gap);
  EXPECT_EQ(1, i->ack);
  ASSERT_NE(ranges.end(), ++i);
  EXPECT_EQ(4, i->gap);
  EXPECT_EQ(2, i->ack);
  ASSERT_NE(ranges.end(), ++i);
  EXPECT_EQ(2, i->gap);
  EXPECT_EQ(1, i->ack);
  EXPECT_EQ(ranges.end(), ++i);
}

TEST(quic, ack_range_iterator_subtract)
{
  const ack_range add[] = {{0, 8}, {8, 8}, {1, 8}}; // [0,8) [16,24) [25,33)
  const ack_range subtract[] = {{1, 2}, {19, 8}}; // [1,3) [22,30)
  const ack_range result[] = {{0, 1}, {2, 5}, {8, 6}, {8, 3}}; // [0,1) [3,8) [16,22) [30,33)

  ack_range_set<packet_number_t> ranges;
  ranges.insert(0, std::begin(add), std::end(add));
  ASSERT_EQ(0, ranges.lower());
  ASSERT_EQ(33, ranges.upper());

  ranges.subtract(0, std::begin(subtract), std::end(subtract));
  ASSERT_EQ(0, ranges.lower());
  ASSERT_EQ(33, ranges.upper());
  auto i = ranges.begin();
  ASSERT_NE(i, ranges.end());
  EXPECT_EQ(result[0], *i);
  ASSERT_NE(ranges.end(), ++i);
  EXPECT_EQ(result[1], *i);
  ASSERT_NE(ranges.end(), ++i);
  EXPECT_EQ(result[2], *i);
  ASSERT_NE(ranges.end(), ++i);
  EXPECT_EQ(result[3], *i);
  EXPECT_EQ(ranges.end(), ++i);
}

TEST(quic, ack_range_iterator_subtract_reverse)
{
  const ack_range add[] = {{0, 8}, {8, 8}, {1, 8}}; // [0,8) [16,24) [25,33)
  const ack_range subtract[] = {{1, 2}, {19, 8}}; // [1,3) [22,30)
  const ack_range result[] = {{0, 1}, {2, 5}, {8, 6}, {8, 3}}; // [0,1) [3,8) [16,22) [30,33)

  ack_range_set<packet_number_t> ranges;
  ranges.insert(0, std::begin(add), std::end(add));
  ASSERT_EQ(0, ranges.lower());
  ASSERT_EQ(33, ranges.upper());

  ranges.subtract_reverse(30, std::rbegin(subtract), std::rend(subtract));
  ASSERT_EQ(0, ranges.lower());
  ASSERT_EQ(33, ranges.upper());
  auto i = ranges.begin();
  ASSERT_NE(i, ranges.end());
  EXPECT_EQ(result[0], *i);
  ASSERT_NE(ranges.end(), ++i);
  EXPECT_EQ(result[1], *i);
  ASSERT_NE(ranges.end(), ++i);
  EXPECT_EQ(result[2], *i);
  ASSERT_NE(ranges.end(), ++i);
  EXPECT_EQ(result[3], *i);
  EXPECT_EQ(ranges.end(), ++i);
}

} // namespace nexus::quic::detail
