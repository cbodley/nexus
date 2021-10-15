#include <nexus/quic/connection_id.hpp>
#include <gtest/gtest.h>

namespace nexus::quic {

using value_type = connection_id::value_type;

template <size_t Size>
using array_type = std::array<value_type, Size>;

template <size_t NewSize, size_t Size>
constexpr auto resize(const std::array<unsigned char, Size>& data)
    -> std::array<unsigned char, NewSize>
{
  auto result = array_type<NewSize>{};
  constexpr auto count = std::min(NewSize, Size);
  for (size_t i = 0; i < count; i++) {
    result[i] = data[i];
  }
  return result;
}

constexpr array_type<6> short_id{
  'a','b','c','d','e','f'
};
constexpr array_type<26> long_id{
  'a','b','c','d','e','f','g','h','i','j','k','l','m',
  'n','o','p','q','r','s','t','u','v','w','x','y','z'
};

constexpr auto long_id19 = resize<19>(long_id);
constexpr auto long_id20 = resize<20>(long_id);

// array comparisons
template <size_t Size>
inline bool operator==(const value_type (&l)[Size], const connection_id& r) {
  return Size == r.size() && std::equal(std::begin(l), std::end(l), r.begin());
}
template <size_t Size>
inline bool operator==(const connection_id& l, const value_type (&r)[Size]) {
  return l.size() == Size && std::equal(l.begin(), l.end(), std::begin(r));
}
template <size_t Size>
inline bool operator!=(const value_type (&l)[Size], const connection_id& r) {
  return Size != r.size() || !std::equal(std::begin(l), std::end(l), r.begin());
}
template <size_t Size>
inline bool operator!=(const connection_id& l, const value_type (&r)[Size]) {
  return l.size() != Size || !std::equal(l.begin(), l.end(), std::begin(r));
}

// std::array comparisons
template <size_t Size>
inline bool operator==(const array_type<Size>& l, const connection_id& r) {
  return l.size() == r.size() && std::equal(l.begin(), l.end(), r.begin());
}
template <size_t Size>
inline bool operator==(const connection_id& l, const array_type<Size>& r) {
  return l.size() == r.size() && std::equal(l.begin(), l.end(), r.begin());
}
template <size_t Size>
inline bool operator!=(const array_type<Size>& l, const connection_id& r) {
  return l.size() != r.size() || !std::equal(l.begin(), l.end(), r.begin());
}
template <size_t Size>
inline bool operator!=(const connection_id& l, const array_type<Size>& r) {
  return l.size() != r.size() || !std::equal(l.begin(), l.end(), r.begin());
}

TEST(connection_id, construct)
{
  constexpr connection_id id1;
  EXPECT_TRUE(id1.empty());
  EXPECT_EQ(0, id1.size());
  EXPECT_EQ(id1.begin(), id1.end());
  EXPECT_EQ(id1.rbegin(), id1.rend());

  constexpr unsigned char arr[] = {'a','b','c','d'};
  constexpr auto id2 = connection_id{arr};
  EXPECT_FALSE(id2.empty());
  EXPECT_EQ(sizeof(arr), id2.size());
  EXPECT_EQ(arr, id2);

  constexpr auto id3 = connection_id{resize<16>(long_id)};
  EXPECT_FALSE(id3.empty());
  EXPECT_EQ(16, id3.size());
  EXPECT_EQ(resize<16>(long_id), id3);

  constexpr auto id4 = connection_id{long_id.data(), 12};
  EXPECT_FALSE(id4.empty());
  EXPECT_EQ(12, id4.size());
  EXPECT_EQ(resize<12>(long_id), id4);

  constexpr auto id5 = connection_id{{'a','b','c','d'}};
  EXPECT_FALSE(id5.empty());
  EXPECT_EQ(4, id5.size());
  EXPECT_EQ(arr, id5);
}

TEST(connection_id, resize)
{
  connection_id id1;
  EXPECT_EQ(0, std::distance(id1.begin(), id1.end()));
  EXPECT_EQ(0, std::distance(id1.rbegin(), id1.rend()));
  id1.resize(12);
  EXPECT_EQ(12, id1.size());
  EXPECT_EQ(12, std::distance(id1.begin(), id1.end()));
  EXPECT_EQ(12, std::distance(id1.rbegin(), id1.rend()));

  auto id2 = connection_id{long_id20};
  EXPECT_EQ(long_id20, id2);
  EXPECT_NE(long_id19, id2);
  id2.resize(19);
  EXPECT_EQ(19, std::distance(id2.begin(), id2.end()));
  EXPECT_EQ(19, std::distance(id2.rbegin(), id2.rend()));
  EXPECT_EQ(long_id19, id2);
  EXPECT_NE(long_id20, id2);
  id2.resize(0);
  EXPECT_TRUE(id2.empty());
  EXPECT_EQ(0, std::distance(id2.begin(), id2.end()));
  EXPECT_EQ(0, std::distance(id2.rbegin(), id2.rend()));
}

constexpr array_type<1> a{'a'};
constexpr array_type<2> aa{'a','a'};
constexpr array_type<1> b{'b'};

TEST(connection_id, eq)
{
  EXPECT_EQ(connection_id(), connection_id());
  EXPECT_EQ(connection_id(a), connection_id(a));
  EXPECT_EQ(connection_id(long_id20), connection_id(long_id20));
}

TEST(connection_id, ne)
{
  EXPECT_NE(connection_id(), connection_id(a));
  EXPECT_NE(connection_id(a), connection_id());

  EXPECT_NE(connection_id(a), connection_id(aa));
  EXPECT_NE(connection_id(aa), connection_id(a));

  EXPECT_NE(connection_id(a), connection_id(b));
  EXPECT_NE(connection_id(b), connection_id(a));

  EXPECT_NE(connection_id(long_id19), connection_id(long_id20));
  EXPECT_NE(connection_id(long_id20), connection_id(long_id19));
}

TEST(connection_id, lt)
{
  EXPECT_LT(connection_id(), connection_id(a));
  EXPECT_LT(connection_id(a), connection_id(aa));
  EXPECT_LT(connection_id(a), connection_id(b));
  EXPECT_LT(connection_id(long_id19), connection_id(long_id20));
}

TEST(connection_id, lte)
{
  EXPECT_LE(connection_id(), connection_id());
  EXPECT_LE(connection_id(), connection_id(a));
  EXPECT_LE(connection_id(a), connection_id(a));
  EXPECT_LE(connection_id(a), connection_id(aa));
  EXPECT_LE(connection_id(a), connection_id(b));
  EXPECT_LE(connection_id(long_id19), connection_id(long_id20));
  EXPECT_LE(connection_id(long_id20), connection_id(long_id20));
}

TEST(connection_id, gt)
{
  EXPECT_GT(connection_id(a), connection_id());
  EXPECT_GT(connection_id(aa), connection_id(a));
  EXPECT_GT(connection_id(b), connection_id(a));
  EXPECT_GT(connection_id(long_id20), connection_id(long_id19));
}

TEST(connection_id, gte)
{
  EXPECT_GE(connection_id(), connection_id());
  EXPECT_GE(connection_id(a), connection_id());
  EXPECT_GE(connection_id(a), connection_id(a));
  EXPECT_GE(connection_id(aa), connection_id(a));
  EXPECT_GE(connection_id(b), connection_id(a));
  EXPECT_GE(connection_id(long_id20), connection_id(long_id19));
  EXPECT_GE(connection_id(long_id20), connection_id(long_id20));
}

TEST(connection_id, copy)
{
  constexpr auto id1 = connection_id{long_id20};
  connection_id id2 = id1;
  EXPECT_EQ(long_id20, id1);
  EXPECT_EQ(long_id20, id2);
}

TEST(connection_id, copy_assign)
{
  constexpr auto id1 = connection_id{long_id20};
  connection_id id2;
  id2 = id1;
  EXPECT_EQ(long_id20, id1);
  EXPECT_EQ(long_id20, id2);
}

TEST(connection_id, move)
{
  auto id1 = connection_id{long_id20};
  auto id2 = connection_id{std::move(id1)};
  EXPECT_EQ(long_id20, id2);
}

TEST(connection_id, move_assign)
{
  auto id1 = connection_id{long_id20};
  connection_id id2;
  id2 = std::move(id1);
  EXPECT_EQ(long_id20, id2);
}

TEST(connection_id, length_error)
{
  EXPECT_NO_THROW(connection_id(long_id.data(), 20));
  EXPECT_THROW(connection_id(long_id.data(), 21), std::length_error);

  connection_id id;
  id.resize(20);
  EXPECT_THROW(id.resize(21), std::length_error);
}

} // namespace nexus::quic
