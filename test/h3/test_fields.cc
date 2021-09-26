#include <nexus/h3/fields.hpp>
#include <gtest/gtest.h>

namespace nexus::h3 {

TEST(fields, empty)
{
  fields f;
  EXPECT_EQ(0, f.size());
  const auto begin = f.begin();
  const auto end = f.end();
  EXPECT_EQ(end, begin);
  const auto [lower, upper] = f.equal_range("shape");
  EXPECT_EQ(end, lower);
  EXPECT_EQ(end, upper);
}

TEST(fields, insert)
{
  fields f;
  f.insert("shape", "square");
  f.insert("color", "blue");

  EXPECT_EQ(2, f.size());
  const auto first = f.begin();
  ASSERT_NE(first, f.end());
  EXPECT_STREQ("shape: square", first->c_str());
  const auto second = std::next(first);
  ASSERT_NE(second, f.end());
  EXPECT_STREQ("color: blue", second->c_str());
  const auto third = std::next(second);
  EXPECT_EQ(third, f.end());
}

TEST(fields, insert_same_name)
{
  fields f;
  f.insert("shape", "square");
  f.insert("shape", "circle");

  const auto first = f.begin();
  ASSERT_NE(first, f.end());
  EXPECT_STREQ("shape: square", first->c_str());
  const auto second = std::next(first);
  ASSERT_NE(second, f.end());
  EXPECT_STREQ("shape: circle", second->c_str());
  const auto third = std::next(second);
  EXPECT_EQ(third, f.end());
}

TEST(fields, insert_same_name_out_of_order)
{
  fields f;
  f.insert("shape", "square");
  f.insert("color", "blue");
  f.insert("shape", "circle", true);

  EXPECT_EQ(3, f.size());
  const auto first = f.begin();
  ASSERT_NE(first, f.end());
  EXPECT_STREQ("shape: square", first->c_str());
  EXPECT_FALSE(first->never_index());
  const auto second = std::next(first);
  ASSERT_NE(second, f.end());
  EXPECT_STREQ("shape: circle", second->c_str());
  EXPECT_TRUE(second->never_index());
  const auto third = std::next(second);
  ASSERT_NE(third, f.end());
  EXPECT_STREQ("color: blue", third->c_str());
  EXPECT_FALSE(third->never_index());
  const auto fourth = std::next(third);
  EXPECT_EQ(fourth, f.end());

  const auto [lower, upper] = f.equal_range("shape");
  EXPECT_EQ(first, lower);
  EXPECT_EQ(third, upper);
}

TEST(fields, assign)
{
  fields f;
  f.insert("shape", "square", true);
  f.insert("color", "blue");
  f.insert("shape", "circle");
  f.assign("shape", "line");

  EXPECT_EQ(2, f.size());
  const auto first = f.begin();
  ASSERT_NE(first, f.end());
  EXPECT_STREQ("color: blue", first->c_str());
  const auto second = std::next(first);
  ASSERT_NE(second, f.end());
  EXPECT_STREQ("shape: line", second->c_str());
  EXPECT_FALSE(second->never_index());
  const auto third = std::next(second);
  EXPECT_EQ(third, f.end());

  const auto [lower, upper] = f.equal_range("shape");
  EXPECT_EQ(second, lower);
  EXPECT_EQ(third, upper);
}

} // namespace nexus::h3
