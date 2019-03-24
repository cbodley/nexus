#include <http2/detail/hpack/dynamic_table.hpp>
#include <gtest/gtest.h>

namespace nexus::http2::detail::hpack {

// typedef for a table with overhead=0 to make some math easier
using dynamic_table_0 = basic_dynamic_table<uint32_t, 0>;

TEST(HPACKDynamicTable, lookup_null)
{
  dynamic_table table(4096);

  const std::string NAME = "foo";
  const std::string VALUE = "bar";
  ASSERT_TRUE(table.insert(NAME, VALUE));
  {
    std::string name;
    ASSERT_TRUE(table.lookup(0, &name, nullptr));
    EXPECT_EQ(NAME, name);
  }
  {
    std::string value;
    ASSERT_TRUE(table.lookup(0, nullptr, &value));
    EXPECT_EQ(VALUE, value);
  }
  EXPECT_TRUE(table.lookup(0, nullptr, nullptr));
}

TEST(HPACKDynamicTable, insert_mutable)
{
  dynamic_table table(4096);

  std::string str = "foo";
  ASSERT_TRUE(table.insert(str, str));
  {
    std::string name, value;
    ASSERT_TRUE(table.lookup(0, &name, &value));
    EXPECT_EQ("foo", name);
    EXPECT_EQ("foo", value);
  }
  str = "bar"; // mutate source string
  { // lookup returns initial values
    std::string name, value;
    ASSERT_TRUE(table.lookup(0, &name, &value));
    EXPECT_EQ("foo", name);
    EXPECT_EQ("foo", value);
  }
}

TEST(HPACKDynamicTable, insert_empty_value)
{
  // tests that the per-entry overhead is 32 bytes
  {
    dynamic_table table31(31);
    std::string str = "";
    EXPECT_FALSE(table31.insert(str, str));
  }
  {
    dynamic_table table32(32);
    std::string str = "";
    EXPECT_TRUE(table32.insert(str, str));

    std::string name, value;
    ASSERT_TRUE(table32.lookup(0, &name, &value));
    EXPECT_TRUE(name.empty());
    EXPECT_TRUE(value.empty());
  }
}

TEST(HPACKDynamicTable, insert_too_big)
{
  dynamic_table table(80);
  {
    std::string str(32, 'q');
    ASSERT_FALSE(table.insert(str, str)); // 32 + 32 + 32 = 96
    EXPECT_FALSE(table.lookup(0, nullptr, nullptr));
  }
  {
    std::string str = "";
    ASSERT_TRUE(table.insert(str, str)); // 32
    ASSERT_TRUE(table.insert(str, str)); // 32
    EXPECT_TRUE(table.lookup(0, nullptr, nullptr));
    EXPECT_TRUE(table.lookup(1, nullptr, nullptr));
  }
  {
    std::string str(32, 'q');
    ASSERT_FALSE(table.insert(str, str)); // 32 + 32 + 32 = 96
    EXPECT_FALSE(table.lookup(0, nullptr, nullptr)); // drops empty entries
  }
}

TEST(HPACKDynamicTable, insert_evict)
{
  dynamic_table table(80);
  {
    std::string str(32, 'q');
    ASSERT_FALSE(table.insert(str, str)); // 32 + 32 + 32 = 96
    EXPECT_FALSE(table.lookup(0, nullptr, nullptr));
  }
  {
    std::string str = "";
    ASSERT_TRUE(table.insert(str, str)); // 32
    ASSERT_TRUE(table.insert(str, str)); // 32
    EXPECT_TRUE(table.lookup(0, nullptr, nullptr));
    EXPECT_TRUE(table.lookup(1, nullptr, nullptr));
  }
  {
    std::string str(32, 'q');
    ASSERT_FALSE(table.insert(str, str)); // 32 + 32 + 32 = 96
    EXPECT_FALSE(table.lookup(0, nullptr, nullptr)); // drops empty entries
  }
}

TEST(HPACKDynamicTable, insert_wrap_name)
{
  dynamic_table_0 table(2);
  ASSERT_TRUE(table.insert("0", "")); // offset=0 length=1
  ASSERT_TRUE(table.insert("ab", "")); // offset=1 length=2
  std::string name;
  ASSERT_TRUE(table.lookup(0, &name, nullptr));
  EXPECT_EQ("ab", name);
  EXPECT_FALSE(table.lookup(1, nullptr, nullptr));
}

TEST(HPACKDynamicTable, insert_wrap_value)
{
  dynamic_table_0 table(2);
  ASSERT_TRUE(table.insert("", "0")); // offset=0 length=1
  ASSERT_TRUE(table.insert("", "ab")); // offset=1 length=2
  std::string value;
  ASSERT_TRUE(table.lookup(0, nullptr, &value));
  EXPECT_EQ("ab", value);
  EXPECT_FALSE(table.lookup(1, nullptr, nullptr));
}

TEST(HPACKDynamicTable, set_size_evict)
{
  dynamic_table_0 table(4);
  ASSERT_TRUE(table.insert("a", ""));
  ASSERT_TRUE(table.insert("b", ""));
  ASSERT_TRUE(table.insert("c", ""));
  ASSERT_TRUE(table.insert("d", ""));
  table.set_size(2);
  std::string name;
  ASSERT_TRUE(table.lookup(0, &name, nullptr));
  EXPECT_EQ("d", name);
  ASSERT_TRUE(table.lookup(1, &name, nullptr));
  EXPECT_EQ("c", name);
  EXPECT_FALSE(table.lookup(2, nullptr, nullptr));
}

} // namespace nexus::http2::detail::hpack
