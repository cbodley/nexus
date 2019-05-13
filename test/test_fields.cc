#include <nexus/http2/basic_fields.hpp>
#include <gtest/gtest.h>

namespace nexus::http2 {

TEST(Fields, make_field)
{
  auto f1 = detail::make_field(field::status_200);
  EXPECT_EQ(field::status_200, f1->name());
  EXPECT_EQ(":status", f1->name_string());
  EXPECT_EQ("200", f1->value());

  auto f2 = detail::make_field(boost::asio::buffer("abc", 3),
                               boost::asio::buffer("def", 3));
  EXPECT_EQ(field::unknown, f2->name());
  EXPECT_EQ("abc", f2->name_string());
  EXPECT_EQ("def", f2->value());

  auto f3 = detail::make_field(field::content_length,
                               boost::asio::buffer("123", 3));
  EXPECT_EQ(field::content_length, f3->name());
  EXPECT_EQ("content-length", f3->name_string());
  EXPECT_EQ("123", f3->value());
}

TEST(Fields, insert)
{
  basic_fields<> fields;

  fields.insert("abc", "def");
  ASSERT_EQ(1u, std::distance(fields.begin(), fields.end()));
  EXPECT_EQ(field::unknown, fields.begin()->name());
  EXPECT_EQ("abc", fields.begin()->name_string());
  EXPECT_EQ("def", fields.begin()->value());

  fields.insert(field::content_length, "123");
  ASSERT_EQ(2u, std::distance(fields.begin(), fields.end()));
  EXPECT_EQ(field::unknown, fields.begin()->name());
  EXPECT_EQ("abc", fields.begin()->name_string());
  EXPECT_EQ("def", fields.begin()->value());
  EXPECT_EQ(field::content_length, std::next(fields.begin())->name());
  EXPECT_EQ("content-length", std::next(fields.begin())->name_string());
  EXPECT_EQ("123", std::next(fields.begin())->value());
}

TEST(Fields, equal_range)
{
  basic_fields<> fields;
  fields.insert(field::authority, "xyz");
  fields.insert(field::content_length, "123");
  fields.insert(field::authority, "XYZ");
  fields.insert("abc", "def");
  fields.insert("xyz", "123");
  fields.insert("abc", "ghi");
  {
    auto range = fields.equal_range(field::authority);
    ASSERT_EQ(2u, std::distance(range.first, range.second));
    EXPECT_EQ(field::authority, range.first->name());
    EXPECT_EQ(":authority", range.first->name_string());
    EXPECT_EQ("xyz", range.first->value());
    EXPECT_EQ(field::authority, std::next(range.first)->name());
    EXPECT_EQ(":authority", std::next(range.first)->name_string());
    EXPECT_EQ("XYZ", std::next(range.first)->value());
  }
  {
    auto range = fields.equal_range("abc");
    ASSERT_EQ(2u, std::distance(range.first, range.second));
    EXPECT_EQ(field::unknown, range.first->name());
    EXPECT_EQ("abc", range.first->name_string());
    EXPECT_EQ("def", range.first->value());
    EXPECT_EQ(field::unknown, std::next(range.first)->name());
    EXPECT_EQ("abc", std::next(range.first)->name_string());
    EXPECT_EQ("ghi", std::next(range.first)->value());
  }
}

TEST(Fields, erase)
{
  basic_fields<> fields;
  fields.insert(field::authority, "xyz");
  fields.insert(field::authority, "XYZ");
  fields.insert("abc", "def");
  fields.insert("foo", "bar");
  ASSERT_EQ(4u, std::distance(fields.begin(), fields.end()));
  {
    // erase with iterator from find()
    auto f = fields.find("abc");
    ASSERT_NE(fields.end(), f);
    auto after = fields.erase(f);
    ASSERT_NE(fields.end(), after);
    EXPECT_EQ("bar", after->value());
    ASSERT_EQ(3u, std::distance(fields.begin(), fields.end()));
    EXPECT_EQ("foo", std::next(std::next(fields.begin()))->name_string());
    auto range = fields.equal_range("abc");
    EXPECT_EQ(range.first, range.second);
  }
  {
    // erase with iterator from equal_range()
    auto range = fields.equal_range(field::authority);
    ASSERT_EQ(2u, std::distance(range.first, range.second));
    auto after = fields.erase(range.first);
    ASSERT_NE(basic_fields<>::const_name_iterator(), after);
    EXPECT_EQ("XYZ", after->value());
    ASSERT_EQ(2u, std::distance(fields.begin(), fields.end()));
    EXPECT_EQ("foo", std::next(fields.begin())->name_string());
    range = fields.equal_range(field::authority);
    ASSERT_EQ(1u, std::distance(range.first, range.second));
    EXPECT_EQ("XYZ", range.first->value());
  }
}

using allocator_log = std::vector<size_t>;
// mark highest bit for deallocation events
constexpr size_t deallocate_flag = static_cast<size_t>(1) << (std::numeric_limits<size_t>::digits - 1);

template <typename T>
struct logging_allocator : std::allocator<T> {
  allocator_log* log;
  using size_type = typename std::allocator<T>::size_type;
  using pointer = typename std::allocator<T>::pointer;

  template <typename U>
  struct rebind { using other = logging_allocator<U>; };

  // converting copy constructor (requires friend)
  template <typename> friend struct logging_allocator;
  template <typename U>
  logging_allocator(const logging_allocator<U>& other) : log(other.log) {}

  template <typename ...Args>
  logging_allocator(allocator_log* log, Args&& ...args)
    : std::allocator<T>(std::forward<Args>(args)...), log(log)
  {}
  pointer allocate(size_type n, const void* hint = nullptr) {
    log->emplace_back(n);
    return std::allocator<T>::allocate(n, hint);
  }
  void deallocate(pointer p, size_type n) {
    if (p) {
      log->push_back(n | deallocate_flag);
    }
    std::allocator<T>::deallocate(p, n);
  }
};

TEST(Fields, allocator)
{
  using allocator_type = logging_allocator<char>;
  using fields_type = basic_fields<allocator_type>;
  using value_type = typename fields_type::value_type;
  constexpr size_t base_size = sizeof(value_type) + 1;
  allocator_log log;
  {
    fields_type fields(&log);
    auto f = fields.insert(field::authority, "xyz");
    ASSERT_EQ(1u, log.size());
    EXPECT_EQ(base_size + 3, log[0]);
    fields.erase(f);
    ASSERT_EQ(2u, log.size());
    EXPECT_EQ(deallocate_flag | (base_size + 3), log[1]);
    fields.insert("abc", "def");
    ASSERT_EQ(3u, log.size());
    EXPECT_EQ(base_size + 6, log[2]);
  }
  ASSERT_EQ(4u, log.size());
  EXPECT_EQ(deallocate_flag | (base_size + 6), log[3]);
}

} // namespace nexus::http2
