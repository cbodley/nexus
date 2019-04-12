#include <nexus/http2/hpack/header.hpp>
#include <nexus/http2/hpack/decoder.hpp>
#include <boost/beast/http/fields.hpp>
#include <gtest/gtest.h>

namespace boost::beast::http {
bool operator==(const http::fields::value_type& lhs,
                const http::fields::value_type& rhs) {
  return lhs.name_string() == rhs.name_string()
      && lhs.value() == rhs.value();
}
bool operator==(const http::fields& lhs, const http::fields& rhs) {
  return std::equal(lhs.begin(), lhs.end(), rhs.begin());
}
} // namespace boost::beast::http

namespace nexus::http2::hpack {

static const boost::system::error_code ok;

namespace http = boost::beast::http;

TEST(HPACKHeader, decode_static_value)
{
  std::vector<uint8_t> encoded;
  {
    auto buf = boost::asio::dynamic_buffer(encoded);
    constexpr uint32_t authority = 1; // :authority
    ASSERT_EQ(1u, encode_indexed_header(authority, buf));
    constexpr uint32_t method_post = 3; // :method POST
    ASSERT_EQ(1u, encode_indexed_header(method_post, buf));
    constexpr uint32_t invalid_index = 999;
    ASSERT_EQ(3u, encode_indexed_header(invalid_index, buf));
    ASSERT_EQ(5u, encoded.size());
  }

  dynamic_table table(4096);
  http::fields fields;
  decoder d(table, fields, 4096);

  boost::system::error_code ec;
  d.decode(boost::asio::buffer(encoded), ec);
  EXPECT_EQ(error::decode_invalid_index, ec);

  ASSERT_EQ(2u, std::distance(fields.begin(), fields.end()));
  auto field = fields.begin();
  EXPECT_EQ(":authority", field->name_string());
  EXPECT_TRUE(field->value().empty());
  ++field;
  EXPECT_EQ(":method", field->name_string());
  EXPECT_EQ("POST", field->value());

  d.finish(ec);
  EXPECT_EQ(ok, ec);
}

TEST(HPACKHeader, decode_dynamic_value)
{
  std::vector<uint8_t> encoded;
  {
    auto buf = boost::asio::dynamic_buffer(encoded);
    ASSERT_EQ(1u, encode_indexed_header(static_table::size+1, buf));
    ASSERT_EQ(1u, encode_indexed_header(static_table::size+3, buf));
    ASSERT_EQ(1u, encode_indexed_header(static_table::size+4, buf));
    ASSERT_EQ(3u, encoded.size());
  }

  dynamic_table table(4096);
  table.insert("e", "f");
  table.insert("c", "d");
  table.insert("a", "b");
  http::fields fields;
  decoder d(table, fields, 4096);

  boost::system::error_code ec;
  d.decode(boost::asio::buffer(encoded), ec);
  EXPECT_EQ(error::decode_invalid_index, ec);

  ASSERT_EQ(2u, std::distance(fields.begin(), fields.end()));
  auto field = fields.begin();
  EXPECT_EQ("a", field->name_string());
  EXPECT_EQ("b", field->value());
  ++field;
  EXPECT_EQ("e", field->name_string());
  EXPECT_EQ("f", field->value());
}

TEST(HPACKHeader, decode_static_name)
{
  std::vector<uint8_t> encoded;
  {
    auto buf = boost::asio::dynamic_buffer(encoded);
    constexpr uint32_t authority = 1; // :authority
    ASSERT_EQ(5u, encode_literal_header(authority, "mah", buf));
    constexpr uint32_t method_post = 3; // :method POST
    ASSERT_EQ(9u, encode_literal_header(method_post, "OPTIONS", buf));
    constexpr uint32_t invalid_index = 999;
    ASSERT_EQ(11u, encode_literal_header(invalid_index, "invalid", buf));
    ASSERT_EQ(25u, encoded.size());
  }

  dynamic_table table(4096);
  http::fields fields;
  decoder d(table, fields, 4096);

  boost::system::error_code ec;
  d.decode(boost::asio::buffer(encoded), ec);
  EXPECT_EQ(error::decode_invalid_index, ec);

  ASSERT_EQ(2u, std::distance(fields.begin(), fields.end()));
  auto field = fields.begin();
  EXPECT_EQ(":authority", field->name_string());
  EXPECT_EQ("mah", field->value());
  ++field;
  EXPECT_EQ(":method", field->name_string());
  EXPECT_EQ("OPTIONS", field->value());
}

TEST(HPACKHeader, decode_dynamic_name)
{
  std::vector<uint8_t> encoded;
  {
    auto buf = boost::asio::dynamic_buffer(encoded);
    ASSERT_EQ(3u, encode_literal_header(static_table::size+1, "x", buf));
    ASSERT_EQ(4u, encode_literal_header(static_table::size+4, "y", buf));
    ASSERT_EQ(4u, encode_literal_header(static_table::size+6, "z", buf));
    ASSERT_EQ(11u, encoded.size());
  }

  dynamic_table table(4096);
  table.insert("e", "f");
  table.insert("c", "d");
  table.insert("a", "b");
  http::fields fields;
  decoder d(table, fields, 4096);

  boost::system::error_code ec;
  d.decode(boost::asio::buffer(encoded), ec);
  EXPECT_EQ(error::decode_invalid_index, ec);

  ASSERT_EQ(2u, std::distance(fields.begin(), fields.end()));
  auto field = fields.begin();
  EXPECT_EQ("a", field->name_string());
  EXPECT_EQ("x", field->value());
  ++field;
  EXPECT_EQ("e", field->name_string());
  EXPECT_EQ("y", field->value());
}

TEST(HPACKHeader, decode_noindex)
{
  std::vector<uint8_t> encoded;
  {
    auto buf = boost::asio::dynamic_buffer(encoded);
    constexpr uint32_t authority = 1; // :authority
    ASSERT_EQ(3u, encode_literal_header_no_index(authority, "b", buf));
    ASSERT_EQ(5u, encode_literal_header_no_index("c", "d", buf));
    ASSERT_EQ(8u, encoded.size());
  }

  dynamic_table table(4096);
  http::fields fields;
  decoder d(table, fields, 4096);

  boost::system::error_code ec;
  d.decode(boost::asio::buffer(encoded), ec);
  EXPECT_EQ(ok, ec);

  ASSERT_EQ(2u, std::distance(fields.begin(), fields.end()));
  auto field = fields.begin();
  EXPECT_EQ(":authority", field->name_string());
  EXPECT_EQ("b", field->value());
  ++field;
  EXPECT_EQ("c", field->name_string());
  EXPECT_EQ("d", field->value());

  EXPECT_FALSE(table.lookup(0, nullptr, nullptr)); // nothing inserted

  d.finish(ec);
  EXPECT_EQ(ok, ec);
}

TEST(HPACKHeader, decode_table_size_update)
{
  std::vector<uint8_t> encoded;
  {
    auto buf = boost::asio::dynamic_buffer(encoded);
    ASSERT_EQ(5u, encode_literal_header("a", "b", buf));
    ASSERT_EQ(1u, encode_indexed_header(static_table::size+1, buf));
    ASSERT_EQ(1u, encode_table_size_update(16, buf));
    ASSERT_EQ(1u, encode_indexed_header(static_table::size+1, buf));
    ASSERT_EQ(8u, encoded.size());
  }

  dynamic_table table(4096);
  http::fields fields;
  decoder d(table, fields, 4096);

  boost::system::error_code ec;
  d.decode(boost::asio::buffer(encoded), ec);
  EXPECT_EQ(error::decode_invalid_index, ec);

  ASSERT_EQ(2u, std::distance(fields.begin(), fields.end()));
  auto field = fields.begin();
  EXPECT_EQ("a", field->name_string());
  EXPECT_EQ("b", field->value());
  ++field;
  EXPECT_EQ("a", field->name_string());
  EXPECT_EQ("b", field->value());

  EXPECT_EQ(16, table.max_size());
  EXPECT_FALSE(table.lookup(0, nullptr, nullptr));
}

TEST(HPACKHeader, encode_fields)
{
  http::fields fields;
  fields.insert("content-type", "application/json");
  fields.insert("date", "Thu, 01 Jan 1970 00:00:00 GMT");
  fields.insert("my-custom-header", "has-a-value");
  std::vector<uint8_t> encoded;
  {
    dynamic_table table(4096);
    auto buf = boost::asio::dynamic_buffer(encoded);
    ASSERT_EQ(79u, encode_headers(fields, table, buf));
    ASSERT_EQ(79u, encoded.size());
  }

  dynamic_table table(4096);
  http::fields fields2;
  decoder d(table, fields2, 4096);

  boost::system::error_code ec;
  d.decode(boost::asio::buffer(encoded), ec);
  EXPECT_EQ(ok, ec);
  EXPECT_EQ(fields, fields2);
}

} // namespace nexus::http2::hpack
