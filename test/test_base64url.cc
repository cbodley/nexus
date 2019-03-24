#include <http2/detail/base64url.hpp>
#include <gtest/gtest.h>

namespace nexus::http2 {

TEST(Base64Url, encode)
{
  EXPECT_EQ("", detail::base64url::encode(""));
  EXPECT_EQ("Zg", detail::base64url::encode("f"));
  EXPECT_EQ("Zm8", detail::base64url::encode("fo"));
  EXPECT_EQ("Zm9v", detail::base64url::encode("foo"));
  EXPECT_EQ("Zm9vYg", detail::base64url::encode("foob"));
  EXPECT_EQ("Zm9vYmE", detail::base64url::encode("fooba"));
  EXPECT_EQ("Zm9vYmFy", detail::base64url::encode("foobar"));
}

TEST(Base64Url, decode)
{
  EXPECT_EQ("", detail::base64url::decode(""));
  EXPECT_EQ("f", detail::base64url::decode("Zg"));
  EXPECT_EQ("fo", detail::base64url::decode("Zm8"));
  EXPECT_EQ("foo", detail::base64url::decode("Zm9v"));
  EXPECT_EQ("foob", detail::base64url::decode("Zm9vYg"));
  EXPECT_EQ("fooba", detail::base64url::decode("Zm9vYmE"));
  EXPECT_EQ("foobar", detail::base64url::decode("Zm9vYmFy"));

  EXPECT_THROW(detail::base64url::decode("1"), boost::system::system_error);
  EXPECT_THROW(detail::base64url::decode("12345"), boost::system::system_error);
  EXPECT_THROW(detail::base64url::decode("aaa["), boost::system::system_error);
  EXPECT_THROW(detail::base64url::decode("aa=="), boost::system::system_error);

  auto decode_ec = [] (std::string_view input) {
    boost::system::error_code ec;
    detail::base64url::decode(input, ec);
    return ec;
  };
  EXPECT_EQ(detail::base64url::error::invalid_length, decode_ec("1"));
  EXPECT_EQ(detail::base64url::error::invalid_length, decode_ec("12345"));
  EXPECT_EQ(detail::base64url::error::invalid_character, decode_ec("aaa["));
  EXPECT_EQ(detail::base64url::error::invalid_character, decode_ec("aa=="));
}

} // namespace nexus::http2
