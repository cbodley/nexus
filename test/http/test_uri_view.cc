#include <nexus/http/uri_view.hpp>
#include <gtest/gtest.h>

namespace nexus::http {

TEST(uri_view, parse_absolute)
{
  {
    auto u = uri_view::parse("http:");
    EXPECT_EQ("http", u.scheme());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("", u.fragment());
    EXPECT_EQ("", u.authority());
    EXPECT_EQ("http:", u.get());
  }
  {
    auto u = uri_view::parse("scheme:path");
    EXPECT_EQ("scheme", u.scheme());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("path", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("", u.fragment());
    EXPECT_EQ("", u.authority());
    EXPECT_EQ("scheme:path", u.get());
  }
  {
    auto u = uri_view::parse("scheme:path?query");
    EXPECT_EQ("scheme", u.scheme());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("path", u.path());
    EXPECT_EQ("query", u.query());
    EXPECT_EQ("", u.fragment());
    EXPECT_EQ("", u.authority());
    EXPECT_EQ("scheme:path?query", u.get());
  }
  {
    auto u = uri_view::parse("scheme:path#fragment");
    EXPECT_EQ("scheme", u.scheme());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("path", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("fragment", u.fragment());
    EXPECT_EQ("", u.authority());
    EXPECT_EQ("scheme:path#fragment", u.get());
  }
  {
    auto u = uri_view::parse("scheme:path?query#fragment");
    EXPECT_EQ("scheme", u.scheme());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("path", u.path());
    EXPECT_EQ("query", u.query());
    EXPECT_EQ("fragment", u.fragment());
    EXPECT_EQ("", u.authority());
    EXPECT_EQ("scheme:path?query#fragment", u.get());
  }
  {
    auto u = uri_view::parse("scheme:?query");
    EXPECT_EQ("scheme", u.scheme());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("", u.path());
    EXPECT_EQ("query", u.query());
    EXPECT_EQ("", u.fragment());
    EXPECT_EQ("", u.authority());
    EXPECT_EQ("scheme:?query", u.get());
  }
  {
    auto u = uri_view::parse("scheme:#fragment");
    EXPECT_EQ("scheme", u.scheme());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("fragment", u.fragment());
    EXPECT_EQ("", u.authority());
    EXPECT_EQ("scheme:#fragment", u.get());
  }
  {
    auto u = uri_view::parse("scheme:#frag?ment");
    EXPECT_EQ("scheme", u.scheme());
    EXPECT_EQ("", u.authority());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("frag?ment", u.fragment());
  }
}

TEST(uri_view, parse_absolute_authority)
{
  {
    auto u = uri_view::parse("http://host.com");
    EXPECT_EQ("http", u.scheme());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("host.com", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("", u.fragment());
    EXPECT_EQ("host.com", u.authority());
    EXPECT_EQ("http://host.com", u.get());
  }
  {
    auto u = uri_view::parse("http://host.com:8080");
    EXPECT_EQ("http", u.scheme());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("host.com", u.host());
    EXPECT_EQ("8080", u.port());
    EXPECT_EQ("", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("", u.fragment());
    EXPECT_EQ("host.com:8080", u.authority());
    EXPECT_EQ("http://host.com:8080", u.get());
  }
  {
    auto u = uri_view::parse("http://userinfo@host.com");
    EXPECT_EQ("http", u.scheme());
    EXPECT_EQ("userinfo", u.userinfo());
    EXPECT_EQ("host.com", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("", u.fragment());
    EXPECT_EQ("userinfo@host.com", u.authority());
    EXPECT_EQ("http://userinfo@host.com", u.get());
  }
  {
    auto u = uri_view::parse("http://userinfo@host.com:8080");
    EXPECT_EQ("http", u.scheme());
    EXPECT_EQ("userinfo", u.userinfo());
    EXPECT_EQ("host.com", u.host());
    EXPECT_EQ("8080", u.port());
    EXPECT_EQ("", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("", u.fragment());
    EXPECT_EQ("userinfo@host.com:8080", u.authority());
    EXPECT_EQ("http://userinfo@host.com:8080", u.get());
  }
  {
    auto u = uri_view::parse("http://userinfo@host.com:8080/path");
    EXPECT_EQ("http", u.scheme());
    EXPECT_EQ("userinfo", u.userinfo());
    EXPECT_EQ("host.com", u.host());
    EXPECT_EQ("8080", u.port());
    EXPECT_EQ("/path", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("", u.fragment());
    EXPECT_EQ("userinfo@host.com:8080", u.authority());
    EXPECT_EQ("http://userinfo@host.com:8080/path", u.get());
  }
  {
    auto u = uri_view::parse("http://userinfo@host.com:8080/path?query");
    EXPECT_EQ("http", u.scheme());
    EXPECT_EQ("userinfo", u.userinfo());
    EXPECT_EQ("host.com", u.host());
    EXPECT_EQ("8080", u.port());
    EXPECT_EQ("/path", u.path());
    EXPECT_EQ("query", u.query());
    EXPECT_EQ("", u.fragment());
    EXPECT_EQ("userinfo@host.com:8080", u.authority());
    EXPECT_EQ("http://userinfo@host.com:8080/path?query", u.get());
  }
  {
    auto u = uri_view::parse("http://userinfo@host.com:8080/path?query#fragment");
    EXPECT_EQ("http", u.scheme());
    EXPECT_EQ("userinfo", u.userinfo());
    EXPECT_EQ("host.com", u.host());
    EXPECT_EQ("8080", u.port());
    EXPECT_EQ("/path", u.path());
    EXPECT_EQ("query", u.query());
    EXPECT_EQ("fragment", u.fragment());
    EXPECT_EQ("userinfo@host.com:8080", u.authority());
    EXPECT_EQ("http://userinfo@host.com:8080/path?query#fragment", u.get());
  }
  {
    auto u = uri_view::parse("http://userinfo@host.com:8080/path#fragment");
    EXPECT_EQ("http", u.scheme());
    EXPECT_EQ("userinfo", u.userinfo());
    EXPECT_EQ("host.com", u.host());
    EXPECT_EQ("8080", u.port());
    EXPECT_EQ("/path", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("fragment", u.fragment());
    EXPECT_EQ("userinfo@host.com:8080", u.authority());
    EXPECT_EQ("http://userinfo@host.com:8080/path#fragment", u.get());
  }
  {
    auto u = uri_view::parse("http://userinfo@host.com:8080/path#frag?ment");
    EXPECT_EQ("http", u.scheme());
    EXPECT_EQ("userinfo", u.userinfo());
    EXPECT_EQ("host.com", u.host());
    EXPECT_EQ("8080", u.port());
    EXPECT_EQ("/path", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("frag?ment", u.fragment());
    EXPECT_EQ("userinfo@host.com:8080", u.authority());
    EXPECT_EQ("http://userinfo@host.com:8080/path#frag?ment", u.get());
  }
}

TEST(uri_view, parse_relative)
{
  {
    auto u = uri_view::parse("");
    EXPECT_EQ("", u.scheme());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("", u.fragment());
    EXPECT_EQ("", u.authority());
    EXPECT_EQ("", u.get());
  }
  {
    auto u = uri_view::parse("path");
    EXPECT_EQ("", u.scheme());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("path", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("", u.fragment());
    EXPECT_EQ("", u.authority());
    EXPECT_EQ("path", u.get());
  }
  {
    auto u = uri_view::parse("/path");
    EXPECT_EQ("", u.scheme());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("/path", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("", u.fragment());
    EXPECT_EQ("", u.authority());
    EXPECT_EQ("/path", u.get());
  }
  {
    auto u = uri_view::parse("path?query");
    EXPECT_EQ("", u.scheme());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("path", u.path());
    EXPECT_EQ("query", u.query());
    EXPECT_EQ("", u.fragment());
    EXPECT_EQ("", u.authority());
    EXPECT_EQ("path?query", u.get());
  }
  {
    auto u = uri_view::parse("path#fragment");
    EXPECT_EQ("", u.scheme());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("path", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("fragment", u.fragment());
    EXPECT_EQ("", u.authority());
    EXPECT_EQ("path#fragment", u.get());
  }
  {
    auto u = uri_view::parse("/pa:th");
    EXPECT_EQ("", u.scheme());
    EXPECT_EQ("", u.authority());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("/pa:th", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("", u.fragment());
  }
  {
    auto u = uri_view::parse("./pa:th");
    EXPECT_EQ("", u.scheme());
    EXPECT_EQ("", u.authority());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("./pa:th", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("", u.fragment());
  }
  {
    auto u = uri_view::parse("?query");
    EXPECT_EQ("", u.scheme());
    EXPECT_EQ("", u.authority());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("", u.path());
    EXPECT_EQ("query", u.query());
    EXPECT_EQ("", u.fragment());
  }
  {
    auto u = uri_view::parse("#fragment");
    EXPECT_EQ("", u.scheme());
    EXPECT_EQ("", u.authority());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("fragment", u.fragment());
  }
  {
    auto u = uri_view::parse("#frag?ment");
    EXPECT_EQ("", u.scheme());
    EXPECT_EQ("", u.authority());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("frag?ment", u.fragment());
  }
}

TEST(uri_view, parse_relative_authority)
{
  {
    auto u = uri_view::parse("//host.com");
    EXPECT_EQ("", u.scheme());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("host.com", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("", u.fragment());
    EXPECT_EQ("host.com", u.authority());
    EXPECT_EQ("//host.com", u.get());
  }
  {
    auto u = uri_view::parse("//host.com:8080");
    EXPECT_EQ("", u.scheme());
    EXPECT_EQ("", u.userinfo());
    EXPECT_EQ("host.com", u.host());
    EXPECT_EQ("8080", u.port());
    EXPECT_EQ("", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("", u.fragment());
    EXPECT_EQ("host.com:8080", u.authority());
    EXPECT_EQ("//host.com:8080", u.get());
  }
  {
    auto u = uri_view::parse("//userinfo@host.com");
    EXPECT_EQ("", u.scheme());
    EXPECT_EQ("userinfo", u.userinfo());
    EXPECT_EQ("host.com", u.host());
    EXPECT_EQ("", u.port());
    EXPECT_EQ("", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("", u.fragment());
    EXPECT_EQ("userinfo@host.com", u.authority());
    EXPECT_EQ("//userinfo@host.com", u.get());
  }
  {
    auto u = uri_view::parse("//userinfo@host.com:8080");
    EXPECT_EQ("", u.scheme());
    EXPECT_EQ("userinfo", u.userinfo());
    EXPECT_EQ("host.com", u.host());
    EXPECT_EQ("8080", u.port());
    EXPECT_EQ("", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("", u.fragment());
    EXPECT_EQ("userinfo@host.com:8080", u.authority());
    EXPECT_EQ("//userinfo@host.com:8080", u.get());
  }
  {
    auto u = uri_view::parse("//userinfo@host.com:8080/path");
    EXPECT_EQ("", u.scheme());
    EXPECT_EQ("userinfo", u.userinfo());
    EXPECT_EQ("host.com", u.host());
    EXPECT_EQ("8080", u.port());
    EXPECT_EQ("/path", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("", u.fragment());
    EXPECT_EQ("userinfo@host.com:8080", u.authority());
    EXPECT_EQ("//userinfo@host.com:8080/path", u.get());
  }
  {
    auto u = uri_view::parse("//userinfo@host.com:8080/path?query");
    EXPECT_EQ("", u.scheme());
    EXPECT_EQ("userinfo", u.userinfo());
    EXPECT_EQ("host.com", u.host());
    EXPECT_EQ("8080", u.port());
    EXPECT_EQ("/path", u.path());
    EXPECT_EQ("query", u.query());
    EXPECT_EQ("", u.fragment());
    EXPECT_EQ("userinfo@host.com:8080", u.authority());
    EXPECT_EQ("//userinfo@host.com:8080/path?query", u.get());
  }
  {
    auto u = uri_view::parse("//userinfo@host.com:8080/path?query#fragment");
    EXPECT_EQ("", u.scheme());
    EXPECT_EQ("userinfo", u.userinfo());
    EXPECT_EQ("host.com", u.host());
    EXPECT_EQ("8080", u.port());
    EXPECT_EQ("/path", u.path());
    EXPECT_EQ("query", u.query());
    EXPECT_EQ("fragment", u.fragment());
    EXPECT_EQ("userinfo@host.com:8080", u.authority());
    EXPECT_EQ("//userinfo@host.com:8080/path?query#fragment", u.get());
  }
  {
    auto u = uri_view::parse("//userinfo@host.com:8080/path#fragment");
    EXPECT_EQ("", u.scheme());
    EXPECT_EQ("userinfo", u.userinfo());
    EXPECT_EQ("host.com", u.host());
    EXPECT_EQ("8080", u.port());
    EXPECT_EQ("/path", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("fragment", u.fragment());
    EXPECT_EQ("userinfo@host.com:8080", u.authority());
    EXPECT_EQ("//userinfo@host.com:8080/path#fragment", u.get());
  }
  {
    auto u = uri_view::parse("//userinfo@host.com:8080/path#frag?ment");
    EXPECT_EQ("", u.scheme());
    EXPECT_EQ("userinfo", u.userinfo());
    EXPECT_EQ("host.com", u.host());
    EXPECT_EQ("8080", u.port());
    EXPECT_EQ("/path", u.path());
    EXPECT_EQ("", u.query());
    EXPECT_EQ("frag?ment", u.fragment());
    EXPECT_EQ("userinfo@host.com:8080", u.authority());
    EXPECT_EQ("//userinfo@host.com:8080/path#frag?ment", u.get());
  }
}

TEST(uri_view, copy)
{
  auto uri = uri_view::parse("https://domain.com/index.html");
  ASSERT_EQ("https", uri.scheme());
  ASSERT_EQ("domain.com", uri.authority());
  ASSERT_EQ("/index.html", uri.path());
  ASSERT_EQ("https://domain.com/index.html", uri.get());
  {
    uri_view copied{uri}; // copy construct
    EXPECT_EQ("https", uri.scheme());
    EXPECT_EQ("domain.com", uri.authority());
    EXPECT_EQ("/index.html", uri.path());
    EXPECT_EQ("https://domain.com/index.html", uri.get());
    EXPECT_EQ("https", copied.scheme());
    EXPECT_EQ("domain.com", copied.authority());
    EXPECT_EQ("/index.html", copied.path());
    EXPECT_EQ("https://domain.com/index.html", copied.get());
  }
  {
    uri_view copied;
    copied = uri; // copy assign
    EXPECT_EQ("https", uri.scheme());
    EXPECT_EQ("domain.com", uri.authority());
    EXPECT_EQ("/index.html", uri.path());
    EXPECT_EQ("https://domain.com/index.html", uri.get());
    EXPECT_EQ("https", copied.scheme());
    EXPECT_EQ("domain.com", copied.authority());
    EXPECT_EQ("/index.html", copied.path());
    EXPECT_EQ("https://domain.com/index.html", copied.get());
  }
}

TEST(uri_view, move)
{
  {
    auto uri = uri_view::parse("https://domain.com/index.html");
    ASSERT_EQ("https://domain.com/index.html", uri.get());
    uri_view copied{std::move(uri)}; // move construct
    EXPECT_EQ("https", copied.scheme());
    EXPECT_EQ("domain.com", copied.authority());
    EXPECT_EQ("/index.html", copied.path());
    EXPECT_EQ("https://domain.com/index.html", copied.get());
  }
  {
    auto uri = uri_view::parse("https://domain.com/index.html");
    ASSERT_EQ("https://domain.com/index.html", uri.get());
    uri_view copied;
    EXPECT_EQ("", copied.get());
    copied = std::move(uri); // move assign
    EXPECT_EQ("https", copied.scheme());
    EXPECT_EQ("domain.com", copied.authority());
    EXPECT_EQ("/index.html", copied.path());
    EXPECT_EQ("https://domain.com/index.html", copied.get());
  }
}

} // namespace nexus::http
