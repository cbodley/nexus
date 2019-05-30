#pragma once

#include <cstddef>

namespace nexus::http::detail {

// a structured representation of the parts
template <typename StringView, typename SizeType>
struct uri_parts {
  struct part { SizeType begin = 0; SizeType end = 0; };
  part scheme;
  part userinfo;
  part host;
  part port;
  part path;
  part query;
  part fragment;

  void parse(StringView str);
};

template <typename StringView, typename SizeType>
void uri_parts<StringView, SizeType>::parse(const StringView str)
{
  typename StringView::size_type pos = 0;

  // scheme:
  auto end = str.find(':');
  if (end == StringView::npos) {
    scheme.end = 0;
  } else {
    scheme.end = end;
    // if : comes after / it isn't part of the scheme
    auto slash = str.find('/');
    if (slash != StringView::npos && slash < scheme.end) {
      scheme.end = 0;
    } else {
      pos = scheme.end + 1;
    }
  }
  // //authority
  if (str.compare(pos, 2, "//") == 0) {
    userinfo.begin = pos + 2;
    end = str.find('/', userinfo.begin); // end of authority
    if (end == StringView::npos) {
      port.end = str.size();
    } else {
      port.end = end;
    }
    // userinfo@
    end = str.find('@', userinfo.begin);
    if (end > port.end) { // @ outside of authority
      userinfo.end = userinfo.begin; // no userinfo
      host.begin = userinfo.begin;
    } else {
      userinfo.end = end;
      host.begin = userinfo.end + 1; // after @
    }
    // host:port
    end = str.find(':', host.begin);
    if (end < port.end) {
      host.end = end;
      port.begin = host.end + 1; // after :
    } else {
      port.begin = port.end; // no port
      host.end = port.end;
    }
    path.begin = port.end;
  } else {
    // no authority
    userinfo.begin = userinfo.end = pos;
    host.begin = host.end = pos;
    port.begin = port.end = pos;
    path.begin = pos;
  }
  // path?query#fragment
  end = str.find('?', path.begin);
  if (end != StringView::npos) {
    path.end = end;
    query.begin = path.end + 1; // after ?
    end = str.find('#', path.begin);
    if (end == StringView::npos) {
      query.end = str.size();
      fragment.begin = fragment.end = query.end; // no fragment
    } else {
      query.end = end;
      if (query.end < path.end) { // # before ?
        path.end = query.begin = query.end; // no query
        fragment.begin = query.end + 1; // after #
      } else {
        fragment.begin = query.end + 1; // after #
        fragment.end = str.size();
      }
    }
  } else {
    // no query
    end = str.find('#', path.begin);
    if (end != StringView::npos) {
      path.end = end;
      query.begin = query.end = path.end; // no query
      fragment.begin = path.end + 1; // after #
      fragment.end = str.size();
    } else {
      path.end = str.size();
      query.begin = query.end = path.end; // no query
      fragment.begin = fragment.end = path.end; // no fragment
    }
  }
}

} // namespace nexus::http::detail
