#pragma once

#include <vector>
#include <nexus/h3/fields.hpp>
#include <lsxpack_header.h>

namespace nexus::quic::detail {

struct recv_header_set {
  h3::fields fields;
  int is_push_promise;
  lsxpack_header header;
  std::vector<char> buffer;

  recv_header_set(int is_push_promise) : is_push_promise(is_push_promise) {}
};

} // namespace nexus::quic::detail
