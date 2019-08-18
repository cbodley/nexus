#pragma once

#include <cstdint>

namespace nexus::quic::detail {

using offset_t = uint64_t;
using stream_count_t = uint64_t;

struct flow_control_data {
  offset_t data_limit = 0;
  stream_count_t stream_limit = 0;
};

} // namespace nexus::quic::detail
