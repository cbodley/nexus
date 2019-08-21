#pragma once

#include <array>
#include <chrono>

#include <nexus/quic/detail/connection_id.hpp>
#include <nexus/quic/detail/token.hpp>
#include <nexus/quic/detail/varint.hpp>

namespace nexus::quic::detail {

using transport_value_len_t = uint16_t;

enum class transport_parameter_id : uint16_t {
  original_connection_id = 0,
  idle_timeout = 1,
  stateless_reset_token = 2,
  max_packet_size = 3,
  initial_max_data = 4,
  initial_max_stream_data_bidi_local = 5,
  initial_max_stream_data_bidi_remote = 6,
  initial_max_stream_data_uni = 7,
  initial_max_streams_bidi = 8,
  initial_max_streams_uni = 9,
  ack_delay_exponent = 10,
  max_ack_delay = 11,
  disable_migration = 12,
  preferred_address = 13,
  active_connection_id_limit = 14,
};
using transport_parameter_mask_t = std::bitset<16>;

struct transport_preferred_address {
  std::array<uint8_t, 4> addressv4;
  uint16_t portv4;
  std::array<uint8_t, 16> addressv6;
  uint16_t portv6;
  connection_id_t connection_id; // <0..18>
  token_t stateless_reset_token; // [16]
};

struct transport_parameters {
  connection_id_t original_connection_id;
  std::chrono::milliseconds idle_timeout;
  token_t stateless_reset_token;
  varint_t max_packet_size; // max/default=65527, min=1200
  varint_t initial_max_data;
  varint_t initial_max_stream_data_bidi_local;
  varint_t initial_max_stream_data_bidi_remote;
  varint_t initial_max_stream_data_uni;
  varint_t initial_max_streams_bidi;
  varint_t initial_max_streams_uni;
  varint_t ack_delay_exponent; // default=3, max=20
  std::chrono::milliseconds max_ack_delay;
  bool disable_migration;
  transport_preferred_address preferred_address;
  varint_t active_connection_id_limit; // default=0
};

} // namespace nexus::quic::detail
