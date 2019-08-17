#pragma once

#include <cstdint>

#include <nexus/quic/detail/connection_id.hpp>
#include <nexus/quic/detail/token.hpp>
#include <nexus/quic/detail/varint.hpp>

namespace nexus::quic::detail {

constexpr uint8_t long_packet_header_mask = 0x80;
constexpr uint8_t packet_fixed_bit_mask = 0x40;

constexpr uint8_t packet_number_length_mask = 0x03;

constexpr uint8_t long_packet_type_mask = 0x30;
constexpr uint8_t long_packet_type_initial = 0x00;
constexpr uint8_t long_packet_type_0rtt = 0x10;
constexpr uint8_t long_packet_type_handshake = 0x20;
constexpr uint8_t long_packet_type_retry = 0x30;
constexpr uint8_t long_packet_type_specific_mask = 0x0f;

using version_t = uint32_t;
using packet_number_t = uint32_t;

struct long_header {
  version_t version;
  connection_id_t destination;
  connection_id_t source;
};

struct initial_packet {
  token_t token;
  packet_number_t packet_number;
  varint_t payload_length;
};

struct zero_rtt_packet {
  packet_number_t packet_number;
  varint_t payload_length;
};

struct handshake_packet {
  packet_number_t packet_number;
  varint_t payload_length;
};

struct retry_packet {
  connection_id_t original_destination;
  token_t retry_token;
};

} // namespace nexus::quic::detail
