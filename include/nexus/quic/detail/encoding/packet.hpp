#pragma once

#include <boost/asio/buffers_iterator.hpp>

#include <nexus/quic/detail/packet.hpp>
#include <nexus/detail/encoding/encoding.hpp>
#include <nexus/quic/detail/encoding/connection_id.hpp>
#include <nexus/quic/detail/encoding/token.hpp>
#include <nexus/quic/detail/encoding/varint.hpp>

namespace nexus::quic::detail {

template <typename DynamicBuffer>
size_t encode_header(uint8_t head, const long_header& header,
                     DynamicBuffer& buffer)
{
  return encode2(buffer,
                network_order_encoder<uint8_t>{head},
                network_order_encoder<uint32_t>{header.version},
                connection_id_encoder{header.destination},
                connection_id_encoder{header.source});
}

template <typename DynamicBuffer>
size_t encode_packet(const initial_packet& packet, DynamicBuffer& buffer)
{
  const size_t nonzero_packet_number = std::max<packet_number_t>(1, packet.packet_number);
  const size_t packet_number_length = 1 + log2_nonzero(nonzero_packet_number) / 8;
  const size_t length = packet.payload_length + packet_number_length;

  return encode2(buffer,
                varint_prefix_string_encoder{packet.token},
                varint_encoder{length},
                network_order_encoder{packet.packet_number, packet_number_length});
}

template <typename DynamicBuffer>
size_t encode_packet(const zero_rtt_packet& packet, DynamicBuffer& buffer)
{
  const size_t nonzero_packet_number = std::max<packet_number_t>(1, packet.packet_number);
  const size_t packet_number_length = 1 + log2_nonzero(nonzero_packet_number) / 8;
  const size_t length = packet.payload_length + packet_number_length;
  return encode2(buffer,
                varint_encoder{length},
                network_order_encoder{packet.packet_number, packet_number_length});
}

template <typename DynamicBuffer>
size_t encode_packet(const handshake_packet& packet, DynamicBuffer& buffer)
{
  const size_t nonzero_packet_number = std::max<packet_number_t>(1, packet.packet_number);
  const size_t packet_number_length = 1 + log2_nonzero(nonzero_packet_number) / 8;
  const size_t length = packet.payload_length + packet_number_length;
  return encode2(buffer,
                varint_encoder{length},
                network_order_encoder{packet.packet_number, packet_number_length});
}

template <typename DynamicBuffer>
size_t encode_packet(const retry_packet& packet, DynamicBuffer& buffer)
{
  const std::string& token = packet.retry_token; // XXX: no explicit token length?
  return encode2(buffer,
                connection_id_encoder{packet.original_destination},
                string_encoder{token});
}


template <typename InputIterator>
bool decode_head(uint8_t& head, InputIterator& in, size_t& remaining)
{
  return decode(in, remaining, network_order_decoder{head});
}

template <typename InputIterator>
bool decode_header(long_header& header, InputIterator& in, size_t& remaining)
{
  return decode(in, remaining,
                network_order_decoder<uint32_t>{header.version},
                connection_id_decoder{header.destination},
                connection_id_decoder{header.source});
}

template <typename InputIterator>
bool decode_payload_length(InputIterator& in, size_t& remaining,
                           varint_t& payload_length,
                           uint8_t packet_number_length)
{
  varint_t length = 0;
  if (!decode(in, remaining, varint_decoder{length})) {
    return false;
  }
  if (length < packet_number_length) {
    return false;
  }
  payload_length = length - packet_number_length;
  return true;
}

template <typename InputIterator>
bool decode_packet(initial_packet& packet, uint8_t packet_number_length,
                   InputIterator& in, size_t& remaining)
{
  return decode(in, remaining, varint_prefix_string_decoder{packet.token})
      && decode_payload_length(in, remaining, packet.payload_length,
                               packet_number_length)
      && decode(in, remaining, network_order_decoder{packet.packet_number,
                                                     packet_number_length});
}

template <typename InputIterator>
bool decode_packet(zero_rtt_packet& packet, uint8_t packet_number_length,
                   InputIterator& in, size_t& remaining)
{
  return decode_payload_length(in, remaining, packet.payload_length,
                               packet_number_length)
      && decode(in, remaining, network_order_decoder{packet.packet_number,
                                                     packet_number_length});
}

template <typename InputIterator>
bool decode_packet(handshake_packet& packet, uint8_t packet_number_length,
                   InputIterator& in, size_t& remaining)
{
  return decode_payload_length(in, remaining, packet.payload_length,
                               packet_number_length)
      && decode(in, remaining, network_order_decoder{packet.packet_number,
                                                     packet_number_length});
}

template <typename InputIterator>
bool decode_packet(retry_packet& packet, InputIterator& in, size_t& remaining)
{
  if (!decode(in, remaining, connection_id_decoder{packet.original_destination})) {
    return false;
  }
  // XXX: assumes that retry token length is implicit in the packet size
  size_t retry_token_length = remaining;
  return decode(in, remaining, string_decoder{packet.retry_token, retry_token_length});
}

template <typename Dispatcher, typename InputIterator>
bool decode_packet(Dispatcher& dispatcher, InputIterator& in, size_t& remaining)
{
  uint8_t head = 0;
  if (!decode_network_order(head, in, remaining)) {
    return false;
  }
  if ((head & packet_fixed_bit_mask) == 0) {
    return false;
  }
  // TODO: remove packet header protection
  if ((head & long_packet_header_mask) == 0) {
    return false; // TODO: implement short header decoding
  }
  long_header header;
  if (!decode_header(header, in, remaining)) {
    return false;
  }
  const uint8_t type = head & long_packet_type_mask;
  const uint8_t packet_number_length = (head & packet_number_length_mask) + 1;
  if (type == long_packet_type_initial) {
    initial_packet packet;
    return decode_packet(packet, packet_number_length, in, remaining)
        && dispatcher(header, packet, in, remaining);
  }
  if (type == long_packet_type_0rtt) {
    zero_rtt_packet packet;
    return decode_packet(packet, packet_number_length, in, remaining)
        && dispatcher(header, packet, in, remaining);
  }
  if (type == long_packet_type_handshake) {
    handshake_packet packet;
    return decode_packet(packet, packet_number_length, in, remaining)
        && dispatcher(header, packet, in, remaining);
  }
  if (type == long_packet_type_retry) {
    retry_packet packet;
    return decode_packet(packet, in, remaining)
        && dispatcher(header, packet, in, remaining);
  }
  return false;
}

} // namespace nexus::quic::detail
