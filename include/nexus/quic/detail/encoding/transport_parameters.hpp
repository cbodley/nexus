#pragma once

#include <bitset>

#include <nexus/quic/detail/transport_parameters.hpp>
#include <nexus/detail/encoding/array.hpp>
#include <nexus/detail/encoding/encoding.hpp>
#include <nexus/detail/encoding/network_order.hpp>
#include <nexus/quic/detail/encoding/connection_id.hpp>
#include <nexus/quic/detail/encoding/varint.hpp>

namespace nexus::quic::detail {

size_t encoded_size(transport_parameter_id)
{
  return sizeof(uint16_t);
}

template <typename OutputIterator>
void encode(OutputIterator& out, transport_parameter_id id)
{
  using T = std::underlying_type_t<transport_parameter_id>;
  encode(out, network_order_encoder{static_cast<T>(id)});
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining,
            transport_parameter_id& id)
{
  std::underlying_type_t<transport_parameter_id> value;
  if (!decode(in, remaining, network_order_decoder{value})) {
    return false;
  }
  id = static_cast<transport_parameter_id>(value);
  return true;
}

using nexus::detail::byte_array_encoder;
using nexus::detail::byte_array_decoder;

size_t encoded_size(const transport_preferred_address& a)
{
  return sizeof(a.addressv4) + sizeof(a.portv4)
      + sizeof(a.addressv6) + sizeof(a.portv6)
      + 1 + a.connection_id.size()
      + 16;
}

template <typename OutputIterator>
void encode(OutputIterator& out, const transport_preferred_address& a)
{
  encode1(out,
         byte_array_encoder{a.addressv4},
         network_order_encoder{a.portv4},
         byte_array_encoder{a.addressv6},
         network_order_encoder{a.portv6},
         connection_id_encoder{a.connection_id},
         string_encoder{a.stateless_reset_token});
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining,
            transport_preferred_address& a)
{
  return decode(in, remaining,
                byte_array_decoder{a.addressv4},
                network_order_decoder{a.portv4},
                byte_array_decoder{a.addressv6},
                network_order_decoder{a.portv6},
                connection_id_decoder{a.connection_id},
                string_decoder{a.stateless_reset_token, 16});
}


template <typename Rep, typename Period>
struct varint_duration_encoder {
  std::chrono::duration<Rep, Period> dur;
  varint_duration_encoder(std::chrono::duration<Rep, Period> dur) : dur(dur) {}
};

template <typename Rep, typename Period>
size_t encoded_size(const varint_duration_encoder<Rep, Period>& e)
{
  return varint_length(static_cast<varint_t>(e.dur.count()));
}

template <typename OutputIterator, typename Rep, typename Period>
void encode(OutputIterator& out, const varint_duration_encoder<Rep, Period>& e)
{
  encode(out, varint_encoder{static_cast<varint_t>(e.dur.count())});
}

template <typename Rep, typename Period>
struct varint_duration_decoder {
  std::chrono::duration<Rep, Period>& dur;
  varint_duration_decoder(std::chrono::duration<Rep, Period>& dur) : dur(dur) {}
};

template <typename InputIterator, typename Rep, typename Period>
bool decode(InputIterator& in, size_t& remaining,
            varint_duration_decoder<Rep, Period>&& d)
{
  varint_t count = 0;
  if (!decode(in, remaining, varint_decoder{count})) {
    return false;
  }
  d.dur = std::chrono::duration<Rep, Period>(count);
  return true;
}


struct transport_parameters_encoder {
  const transport_parameters& params;
  transport_parameter_mask_t mask;
  struct parameter_pair {
    transport_parameter_id id;
    uint16_t length;
  };
  using parameter_array = std::array<parameter_pair, 16>;
  parameter_array pairs;
  parameter_array::iterator end;

  bool test(transport_parameter_id id) const {
    return mask.test(static_cast<size_t>(id));
  }

  transport_parameters_encoder(const transport_parameters& params,
                               transport_parameter_mask_t mask)
    : params(params), mask(mask), end(pairs.begin())
  {
    if (test(transport_parameter_id::original_connection_id)) {
      end->id = transport_parameter_id::original_connection_id;
      end->length = params.original_connection_id.size();
      ++end;
    }
    if (test(transport_parameter_id::idle_timeout)) {
      end->id = transport_parameter_id::idle_timeout;
      end->length = varint_length(params.idle_timeout.count());
      ++end;
    }
    if (test(transport_parameter_id::stateless_reset_token)) {
      end->id = transport_parameter_id::stateless_reset_token;
      end->length = 16;
      ++end;
    }
    if (test(transport_parameter_id::max_packet_size)) {
      end->id = transport_parameter_id::max_packet_size;
      end->length = varint_length(params.max_packet_size);
      ++end;
    }
    if (test(transport_parameter_id::initial_max_data)) {
      end->id = transport_parameter_id::initial_max_data;
      end->length = varint_length(params.initial_max_data);
      ++end;
    }
    if (test(transport_parameter_id::initial_max_stream_data_bidi_local)) {
      end->id = transport_parameter_id::initial_max_stream_data_bidi_local;
      end->length = varint_length(params.initial_max_stream_data_bidi_local);
      ++end;
    }
    if (test(transport_parameter_id::initial_max_stream_data_bidi_remote)) {
      end->id = transport_parameter_id::initial_max_stream_data_bidi_remote;
      end->length = varint_length(params.initial_max_stream_data_bidi_remote);
      ++end;
    }
    if (test(transport_parameter_id::initial_max_stream_data_uni)) {
      end->id = transport_parameter_id::initial_max_stream_data_uni;
      end->length = varint_length(params.initial_max_stream_data_uni);
      ++end;
    }
    if (test(transport_parameter_id::initial_max_streams_bidi)) {
      end->id = transport_parameter_id::initial_max_streams_bidi;
      end->length = varint_length(params.initial_max_streams_bidi);
      ++end;
    }
    if (test(transport_parameter_id::initial_max_streams_uni)) {
      end->id = transport_parameter_id::initial_max_streams_uni;
      end->length = varint_length(params.initial_max_streams_uni);
      ++end;
    }
    if (test(transport_parameter_id::ack_delay_exponent)) { 
      end->id = transport_parameter_id::ack_delay_exponent;
      end->length = varint_length(params.ack_delay_exponent);
      ++end;
    }
    if (test(transport_parameter_id::max_ack_delay)) { 
      end->id = transport_parameter_id::max_ack_delay;
      end->length = varint_length(params.max_ack_delay.count());
      ++end;
    }
    if (test(transport_parameter_id::disable_migration)) { 
      end->id = transport_parameter_id::disable_migration;
      end->length = 0;
      ++end;
    }
    if (test(transport_parameter_id::preferred_address)) {
      end->id = transport_parameter_id::preferred_address;
      end->length = encoded_size(params.preferred_address);
      ++end;
    }
    if (test(transport_parameter_id::active_connection_id_limit)) {
      end->id = transport_parameter_id::active_connection_id_limit;
      end->length = varint_length(params.active_connection_id_limit);
      ++end;
    }
  }
};

size_t encoded_size(const transport_parameters_encoder& e)
{
  size_t sum = sizeof(uint16_t); // 16-bit count of parameters
  for (auto i = e.pairs.begin(); i != e.end; ++i) {
    sum += 4 + i->length; // 16-bit id and 16-bit length
  }
  return sum;
}

template <typename OutputIterator>
void encode_param(OutputIterator& out, transport_parameter_id id,
                  uint16_t length, const transport_parameters& p)
{
  encode1(out, id, network_order_encoder{length});

  switch (id) {
    case transport_parameter_id::original_connection_id:
      encode(out, string_encoder{p.original_connection_id});
      break;
    case transport_parameter_id::idle_timeout:
      encode(out, varint_duration_encoder{p.idle_timeout});
      break;
    case transport_parameter_id::stateless_reset_token:
      encode(out, string_encoder{p.stateless_reset_token});
      break;
    case transport_parameter_id::max_packet_size:
      encode(out, varint_encoder{p.max_packet_size});
      break;
    case transport_parameter_id::initial_max_data:
      encode(out, varint_encoder{p.initial_max_data});
      break;
    case transport_parameter_id::initial_max_stream_data_bidi_local:
      encode(out, varint_encoder{p.initial_max_stream_data_bidi_local});
      break;
    case transport_parameter_id::initial_max_stream_data_bidi_remote:
      encode(out, varint_encoder{p.initial_max_stream_data_bidi_remote});
      break;
    case transport_parameter_id::initial_max_stream_data_uni:
      encode(out, varint_encoder{p.initial_max_stream_data_uni});
      break;
    case transport_parameter_id::initial_max_streams_bidi:
      encode(out, varint_encoder{p.initial_max_streams_bidi});
      break;
    case transport_parameter_id::initial_max_streams_uni:
      encode(out, varint_encoder{p.initial_max_streams_uni});
      break;
    case transport_parameter_id::ack_delay_exponent:
      encode(out, varint_encoder{p.ack_delay_exponent});
      break;
    case transport_parameter_id::max_ack_delay:
      encode(out, varint_duration_encoder{p.max_ack_delay});
      break;
    case transport_parameter_id::disable_migration:
      break;
    case transport_parameter_id::preferred_address:
      encode(out, p.preferred_address);
      break;
    case transport_parameter_id::active_connection_id_limit:
      encode(out, varint_encoder{p.active_connection_id_limit});
      break;
  }
}

template <typename OutputIterator>
void encode(OutputIterator& out, const transport_parameters_encoder& e)
{
  const uint16_t count = e.mask.count();
  encode(out, network_order_encoder{count});

  for (auto i = e.pairs.begin(); i != e.end; ++i) {
    encode_param(out, i->id, i->length, e.params);
  }
}

struct transport_parameters_decoder {
  transport_parameters& params;
  transport_parameter_mask_t& mask;
};

template <typename InputIterator>
bool decode_param(InputIterator& in, size_t& remaining,
                  transport_parameter_id id, transport_parameters& p)
{
  transport_value_len_t len = 0;
  if (!decode(in, remaining, network_order_decoder{len})) {
    return false;
  }
  switch (id) {
    case transport_parameter_id::original_connection_id:
      return decode(in, remaining, string_decoder{p.original_connection_id, len});
    case transport_parameter_id::idle_timeout:
      return decode(in, remaining, varint_duration_decoder{p.idle_timeout});
    case transport_parameter_id::stateless_reset_token:
      return decode(in, remaining, string_decoder{p.stateless_reset_token, 16});
    case transport_parameter_id::max_packet_size:
      return decode(in, remaining, varint_decoder{p.max_packet_size});
    case transport_parameter_id::initial_max_data:
      return decode(in, remaining, varint_decoder{p.initial_max_data});
    case transport_parameter_id::initial_max_stream_data_bidi_local:
      return decode(in, remaining, varint_decoder{p.initial_max_stream_data_bidi_local});
    case transport_parameter_id::initial_max_stream_data_bidi_remote:
      return decode(in, remaining, varint_decoder{p.initial_max_stream_data_bidi_remote});
    case transport_parameter_id::initial_max_stream_data_uni:
      return decode(in, remaining, varint_decoder{p.initial_max_stream_data_uni});
    case transport_parameter_id::initial_max_streams_bidi:
      return decode(in, remaining, varint_decoder{p.initial_max_streams_bidi});
    case transport_parameter_id::initial_max_streams_uni:
      return decode(in, remaining, varint_decoder{p.initial_max_streams_uni});
    case transport_parameter_id::ack_delay_exponent:
      return decode(in, remaining, varint_decoder{p.ack_delay_exponent});
    case transport_parameter_id::max_ack_delay:
      return decode(in, remaining, varint_duration_decoder{p.max_ack_delay});
    case transport_parameter_id::disable_migration:
      return p.disable_migration = true;
    case transport_parameter_id::preferred_address:
      return decode(in, remaining, p.preferred_address);
    case transport_parameter_id::active_connection_id_limit:
      return decode(in, remaining, varint_decoder{p.active_connection_id_limit});
    default:
      return false;
  }
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining,
            transport_parameters_decoder&& d)
{
  uint16_t count;
  if (!decode(in, remaining, network_order_decoder{count})) {
    return false;
  }
  for (uint16_t i = 0; i < count; i++) {
    std::underlying_type_t<transport_parameter_id> id;
    if (!decode(in, remaining, network_order_decoder{id})) {
      return false;
    }
    if (!decode_param(in, remaining, static_cast<transport_parameter_id>(id),
                      d.params)) {
      return false;
    }
    d.mask.set(id);
  }
  return true;
}

} // namespace nexus::quic::detail
