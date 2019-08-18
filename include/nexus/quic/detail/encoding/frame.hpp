#pragma once

#include <nexus/quic/detail/frame.hpp>
#include <nexus/detail/encoding/encoding.hpp>
#include <nexus/quic/detail/encoding/connection_id.hpp>
#include <nexus/quic/detail/encoding/token.hpp>
#include <nexus/quic/detail/encoding/string.hpp>
#include <nexus/quic/detail/encoding/varint.hpp>

namespace nexus::quic::detail {

using nexus::detail::encoded_size;
using nexus::detail::encode1;
using nexus::detail::encode2;
using nexus::detail::decode;

// ACK
inline size_t encoded_size(const ack_range& r)
{
  return varint_length(r.gap) + varint_length(r.ack);
}

template <typename OutputIterator>
void encode(OutputIterator& out, const ack_range& r)
{
  encode1(out, varint_encoder{r.gap}, varint_encoder{r.ack});
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, ack_range& r)
{
  return decode(in, remaining, varint_decoder{r.gap}, varint_decoder{r.ack});
}

inline size_t encoded_size(const ack_frame& f)
{
  return varint_length(f.largest_acknowledged)
      + varint_length(f.ack_delay)
      + varint_length(f.ack_range_count)
      + varint_length(f.first_ack_range);
}

template <typename OutputIterator>
void encode(OutputIterator& out, const ack_frame& f)
{
  encode1(out,
          varint_encoder{f.largest_acknowledged},
          varint_encoder{f.ack_delay},
          varint_encoder{f.ack_range_count},
          varint_encoder{f.first_ack_range});
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, ack_frame& f)
{
  return decode(in, remaining,
                varint_decoder{f.largest_acknowledged},
                varint_decoder{f.ack_delay},
                varint_decoder{f.ack_range_count},
                varint_decoder{f.first_ack_range});
}

inline size_t encoded_size(const ack_ecn_counts& c)
{
  return varint_length(c.ect0) + varint_length(c.ect1) + varint_length(c.ce);
}

template <typename OutputIterator>
void encode(OutputIterator& out, const ack_ecn_counts& c)
{
  encode1(out,
          varint_encoder{c.ect0},
          varint_encoder{c.ect1},
          varint_encoder{c.ce});
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, ack_ecn_counts& c)
{
  return decode(in, remaining,
                varint_decoder{c.ect0},
                varint_decoder{c.ect1},
                varint_decoder{c.ce});
}


template <typename InputIterator>
struct ack_frame_encoder {
  const ack_frame& ack;
  InputIterator range0;
  InputIterator rangen;

  ack_frame_encoder(const ack_frame& ack,
                    InputIterator range0,
                    InputIterator rangen)
    : ack(ack), range0(range0), rangen(rangen) {}
};

template <typename InputIterator>
inline size_t encoded_size(const ack_frame_encoder<InputIterator>& e)
{
  auto size = encoded_size(e.ack);
  for (auto i = e.range0; i != e.rangen; ++i) {
    size += encoded_size(*i);
  }
  return size;
}

template <typename OutputIterator, typename InputIterator>
void encode(OutputIterator& out, const ack_frame_encoder<InputIterator>& e)
{
  encode(out, e.ack);
  for (auto i = e.range0; i != e.rangen; ++i) {
    encode(out, *i);
  }
}

template <typename OutputIterator>
struct ack_frame_decoder {
  ack_frame& ack;
  OutputIterator range;

  ack_frame_decoder(ack_frame& ack, OutputIterator range)
    : ack(ack), range(range) {}
};

template <typename InputIterator, typename OutputIterator>
bool decode(InputIterator& in, size_t& remaining,
            ack_frame_decoder<OutputIterator>&& d)
{
  if (!decode(in, remaining, d.ack)) {
    return false;
  }
  for (varint_t i = 0; i < d.ack.ack_range_count; i++, ++d.range) {
    if (!decode(in, remaining, *d.range)) {
      return false;
    }
  }
  return true;
}

template <typename InputIterator>
struct ack_ecn_frame_encoder {
  ack_frame_encoder<InputIterator> e;
  const ack_ecn_counts& c;

  ack_ecn_frame_encoder(const ack_frame& ack, InputIterator range0,
                    InputIterator rangen, const ack_ecn_counts& c)
    : e(ack, range0, rangen), c(c) {}
};

template <typename InputIterator>
inline size_t encoded_size(const ack_ecn_frame_encoder<InputIterator>& e)
{
  return encoded_size(e.e, e.c);
}

template <typename OutputIterator, typename InputIterator>
void encode(OutputIterator& out, const ack_ecn_frame_encoder<InputIterator>& e)
{
  encode1(out, e.e, e.c);
}

template <typename OutputIterator>
struct ack_ecn_frame_decoder {
  ack_frame_decoder<OutputIterator> d;
  ack_ecn_counts& c;

  ack_ecn_frame_decoder(ack_frame& ack, OutputIterator range, ack_ecn_counts& c)
    : d(ack, range), c(c) {}
};

template <typename InputIterator, typename OutputIterator>
bool decode(InputIterator& in, size_t& remaining,
            ack_ecn_frame_decoder<OutputIterator>&& d)
{
  return decode(in, remaining, std::move(d.d), d.c);
}


// RESET_STREAM
inline size_t encoded_size(const reset_stream_frame& r)
{
  return varint_length(r.stream_id)
      + varint_length(r.app_error_code)
      + varint_length(r.final_size);
}

template <typename OutputIterator>
void encode(OutputIterator& out, const reset_stream_frame& r)
{
  encode1(out,
          varint_encoder{r.stream_id},
          varint_encoder{r.app_error_code},
          varint_encoder{r.final_size});
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, reset_stream_frame& r)
{
  return decode(in, remaining,
                varint_decoder{r.stream_id},
                varint_decoder{r.app_error_code},
                varint_decoder{r.final_size});
}


// STOP_SENDING
inline size_t encoded_size(const stop_sending_frame& s)
{
  return varint_length(s.stream_id)
      + varint_length(s.app_error_code);
}

template <typename OutputIterator>
void encode(OutputIterator& out, const stop_sending_frame& s)
{
  encode1(out,
          varint_encoder{s.stream_id},
          varint_encoder{s.app_error_code});
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, stop_sending_frame& s)
{
  return decode(in, remaining,
                varint_decoder{s.stream_id},
                varint_decoder{s.app_error_code});
}


// CRYPTO
inline size_t encoded_size(const crypto_frame& c)
{
  return varint_length(c.offset)
      + varint_length(c.length);
}

template <typename OutputIterator>
void encode(OutputIterator& out, const crypto_frame& c)
{
  encode1(out,
          varint_encoder{c.offset},
          varint_encoder{c.length});
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, crypto_frame& c)
{
  return decode(in, remaining,
                varint_decoder{c.offset},
                varint_decoder{c.length});
}

// NEW_TOKEN
inline size_t encoded_size(const new_token_frame& t)
{
  return encoded_size(token_encoder{t.token});
}

template <typename OutputIterator>
void encode(OutputIterator& out, const new_token_frame& t)
{
  encode(out, token_encoder{t.token});
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, new_token_frame& t)
{
  return decode(in, remaining, token_decoder{t.token});
}


// STREAM
struct stream_frame_encoder {
  const stream_frame& s;
  uint8_t flags;
  stream_frame_encoder(const stream_frame& s, uint8_t flags)
    : s(s), flags(flags) {}
};

inline size_t encoded_size(const stream_frame_encoder& e)
{
  size_t size = varint_length(e.s.stream_id);
  if (e.flags & stream_frame_off_bit) {
    size += varint_length(e.s.offset);
  }
  if (e.flags & stream_frame_len_bit) {
    size += varint_length(e.s.length);
  }
  return size;
}

template <typename OutputIterator>
void encode(OutputIterator& out, const stream_frame_encoder& e)
{
  encode(out, varint_encoder{e.s.stream_id});
  if (e.flags & stream_frame_off_bit) {
    encode(out, varint_encoder{e.s.offset});
  }
  if (e.flags & stream_frame_len_bit) {
    encode(out, varint_encoder{e.s.length});
  }
}

struct stream_frame_decoder {
  stream_frame& s;
  uint8_t flags;
  stream_frame_decoder(stream_frame& s, uint8_t flags)
    : s(s), flags(flags) {}
};

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, stream_frame_decoder&& d)
{
  if (!decode(in, remaining, varint_decoder{d.s.stream_id})) {
    return false;
  }
  if (!(d.flags & stream_frame_off_bit)) {
    d.s.offset = 0;
  } else if (!decode(in, remaining, varint_decoder{d.s.offset})) {
    return false;
  }
  if (!(d.flags & stream_frame_len_bit)) {
    d.s.length = 0;
  } else if (!decode(in, remaining, varint_decoder{d.s.length})) {
    return false;
  }
  return true;
}


// MAX_DATA
inline size_t encoded_size(const max_data_frame& m)
{
  return varint_length(m.maximum_data);
}

template <typename OutputIterator>
void encode(OutputIterator& out, const max_data_frame& m)
{
  encode(out, varint_encoder{m.maximum_data});
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, max_data_frame& m)
{
  return decode(in, remaining, varint_decoder{m.maximum_data});
}


// MAX_STREAM_DATA
inline size_t encoded_size(const max_stream_data_frame& m)
{
  return varint_length(m.stream_id) + varint_length(m.maximum_data);
}

template <typename OutputIterator>
void encode(OutputIterator& out, const max_stream_data_frame& m)
{
  encode1(out, varint_encoder{m.stream_id}, varint_encoder{m.maximum_data});
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, max_stream_data_frame& m)
{
  return decode(in, remaining,
                varint_decoder{m.stream_id},
                varint_decoder{m.maximum_data});
}


// MAX_STREAMS
inline size_t encoded_size(const max_streams_frame& m)
{
  return varint_length(m.maximum_streams);
}

template <typename OutputIterator>
void encode(OutputIterator& out, const max_streams_frame& m)
{
  encode(out, varint_encoder{m.maximum_streams});
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, max_streams_frame& m)
{
  return decode(in, remaining, varint_decoder{m.maximum_streams});
}


// DATA_BLOCKED
inline size_t encoded_size(const data_blocked_frame& d)
{
  return varint_length(d.data_limit);
}

template <typename OutputIterator>
void encode(OutputIterator& out, const data_blocked_frame& d)
{
  encode(out, varint_encoder{d.data_limit});
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, data_blocked_frame& d)
{
  return decode(in, remaining, varint_decoder{d.data_limit});
}


// STREAM_DATA_BLOCKED
inline size_t encoded_size(const stream_data_blocked_frame& s)
{
  return varint_length(s.stream_id) + varint_length(s.data_limit);
}

template <typename OutputIterator>
void encode(OutputIterator& out, const stream_data_blocked_frame& s)
{
  encode1(out, varint_encoder{s.stream_id}, varint_encoder{s.data_limit});
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, stream_data_blocked_frame& s)
{
  return decode(in, remaining,
                varint_decoder{s.stream_id},
                varint_decoder{s.data_limit});
}


// STREAMS_BLOCKED
inline size_t encoded_size(const streams_blocked_frame& s)
{
  return varint_length(s.stream_limit);
}

template <typename OutputIterator>
void encode(OutputIterator& out, const streams_blocked_frame& s)
{
  encode(out, varint_encoder{s.stream_limit});
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, streams_blocked_frame& s)
{
  return decode(in, remaining, varint_decoder{s.stream_limit});
}


// NEW_CONNECTION_ID
inline size_t encoded_size(const new_connection_id_frame& n)
{
  return varint_length(n.sequence_number)
      + varint_length(n.retired_prior_to)
      + encoded_size(connection_id_encoder{n.connection_id})
      + encoded_size(token_encoder{n.stateless_reset_token});
}

template <typename OutputIterator>
void encode(OutputIterator& out, const new_connection_id_frame& n)
{
  encode1(out,
          varint_encoder{n.sequence_number},
          varint_encoder{n.retired_prior_to},
          connection_id_encoder{n.connection_id},
          token_encoder{n.stateless_reset_token});
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, new_connection_id_frame& n)
{
  return decode(in, remaining,
                varint_decoder{n.sequence_number},
                varint_decoder{n.retired_prior_to},
                connection_id_decoder{n.connection_id},
                token_decoder{n.stateless_reset_token});
}


// RETIRE_CONNECTION_ID
inline size_t encoded_size(const retire_connection_id_frame& r)
{
  return varint_length(r.sequence_number);
}

template <typename OutputIterator>
void encode(OutputIterator& out, const retire_connection_id_frame& r)
{
  encode(out, varint_encoder{r.sequence_number});
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, retire_connection_id_frame& r)
{
  return decode(in, remaining, varint_decoder{r.sequence_number});
}


// PATH_CHALLENGE
inline size_t encoded_size(const path_challenge_frame&)
{
  return 8; // XXX: assert(p.data.size() == 8)
}

template <typename OutputIterator>
void encode(OutputIterator& out, const path_challenge_frame& p)
{
  encode(out, string_encoder{p.data});
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, path_challenge_frame& p)
{
  return decode(in, remaining, string_decoder{p.data, 8});
}


// PATH_RESPONSE
inline size_t encoded_size(const path_response_frame&)
{
  return 8; // XXX: assert(p.data.size() == 8)
}

template <typename OutputIterator>
void encode(OutputIterator& out, const path_response_frame& p)
{
  encode(out, string_encoder{p.data});
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, path_response_frame& p)
{
  return decode(in, remaining, string_decoder{p.data, 8});
}


// CONNECTION_CLOSE
inline size_t encoded_size(const connection_close_frame& c)
{
  return varint_length(c.error_code)
      + varint_length(c.frame_type)
      + encoded_size(varint_prefix_string_encoder{c.reason_phrase});
}

template <typename OutputIterator>
void encode(OutputIterator& out, const connection_close_frame& c)
{
  encode1(out,
          varint_encoder{c.error_code},
          varint_encoder{c.frame_type},
          varint_prefix_string_encoder{c.reason_phrase});
}

template <typename InputIterator>
bool decode(InputIterator& in, size_t& remaining, connection_close_frame& c)
{
  return decode(in, remaining,
                varint_decoder{c.error_code},
                varint_decoder{c.frame_type},
                varint_prefix_string_decoder{c.reason_phrase});
}

} // namespace nexus::quic::detail
