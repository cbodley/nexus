#pragma once

#include <string>
#include <nexus/quic/detail/connection_id.hpp>
#include <nexus/quic/detail/token.hpp>
#include <nexus/quic/detail/varint.hpp>

namespace nexus::quic::detail {

using frame_type_t = varint_t;

// ACK
struct ack_range {
  varint_t gap;
  varint_t ack;
};

struct ack_frame {
  varint_t largest_acknowledged;
  varint_t ack_delay;
  varint_t ack_range_count;
  varint_t first_ack_range;
};

struct ack_ecn_counts {
  varint_t ect0;
  varint_t ect1;
  varint_t ce;
};


// RESET_STREAM
struct reset_stream_frame {
  varint_t stream_id;
  varint_t app_error_code;
  varint_t final_size;
};


// STOP_SENDING
struct stop_sending_frame {
  varint_t stream_id;
  varint_t app_error_code;
};


// CRYPTO
struct crypto_frame {
  varint_t offset;
  varint_t length;
};


// NEW_TOKEN
struct new_token_frame {
  token_t token;
};


// STREAM
struct stream_frame {
  varint_t stream_id;
  varint_t offset;
  varint_t length;
};

// flags encoded in the stream frame type
static constexpr uint8_t stream_frame_fin_bit = 0x1;
static constexpr uint8_t stream_frame_len_bit = 0x2;
static constexpr uint8_t stream_frame_off_bit = 0x4;


// MAX_DATA
struct max_data_frame {
  varint_t maximum_data;
};


// MAX_STREAM_DATA
struct max_stream_data_frame {
  varint_t stream_id;
  varint_t maximum_data;
};


// MAX_STREAMS
struct max_streams_frame {
  varint_t maximum_streams;
};


// DATA_BLOCKED
struct data_blocked_frame {
  varint_t data_limit;
};


// STREAM_DATA_BLOCKED
struct stream_data_blocked_frame {
  varint_t stream_id;
  varint_t data_limit;
};


// STREAMS_BLOCKED
struct streams_blocked_frame {
  varint_t stream_limit;
};


// NEW_CONNECTION_ID
struct new_connection_id_frame {
  varint_t sequence_number;
  varint_t retired_prior_to;
  connection_id_t connection_id;
  token_t stateless_reset_token;
};


// RETIRE_CONNECTION_ID
struct retire_connection_id_frame {
  varint_t sequence_number;
};


// PATH_CHALLENGE
struct path_challenge_frame {
  std::string data; // size=8
};


// PATH_RESPONSE
struct path_response_frame {
  std::string data; // size=8
};


// CONNECTION_CLOSE
struct connection_close_frame {
  varint_t error_code;
  varint_t frame_type;
  std::string reason_phrase;
};

} // namespace nexus::quic::detail
