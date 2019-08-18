#pragma once

#include <optional>

#include <nexus/quic/detail/flow_control.hpp>

namespace nexus::quic {

using stream_id_t = uint64_t;

namespace detail {

constexpr stream_id_t server_initiated = 0x1;
constexpr stream_id_t unidirectional = 0x2;

enum class send_state : uint8_t {
  ready,
  send,
  sent,
  received,
  reset_sent,
  reset_received
};

struct sending_stream {
  send_state state = send_state::ready;
  flow_control_data flow_control;
};

enum class receive_state : uint8_t {
  receiving,
  size_known,
  received,
  read,
  reset_received,
  reset_read
};

struct receiving_stream {
  receive_state state = receive_state::receiving;
  flow_control_data flow_control;
};

} // namespace detail

class stream {
  std::optional<stream_id_t> id_;
  detail::sending_stream sender_;
  detail::receiving_stream receiver_;
 public:
  std::optional<stream_id_t> id() const { return id_; }
};

} // namespace nexus::quic
