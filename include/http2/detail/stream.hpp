#pragma once

#include <boost/intrusive/set.hpp>

#include <http2/protocol.hpp>

namespace http2::detail {

namespace bi = boost::intrusive;

struct stream_impl : bi::set_base_hook<bi::optimize_size<true>> {
  protocol::stream_identifier id = 0;
  protocol::stream_state state = protocol::stream_state::idle;
  // flow control
  protocol::flow_control_ssize_type inbound_window =
      protocol::default_setting_initial_window_size;
  protocol::flow_control_ssize_type outbound_window =
      protocol::default_setting_initial_window_size;
  // prioritization
  protocol::stream_identifier stream_dependency = 0;
  uint16_t weight = 16; // [1, 256]
};

struct stream_id_less {
  constexpr bool operator()(const stream_impl& lhs,
                            const stream_impl& rhs) const {
    return lhs.id < rhs.id;
  }
  constexpr bool operator()(protocol::stream_identifier lhs,
                            const stream_impl& rhs) const {
    return lhs < rhs.id;
  }
  constexpr bool operator()(const stream_impl& lhs,
                            protocol::stream_identifier rhs) const {
    return lhs.id < rhs;
  }
};
using stream_set = bi::set<stream_impl, bi::compare<stream_id_less>>;

} // namespace http2::detail
