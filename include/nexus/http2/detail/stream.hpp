#pragma once

#include <boost/intrusive/set.hpp>
#include <boost/intrusive/list.hpp>

#include <nexus/http2/basic_fields.hpp>
#include <nexus/http2/protocol.hpp>
#include <nexus/http2/detail/stream_buffer.hpp>

namespace nexus::http2::detail {

struct stream_waiter {
  virtual void complete(boost::system::error_code ec) = 0;
  virtual ~stream_waiter() {}
};

namespace bi = boost::intrusive;

struct stream_impl : bi::set_base_hook<bi::optimize_size<true>>,
                     bi::list_base_hook<> {
  protocol::stream_identifier id = 0;
  protocol::stream_state state = protocol::stream_state::idle;
  protocol::stream_priority priority;
  // flow control
  protocol::flow_control_ssize_type inbound_window =
      protocol::default_setting_initial_window_size;
  protocol::flow_control_ssize_type outbound_window =
      protocol::default_setting_initial_window_size;

  stream_waiter* reader = nullptr;
  boost::intrusive::list<detail::field_pair<>> headers;
  boost::intrusive::list<stream_buffer> buffers;
  bool read_headers = false;

  ~stream_impl() {
    headers.clear_and_dispose(std::default_delete<detail::field_pair<>>{});
    buffers.clear_and_dispose(std::default_delete<stream_buffer>{});
  }
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

} // namespace nexus::http2::detail
