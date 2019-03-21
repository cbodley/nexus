#pragma once

#include <limits>
#include <optional>

#include <boost/asio/streambuf.hpp>
#include <boost/intrusive/set.hpp>

#include <http2/error.hpp>
#include <http2/protocol.hpp>
#include <http2/detail/frame.hpp>
#include <http2/detail/priority.hpp>
#include <http2/detail/settings.hpp>
#include <http2/detail/stream.hpp>

#include <http2/detail/hpack/header.hpp>

namespace http2 {

struct client_tag_t {};
inline constexpr client_tag_t client_tag{};
struct server_tag_t {};
inline constexpr server_tag_t server_tag{};

template <typename Stream>
class basic_connection {
 public:
  using next_layer_type = Stream;
  using lowest_layer_type = typename next_layer_type::lowest_layer_type;
  using executor_type = typename next_layer_type::executor_type;
 protected:
  using buffer_type = boost::asio::streambuf; // TODO: Allocator
  next_layer_type stream;
  detail::stream_set streams;

  struct endpoint {
    protocol::setting_values settings = protocol::default_settings;
    protocol::flow_control_ssize_type window =
        protocol::default_setting_initial_window_size;
    protocol::stream_identifier stream_in_headers = 0;
    protocol::stream_identifier next_stream_id;
    std::optional<buffer_type> buffer;
    std::optional<detail::hpack::dynamic_table> table;

    explicit constexpr endpoint(client_tag_t) : next_stream_id(1) {}
    explicit constexpr endpoint(server_tag_t) : next_stream_id(2) {}
  };
  endpoint self;
  endpoint peer;

  protocol::setting_values settings_sent = protocol::default_settings;
  protocol::setting_values settings_desired;

  buffer_type& output_buffers() {
    if (!peer.buffer) {
      peer.buffer.emplace(self.settings.max_frame_size);
    }
    return *peer.buffer;
  }
  buffer_type& input_buffers() {
    if (!self.buffer) {
      self.buffer.emplace(peer.settings.max_frame_size);
    }
    return *self.buffer;
  }

  template <typename ConstBufferSequence>
  void send_data(const ConstBufferSequence& buffers,
                 protocol::stream_identifier stream_id,
                 boost::system::error_code& ec);

  template <typename Fields>
  void send_headers(const Fields& fields,
                    protocol::stream_identifier stream_id,
                    boost::system::error_code& ec);

  void send_settings(boost::system::error_code& ec);

  void send_window_update(protocol::stream_identifier stream_id,
                          protocol::flow_control_size_type increment,
                          boost::system::error_code& ec);

  void handle_data(const protocol::frame_header& header,
                   boost::system::error_code& ec);

  void handle_headers(const protocol::frame_header& header,
                      boost::system::error_code& ec);

  void handle_settings(const protocol::frame_header& header,
                       boost::system::error_code& ec);
  void handle_settings_ack(const protocol::frame_header& header,
                           boost::system::error_code& ec);

  void handle_window_update(const protocol::frame_header& header,
                            boost::system::error_code& ec);

  void adjust_inbound_window(protocol::flow_control_ssize_type increment,
                             boost::system::error_code& ec);
  void adjust_outbound_window(protocol::flow_control_ssize_type increment,
                              boost::system::error_code& ec);
 public:
  template <typename ...Args>
  basic_connection(client_tag_t, const protocol::setting_values& settings,
                   Args&& ...args)
    : stream(std::forward<Args>(args)...),
      self(client_tag),
      peer(server_tag),
      settings_desired(settings)
  {}
  template <typename ...Args>
  basic_connection(server_tag_t, const protocol::setting_values& settings,
                   Args&& ...args)
    : stream(std::forward<Args>(args)...),
      self(server_tag),
      peer(client_tag),
      settings_desired(settings)
  {}
  ~basic_connection() {
    streams.clear_and_dispose(std::default_delete<detail::stream_impl>{});
  }

  next_layer_type& next_layer() { return stream; }
  const next_layer_type& next_layer() const { return stream; }
  lowest_layer_type& lowest_layer() { return stream.lowest_layer(); }
  const lowest_layer_type& lowest_layer() const { return stream.lowest_layer(); }
  executor_type get_executor() { return stream.get_executor(); }

  void set_header_table_size(protocol::setting_value value) {
    settings_desired.max_header_list_size = value;
  }
  void set_enable_push(protocol::setting_value value) {
    settings_desired.enable_push = value;
  }
  void set_max_concurrent_streams(protocol::setting_value value) {
    settings_desired.max_concurrent_streams = value;
  }
  void set_initial_window_size(protocol::setting_value value) {
    settings_desired.initial_window_size = value;
  }
  void set_max_frame_size(protocol::setting_value value) {
    settings_desired.max_frame_size = value;
  }
  void set_max_header_list_size(protocol::setting_value value) {
    settings_desired.max_header_list_size = value;
  }

  void run(boost::system::error_code& ec);
};

namespace detail {
void checked_adjust_window(protocol::flow_control_ssize_type& window,
                           protocol::flow_control_ssize_type increment,
                           boost::system::error_code& ec)
{
  using limits = std::numeric_limits<protocol::flow_control_ssize_type>;
  if (increment < 0) {
    if (window < limits::min() - increment) {
      ec = make_error_code(protocol::error::flow_control_error);
      return;
    }
  } else if (window > limits::max() - increment) {
    ec = make_error_code(protocol::error::flow_control_error);
    return;
  }
  window += increment;
}
} // namespace detail

template <typename Stream>
template <typename ConstBufferSequence>
void basic_connection<Stream>::send_data(
    const ConstBufferSequence& buffers,
    protocol::stream_identifier stream_id,
    boost::system::error_code& ec)
{
  if (stream_id == 0) {
    ec = make_error_code(protocol::error::protocol_error);
    return;
  }
  auto stream = streams.find(stream_id, detail::stream_id_less{});
  if (stream == streams.end()) {
    ec = make_error_code(protocol::error::protocol_error);
    return;
  }
  switch (stream->state) {
    // allowed states
    case protocol::stream_state::open: break;
    case protocol::stream_state::half_closed_remote: break;
    // disallowed states
    default:
      ec = make_error_code(protocol::error::stream_closed);
      return;
  }

  constexpr auto type = protocol::frame_type::data;
  constexpr uint8_t flags = 0;
  detail::write_frame(next_layer(), type, flags, stream_id,
                      buffers, ec);
}

template <typename Stream>
template <typename Fields>
void basic_connection<Stream>::send_headers(
    const Fields& fields,
    protocol::stream_identifier stream_id,
    boost::system::error_code& ec)
{
  detail::stream_set::iterator stream;

  if (stream_id) {
    stream = streams.find(stream_id, detail::stream_id_less{});
    if (stream == streams.end()) {
      ec = make_error_code(protocol::error::protocol_error);
      return;
    }
    switch (stream->state) {
      // allowed states
      case protocol::stream_state::idle:
        stream->state = protocol::stream_state::open;
        break;
      case protocol::stream_state::open:
        break;
      case protocol::stream_state::reserved_local:
        stream->state = protocol::stream_state::half_closed_remote;
        break;
      case protocol::stream_state::half_closed_remote:
        break;
      // disallowed states
      case protocol::stream_state::reserved_remote:
        ec = make_error_code(protocol::error::protocol_error);
        return;
      case protocol::stream_state::half_closed_local:
        [[fallthrough]];
      case protocol::stream_state::closed:
        ec = make_error_code(protocol::error::stream_closed);
        return;
    }
  } else {
    stream_id = self.next_stream_id;
    self.next_stream_id += 2;
    // new stream
    auto impl = std::make_unique<detail::stream_impl>();
    impl->id = stream_id;
    impl->state = protocol::stream_state::open;
    impl->inbound_window = self.settings.initial_window_size;
    impl->outbound_window = peer.settings.initial_window_size;
    stream = streams.insert(streams.end(), *impl.release());
    // TODO: close any of our idle streams with lower id
  }
  if (!peer.table) {
    peer.table.emplace(peer.settings.header_table_size);
  }
  // TODO: buffer won't hold more than one frame
  // TODO: stop encoding at the end of a buffer and restart with the next continuation
  auto& buffer = output_buffers();
  try {
    detail::hpack::encode_headers(fields, *peer.table, buffer);
  } catch (const std::length_error&) {
    ec = make_error_code(protocol::error::frame_size_error);
    return;
  }
  constexpr auto type = protocol::frame_type::headers;
  constexpr uint8_t flags = 0;
  detail::write_frame(next_layer(), type, flags, stream_id,
                      buffer.data(), ec);
  buffer.consume(buffer.size());
}

template <typename Stream>
void basic_connection<Stream>::send_settings(boost::system::error_code& ec)
{
  if (self.settings != settings_sent) {
    // our last settings haven't been acked yet
    ec = make_error_code(protocol::error::settings_timeout);
    return;
  }
  protocol::setting_parameters settings;
  auto settings_end = protocol::detail::copy_changes(settings.begin(),
                                                     settings_sent,
                                                     settings_desired);

  if (settings_desired.max_frame_size > settings_sent.max_frame_size) {
    self.buffer.emplace(settings_desired.max_frame_size);
  }
  if (settings_desired.header_table_size != settings_sent.header_table_size &&
      peer.table) {
    peer.table->set_size(settings_desired.header_table_size);
  }
  settings_sent = settings_desired;

  auto& buffer = output_buffers();
  assert(buffer.size() == 0);
  detail::write_settings(next_layer(), buffer,
                         settings.begin(), settings_end, ec);
  // TODO: start timer for SETTINGS_TIMEOUT
}

template <typename Stream>
void basic_connection<Stream>::send_window_update(
    protocol::stream_identifier stream_id,
    protocol::flow_control_size_type increment,
    boost::system::error_code& ec)
{
  if (increment > protocol::max_flow_control_window_size) {
    ec = make_error_code(protocol::error::flow_control_error);
    return;
  }
  auto& buffer = output_buffers();
  assert(buffer.size() == 0);
  {
    // encode increment in payload
    auto buf = buffer.prepare(4);
    auto pos = boost::asio::buffers_begin(buf);
    *pos++ = 0x7f & (increment >> 24);
    *pos++ = increment >> 16;
    *pos++ = increment >> 8;
    *pos++ = increment;
    buffer.commit(4);
  }
  constexpr auto type = protocol::frame_type::window_update;
  constexpr uint8_t flags = 0;
  detail::write_frame(next_layer(), type, flags, stream_id,
                      buffer.data(), ec);
  buffer.consume(4);
}

template <typename Stream>
void basic_connection<Stream>::handle_data(
    const protocol::frame_header& header,
    boost::system::error_code& ec)
{
  if (header.stream_id == 0) {
    ec = make_error_code(protocol::error::protocol_error);
    return;
  }
  auto stream = streams.find(header.stream_id, detail::stream_id_less{});
  if (stream == streams.end()) {
    ec = make_error_code(protocol::error::protocol_error);
    return;
  }
  switch (stream->state) {
    // allowed states
    case protocol::stream_state::open:
      if (header.flags & protocol::frame_flag_end_stream) {
        stream->state = protocol::stream_state::half_closed_remote;
      }
      break;
    case protocol::stream_state::half_closed_local:
      if (header.flags & protocol::frame_flag_end_stream) {
        stream->state = protocol::stream_state::closed;
      }
      break;
    // disallowed states
    default:
      ec = make_error_code(protocol::error::stream_closed);
      return;
  }
  // TODO: read into buffers provided by caller
  auto& buffer = input_buffers();
  auto buf = buffer.prepare(header.length);
  boost::asio::read(next_layer(), buf, ec);
  if (ec) {
    return;
  }
  // TODO: decode padding/body
  buffer.commit(0); // discard
}

template <typename Stream>
void basic_connection<Stream>::handle_headers(
    const protocol::frame_header& header,
    boost::system::error_code& ec)
{
  detail::stream_set::iterator stream;

  if (header.stream_id == 0) {
    ec = make_error_code(protocol::error::protocol_error);
    return;
  }
  if (protocol::client_initiated(header.stream_id) !=
      protocol::client_initiated(peer.next_stream_id)) {
    ec = make_error_code(protocol::error::protocol_error);
    return;
  }
  if (header.stream_id >= peer.next_stream_id) {
    peer.next_stream_id = header.stream_id + 2;
    // new stream
    auto impl = std::make_unique<detail::stream_impl>();
    impl->id = header.stream_id;
    impl->state = protocol::stream_state::open;
    impl->inbound_window = self.settings.initial_window_size;
    impl->outbound_window = peer.settings.initial_window_size;
    stream = streams.insert(streams.end(), *impl.release());
    // TODO: close any of peer's idle streams with lower id
  } else {
    // existing stream
    stream = streams.find(header.stream_id, detail::stream_id_less{});
    if (stream == streams.end()) {
      ec = make_error_code(protocol::error::protocol_error);
      return;
    }
    switch (stream->state) {
      // allowed states
      case protocol::stream_state::idle:
        stream->state = protocol::stream_state::open;
        [[fallthrough]];
      case protocol::stream_state::open:
        if (header.flags & protocol::frame_flag_end_stream) {
          stream->state = protocol::stream_state::half_closed_remote;
        }
        break;
      case protocol::stream_state::reserved_remote:
        if (header.flags & protocol::frame_flag_end_stream) {
          stream->state = protocol::stream_state::closed;
        } else {
          stream->state = protocol::stream_state::half_closed_local;
        }
        break;
      // disallowed states
      case protocol::stream_state::half_closed_remote:
        [[fallthrough]]
      case protocol::stream_state::closed:
        ec = make_error_code(protocol::error::stream_closed);
        return;
      default:
        ec = make_error_code(protocol::error::protocol_error);
        return;
    }
  }
  auto& buffers = input_buffers();
  assert(buffers.size() == 0);
  if (header.length) {
    // read the payload
    auto buf = buffers.prepare(header.length);
    const auto bytes_read = boost::asio::read(next_layer(), buf, ec);
    if (ec) {
      return;
    }
    buffers.commit(bytes_read);
  }
  auto buf = buffers.data();
  auto pos = boost::asio::buffers_begin(buf);
  auto end = boost::asio::buffers_end(buf);

  size_t padding = 0;
  if (header.flags & protocol::frame_flag_padded) {
    padding = *pos++;
  }
  if (header.flags & protocol::frame_flag_priority) {
    pos = protocol::detail::decode_priority(pos, stream->priority);
    // TODO: reprioritize
  }

  if (!self.table) {
    self.table.emplace(self.settings.header_table_size);
  }
  auto& table = *self.table;

  std::string name, value;
  while (pos != end) {
    if (!detail::hpack::decode_header(pos, end, table, name, value)) {
      ec = make_error_code(protocol::error::compression_error);
      return;
    }
    // TODO: store fields
  }
  buffers.consume(header.length);

  if (padding > static_cast<size_t>(std::distance(pos, end))) {
    ec = make_error_code(protocol::error::protocol_error);
    return;
  }
}

template <typename Stream>
void basic_connection<Stream>::handle_settings(
    const protocol::frame_header& header,
    boost::system::error_code& ec)
{
  if (header.stream_id != 0) {
    ec = make_error_code(protocol::error::protocol_error);
    return;
  }
  if (header.flags & protocol::frame_flag_ack) {
    handle_settings_ack(header, ec);
    return;
  }
  if (header.length % 6 != 0) {
    ec = make_error_code(protocol::error::frame_size_error);
    return;
  }
  auto& buffers = input_buffers();
  {
    // read the payload
    auto buf = buffers.prepare(header.length);
    const auto bytes_read = boost::asio::read(next_layer(), buf, ec);
    if (ec) {
      return;
    }
    buffers.commit(bytes_read);
  }
  protocol::setting_values& values = peer.settings;
  const protocol::setting_values oldvalues = values;
  {
    // decode changes and process each in order
    auto buf = buffers.data();
    auto pos = boost::asio::buffers_begin(buf);
    auto end = boost::asio::buffers_end(buf);
    while (pos != end) {
      protocol::setting_parameter_pair param;
      pos = protocol::detail::decode_setting(pos, param);

      switch (static_cast<protocol::setting_parameter>(param.identifier)) {
        case protocol::setting_parameter::header_table_size:
          values.header_table_size = param.value;
          if (peer.table) {
            peer.table->set_size(param.value);
          }
          break;
        case protocol::setting_parameter::enable_push:
          values.enable_push = param.value;
          break;
        case protocol::setting_parameter::max_concurrent_streams:
          values.max_concurrent_streams = param.value;
          break;
        case protocol::setting_parameter::initial_window_size:
          if (param.value > protocol::max_flow_control_window_size) {
            ec = make_error_code(protocol::error::flow_control_error);
            return;
          }
          values.initial_window_size = param.value;
          break;
        case protocol::setting_parameter::max_frame_size:
          if (param.value < protocol::min_setting_max_frame_size ||
              param.value > protocol::max_setting_max_frame_size) {
            ec = make_error_code(protocol::error::protocol_error);
            return;
          }
          values.max_frame_size = param.value;
          break;
        case protocol::setting_parameter::max_header_list_size:
          values.max_header_list_size = param.value;
          break;
        default: break; // ignore unrecognized settings
      }
    }
    buffers.consume(header.length);
  }
  // reallocate frame buffer after all settings are decoded
  if (values.max_frame_size != oldvalues.max_frame_size) {
    self.buffer.emplace(values.max_frame_size);
  }
  if (values.initial_window_size != oldvalues.initial_window_size) {
    using ssize_type = protocol::flow_control_ssize_type;
    auto before = static_cast<ssize_type>(oldvalues.initial_window_size);
    auto after = static_cast<ssize_type>(values.initial_window_size);
    auto increment = after - before; // XXX: check overflow
    adjust_outbound_window(increment, ec);
    if (ec) {
      return;
    }
  }

  // TODO: queue ack if someone else is writing
  detail::write_settings_ack(next_layer(), ec);
}

template <typename Stream>
void basic_connection<Stream>::handle_settings_ack(
    const protocol::frame_header& header,
    boost::system::error_code& ec)
{
  if (header.length != 0) {
    ec = make_error_code(protocol::error::frame_size_error);
    return;
  }
  // safe to shrink after ack
  if (self.settings.max_frame_size > settings_sent.max_frame_size) {
    self.buffer.emplace(settings_sent.max_frame_size);
  }
  self.settings = settings_sent;
}

template <typename Stream>
void basic_connection<Stream>::handle_window_update(
    const protocol::frame_header& header,
    boost::system::error_code& ec)
{
  if (header.length != 4) {
    ec = make_error_code(protocol::error::frame_size_error);
    return;
  }
  protocol::flow_control_size_type value = 0;
  {
    // read the payload
    auto& buffer = input_buffers();
    auto buf = buffer.prepare(4);
    boost::asio::read(next_layer(), buf, ec);
    if (ec) {
      return;
    }
    buffer.commit(4);
    // decode a uint31_t
    auto pos = boost::asio::buffers_begin(buffer.data());
    value = static_cast<uint8_t>(*pos++ & 0x7f) << 24;
    value |= static_cast<uint8_t>(*pos++) << 16;
    value |= static_cast<uint8_t>(*pos++) << 8;
    value |= static_cast<uint8_t>(*pos++);
    buffer.consume(4);
  }
  if (value == 0) {
    ec = make_error_code(protocol::error::protocol_error);
    return;
  }
  if (value > protocol::max_flow_control_window_size) {
    ec = make_error_code(protocol::error::flow_control_error);
    return;
  }
  auto increment = static_cast<protocol::flow_control_ssize_type>(value);
  if (header.stream_id == 0) {
    detail::checked_adjust_window(peer.window, increment, ec);
  } else {
    auto s = streams.find(header.stream_id, detail::stream_id_less{});
    if (s != streams.end()) {
      detail::checked_adjust_window(s->outbound_window, increment, ec);
    }
  }
}

template <typename Stream>
void basic_connection<Stream>::run(boost::system::error_code& ec)
{
  while (!ec) {
    protocol::frame_header header;
    detail::read_frame_header(next_layer(), header, ec);
    if (ec) {
      return;
    }
    if (header.length > self.settings.max_frame_size) {
      ec = make_error_code(protocol::error::frame_size_error);
      return;
    }
    switch (static_cast<protocol::frame_type>(header.type)) {
      case protocol::frame_type::data:
        handle_data(header, ec);
        break;
      case protocol::frame_type::headers:
        handle_headers(header, ec);
        break;
      //case protocol::frame_type::priority:
      //case protocol::frame_type::rst_stream:
      case protocol::frame_type::settings:
        handle_settings(header, ec);
        break;
      //case protocol::frame_type::push_promise:
      //case protocol::frame_type::ping:
      //case protocol::frame_type::goaway:
      case protocol::frame_type::window_update:
        handle_window_update(header, ec);
        break;
      //case protocol::frame_type::continuation:
      default:
        ec = make_error_code(protocol::error::protocol_error);
        return;
    }
  }
}

template <typename Stream>
void basic_connection<Stream>::adjust_inbound_window(
    protocol::flow_control_ssize_type increment,
    boost::system::error_code& ec)
{
  detail::checked_adjust_window(self.window, increment, ec);
  for (auto& s : streams) {
    detail::checked_adjust_window(s.inbound_window, increment, ec);
    if (ec) {
      return;
    }
  }
}

template <typename Stream>
void basic_connection<Stream>::adjust_outbound_window(
    protocol::flow_control_ssize_type increment,
    boost::system::error_code& ec)
{
  detail::checked_adjust_window(peer.window, increment, ec);
  for (auto& s : streams) {
    detail::checked_adjust_window(s.outbound_window, increment, ec);
    if (ec) {
      return;
    }
  }
  // TODO: schedule writes if increment > 0
}

} // namespace http2
