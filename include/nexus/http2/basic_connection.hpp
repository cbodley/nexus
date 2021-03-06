#pragma once

#include <limits>
#include <optional>

#include <boost/beast/core/flat_buffer.hpp>

#include <nexus/http2/error.hpp>
#include <nexus/http2/protocol.hpp>
#include <nexus/http2/detail/frame.hpp>
#include <nexus/http2/detail/priority.hpp>
#include <nexus/http2/detail/settings.hpp>
#include <nexus/http2/detail/stream_scheduler.hpp>

#include <nexus/http2/detail/hpack/header.hpp>

namespace nexus::http2 {

struct client_tag_t {};
inline constexpr client_tag_t client_tag{};
struct server_tag_t {};
inline constexpr server_tag_t server_tag{};

template <typename Stream>
class basic_connection : public detail::stream_scheduler {
 public:
  using next_layer_type = Stream;
  using lowest_layer_type = typename next_layer_type::lowest_layer_type;
  using executor_type = typename next_layer_type::executor_type;
 protected:
  next_layer_type stream;

  using buffer_type = boost::beast::flat_buffer; // TODO: Allocator

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

  detail::stream_buffer_pool buffer_pool;

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

  buffer_type& read_payload(size_t size, boost::system::error_code& ec);

  template <typename ConstBufferSequence>
  auto send_data(const ConstBufferSequence& buffers,
                 protocol::stream_identifier stream_id,
                 boost::system::error_code& ec)
    -> std::enable_if_t<detail::is_const_buffer_sequence_v<ConstBufferSequence>>;

  template <typename Fields>
  void send_headers(const Fields& fields,
                    protocol::stream_identifier stream_id,
                    boost::system::error_code& ec);

  void send_priority(const protocol::stream_priority priority,
                     protocol::stream_identifier stream_id,
                     boost::system::error_code& ec);

  template <typename DynamicBuffer>
  auto prepare_settings(DynamicBuffer& buffers,
                        boost::system::error_code& ec)
    -> std::enable_if_t<detail::is_dynamic_buffer_v<DynamicBuffer>>;

  void send_settings(boost::system::error_code& ec);

  template <typename ConstBufferSequence>
  auto send_ping(const ConstBufferSequence& buffers,
                 boost::system::error_code& ec)
    -> std::enable_if_t<detail::is_const_buffer_sequence_v<ConstBufferSequence>>;

  void send_window_update(protocol::stream_identifier stream_id,
                          protocol::flow_control_size_type increment,
                          boost::system::error_code& ec);

  void handle_data(const protocol::frame_header& header,
                   boost::system::error_code& ec);

  void process_headers_payload(const protocol::frame_header& header,
                               buffer_type& buffer,
                               detail::stream_impl& stream,
                               boost::system::error_code& ec);

  void handle_headers(const protocol::frame_header& header,
                      boost::system::error_code& ec);

  void handle_priority(const protocol::frame_header& header,
                       boost::system::error_code& ec);

  void on_settings_ack();

  template <typename ConstBufferSequence>
  auto apply_settings(const ConstBufferSequence& buffers,
                      boost::system::error_code& ec)
    -> std::enable_if_t<detail::is_const_buffer_sequence_v<ConstBufferSequence>>;

  void handle_settings(const protocol::frame_header& header,
                     boost::system::error_code& ec);

  void handle_ping(const protocol::frame_header& header,
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
      settings_desired(settings),
      buffer_pool(self.settings.max_frame_size,
                  self.settings.initial_window_size / self.settings.max_frame_size)
  {}
  template <typename ...Args>
  basic_connection(server_tag_t, const protocol::setting_values& settings,
                   Args&& ...args)
    : stream(std::forward<Args>(args)...),
      self(server_tag),
      peer(client_tag),
      settings_desired(settings),
      buffer_pool(self.settings.max_frame_size,
                  self.settings.initial_window_size / self.settings.max_frame_size)
  {}

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

  // TODO: ping()

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
void account_data(protocol::flow_control_ssize_type& connection_window,
                  protocol::flow_control_ssize_type& stream_window,
                  protocol::flow_control_ssize_type size,
                  boost::system::error_code& ec)
{
  checked_adjust_window(connection_window, -size, ec);
  if (connection_window < 0) {
    ec = make_error_code(protocol::error::flow_control_error);
    return;
  }
  checked_adjust_window(stream_window, -size, ec);
  if (stream_window < 0) {
    ec = make_error_code(protocol::error::flow_control_error);
    return;
  }
}
} // namespace detail

template <typename Stream>
template <typename ConstBufferSequence>
auto basic_connection<Stream>::send_data(
    const ConstBufferSequence& buffers,
    protocol::stream_identifier stream_id,
    boost::system::error_code& ec)
  -> std::enable_if_t<detail::is_const_buffer_sequence_v<ConstBufferSequence>>
{
  if (stream_id == 0) {
    ec = make_error_code(protocol::error::protocol_error);
    return;
  }
  {
    std::scoped_lock lock{this->mutex};

    auto stream = this->streams.find(stream_id, detail::stream_id_less{});
    if (stream == this->streams.end()) {
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
    detail::account_data(peer.window, stream->outbound_window,
                         boost::asio::buffer_size(buffers), ec);
    if (ec) {
      return;
    }
  }
  constexpr auto type = protocol::frame_type::data;
  constexpr uint8_t flags = 0;
  detail::write_frame(this->next_layer(), type, flags, stream_id,
                      buffers, ec);
}

template <typename Stream>
template <typename Fields>
void basic_connection<Stream>::send_headers(
    const Fields& fields,
    protocol::stream_identifier stream_id,
    boost::system::error_code& ec)
{
  std::unique_lock lock{this->mutex};

  detail::stream_set::iterator stream;
  if (stream_id) {
    stream = this->streams.find(stream_id, detail::stream_id_less{});
    if (stream == this->streams.end()) {
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
    stream = this->streams.insert(this->streams.end(), *impl.release());
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
  lock.unlock();

  constexpr auto type = protocol::frame_type::headers;
  constexpr uint8_t flags = 0;
  detail::write_frame(this->next_layer(), type, flags, stream_id,
                      buffer.data(), ec);
  buffer.consume(buffer.size());
}

template <typename Stream>
void basic_connection<Stream>::send_priority(
    const protocol::stream_priority priority,
    protocol::stream_identifier stream_id,
    boost::system::error_code& ec)
{
  if (stream_id == 0) {
    ec = make_error_code(protocol::error::protocol_error);
    return;
  }
  auto& buffer = output_buffers();
  assert(buffer.size() == 0);
  {
    auto buf = buffer.prepare(5);
    auto pos = boost::asio::buffers_begin(buf);
    pos = protocol::detail::encode_priority(priority, pos);
    buffer.commit(5);
  }
  constexpr auto type = protocol::frame_type::priority;
  constexpr uint8_t flags = 0;
  detail::write_frame(this->next_layer(), type, flags, stream_id,
                      buffer.data(), ec);
  buffer.consume(5);
}

template <typename Stream>
template <typename DynamicBuffer>
auto basic_connection<Stream>::prepare_settings(
    DynamicBuffer& buffers,
    boost::system::error_code& ec)
  -> std::enable_if_t<detail::is_dynamic_buffer_v<DynamicBuffer>>
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

  detail::encode_settings(buffers, settings.begin(), settings_end);
}

template <typename Stream>
void basic_connection<Stream>::send_settings(boost::system::error_code& ec)
{
  auto& buffer = output_buffers();
  prepare_settings(buffer, ec);

  // write the settings frame
  constexpr auto type = protocol::frame_type::settings;
  constexpr uint8_t flags = 0;
  constexpr protocol::stream_identifier stream_id = 0;
  detail::write_frame(this->next_layer(), type, flags, stream_id,
                      buffer.data(), ec);
  buffer.consume(buffer.size());
  // TODO: start timer for SETTINGS_TIMEOUT
}

template <typename Stream>
template <typename ConstBufferSequence>
auto basic_connection<Stream>::send_ping(const ConstBufferSequence& buffers,
                                         boost::system::error_code& ec)
  -> std::enable_if_t<detail::is_const_buffer_sequence_v<ConstBufferSequence>>
{
  if (boost::asio::buffer_size(buffers) != 8) {
    ec = make_error_code(protocol::error::frame_size_error);
    return;
  }
  constexpr auto type = protocol::frame_type::ping;
  constexpr uint8_t flags = 0;
  constexpr protocol::stream_identifier stream_id = 0;
  detail::write_frame(this->next_layer(), type, flags, stream_id,
                      buffers, ec);
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
  detail::write_frame(this->next_layer(), type, flags, stream_id,
                      buffer.data(), ec);
  buffer.consume(4);
}

template <typename Stream>
typename basic_connection<Stream>::buffer_type&
basic_connection<Stream>::read_payload(size_t size,
                                       boost::system::error_code& ec)
{
  auto& buffer = input_buffers();
  assert(buffer.size() == 0);
  auto bytes_read = boost::asio::read(this->next_layer(), buffer.prepare(size), ec);
  buffer.commit(bytes_read);
  if (!ec) {
    assert(bytes_read == size);
  }
  return buffer;
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
  auto stream = this->streams.find(header.stream_id, detail::stream_id_less{});
  if (stream == this->streams.end()) {
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
  detail::account_data(self.window, stream->inbound_window,
                       header.length, ec);
  if (ec) {
    return;
  }
  auto buffer = buffer_pool.get();
  assert(buffer->max_size() >= header.length);
  assert(buffer->size() == 0);
  auto buf = buffer->prepare(header.length);
  auto bytes_read = boost::asio::read(this->next_layer(), buf, ec);
  buffer->commit(bytes_read);
  if (ec) {
    buffer->consume(bytes_read);
    buffer_pool.put(std::move(buffer));
  } else {
    stream->buffers.push_back(*buffer.release());
  }
  if (stream->reader) {
    stream->reader->complete(ec);
  }
}

template <typename Stream>
void basic_connection<Stream>::process_headers_payload(
    const protocol::frame_header& header,
    buffer_type& buffer,
    detail::stream_impl& stream,
    boost::system::error_code& ec)
{
  auto buf = buffer.data();
  auto pos = boost::asio::buffers_begin(buf);
  auto end = boost::asio::buffers_end(buf);

  size_t padding = 0;
  if (header.flags & protocol::frame_flag_padded) {
    padding = *pos++;
  }
  if (header.flags & protocol::frame_flag_priority) {
    pos = protocol::detail::decode_priority(pos, stream.priority);
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
    auto f = detail::make_field(boost::asio::buffer(name),
                                boost::asio::buffer(value));
    stream.headers.push_back(*f.release());
  }
  buffer.consume(header.length);

  if (padding > static_cast<size_t>(std::distance(pos, end))) {
    ec = make_error_code(protocol::error::protocol_error);
    return;
  }
}

template <typename Stream>
void basic_connection<Stream>::handle_headers(
    const protocol::frame_header& header,
    boost::system::error_code& ec)
{
  if (header.stream_id == 0) {
    ec = make_error_code(protocol::error::protocol_error);
    return;
  }
  std::unique_lock lock{this->mutex};

  if (protocol::client_initiated(header.stream_id) !=
      protocol::client_initiated(peer.next_stream_id)) {
    ec = make_error_code(protocol::error::protocol_error);
    return;
  }

  detail::stream_set::iterator stream;
  if (header.stream_id >= peer.next_stream_id) {
    peer.next_stream_id = header.stream_id + 2;
    // new stream
    auto impl = std::make_unique<detail::stream_impl>();
    impl->id = header.stream_id;
    impl->state = protocol::stream_state::open;
    impl->inbound_window = self.settings.initial_window_size;
    impl->outbound_window = peer.settings.initial_window_size;
    stream = this->streams.insert(this->streams.end(), *impl.release());
    // TODO: close any of peer's idle streams with lower id
  } else {
    // existing stream
    stream = this->streams.find(header.stream_id, detail::stream_id_less{});
    if (stream == this->streams.end()) {
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
  if (header.length) {
    lock.unlock();
    auto& buffer = read_payload(header.length, ec);
    lock.lock();
    if (!ec) {
      process_headers_payload(header, buffer, *stream, ec);
    }
  }
  if (header.flags & protocol::frame_flag_end_headers) {
    stream->read_headers = true;
    if (stream->reader) {
      stream->reader->complete(ec);
      stream->reader = nullptr;
    } else {
      this->accept_streams.push_back(*stream);
      if (!this->accept_waiters.empty()) {
        this->accept_waiters.front().complete(ec);
        this->accept_waiters.pop_front();
      }
    }
  }
}

template <typename Stream>
void basic_connection<Stream>::handle_priority(
    const protocol::frame_header& header,
    boost::system::error_code& ec)
{
  if (header.stream_id == 0) {
    ec = make_error_code(protocol::error::protocol_error);
    return;
  }
  if (header.length != 5) {
    ec = make_error_code(protocol::error::frame_size_error);
    return;
  }
  auto stream = this->streams.find(header.stream_id, detail::stream_id_less{});
  if (stream == this->streams.end()) {
    // new idle stream
    auto impl = std::make_unique<detail::stream_impl>();
    impl->id = header.stream_id;
    impl->state = protocol::stream_state::idle;
    impl->inbound_window = self.settings.initial_window_size;
    impl->outbound_window = peer.settings.initial_window_size;
    stream = this->streams.insert(this->streams.end(), *impl.release());
  }
  auto& buffer = read_payload(header.length, ec);
  if (ec) {
    return;
  }
  auto pos = boost::asio::buffers_begin(buffer.data());
  pos = protocol::detail::decode_priority(pos, stream->priority);
  buffer.consume(5);
  if (stream->id == stream->priority.dependency) {
    ec = make_error_code(protocol::error::protocol_error); // XXX: stream error
    return;
  }
  // TODO: reprioritize
}

template <typename Stream>
void basic_connection<Stream>::on_settings_ack()
{
  // safe to shrink after ack
  if (self.settings.max_frame_size > settings_sent.max_frame_size) {
    self.buffer.emplace(settings_sent.max_frame_size);
    buffer_pool.set_buffer_size(settings_sent.max_frame_size);
  }
  self.settings = settings_sent;
}

template <typename Stream>
template <typename ConstBufferSequence>
auto basic_connection<Stream>::apply_settings(
    const ConstBufferSequence& buffers,
    boost::system::error_code& ec)
  -> std::enable_if_t<detail::is_const_buffer_sequence_v<ConstBufferSequence>>
{
  protocol::setting_values& values = peer.settings;
  const protocol::setting_values oldvalues = values;
  {
    // decode changes and process each in order
    auto pos = boost::asio::buffers_begin(buffers);
    auto end = boost::asio::buffers_end(buffers);
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
    if (header.length != 0) {
      ec = make_error_code(protocol::error::frame_size_error);
      return;
    }
    on_settings_ack();
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
    const auto bytes_read = boost::asio::read(this->next_layer(), buf, ec);
    if (ec) {
      return;
    }
    buffers.commit(bytes_read);
  }
  apply_settings(buffers.data(), ec);
  buffers.consume(buffers.size());
  if (ec) {
    return;
  }
  // TODO: queue ack if someone else is writing
  constexpr auto type = protocol::frame_type::settings;
  constexpr auto flags = protocol::frame_flag_ack;
  constexpr protocol::stream_identifier stream_id = 0;
  auto payload = boost::asio::const_buffer(); // empty
  detail::write_frame(this->next_layer(), type, flags, stream_id, payload, ec);
}

template <typename Stream>
void basic_connection<Stream>::handle_ping(
    const protocol::frame_header& header,
    boost::system::error_code& ec)
{
  if (header.length != 8) {
    ec = make_error_code(protocol::error::frame_size_error);
    return;
  }
  if (header.stream_id != 0) {
    ec = make_error_code(protocol::error::protocol_error);
    return;
  }
  auto& buffer = read_payload(header.length, ec);
  if (ec) {
    return;
  }
  if (header.flags & protocol::frame_flag_ack) {
    return; // TODO: notify ping caller
  }
  // send an ack
  constexpr auto type = protocol::frame_type::ping;
  constexpr uint8_t flags = protocol::frame_flag_ack;
  constexpr protocol::stream_identifier stream_id = 0;
  detail::write_frame(this->next_layer(), type, flags, stream_id,
                      buffer.data(), ec);
  buffer.consume(8);
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
    boost::asio::read(this->next_layer(), buf, ec);
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
    auto s = this->streams.find(header.stream_id, detail::stream_id_less{});
    if (s != this->streams.end()) {
      detail::checked_adjust_window(s->outbound_window, increment, ec);
    }
  }
}

template <typename Stream>
void basic_connection<Stream>::run(boost::system::error_code& ec)
{
  while (!ec) {
    protocol::frame_header header;
    detail::read_frame_header(this->next_layer(), header, ec);
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
      case protocol::frame_type::priority:
        handle_priority(header, ec);
        break;
      //case protocol::frame_type::rst_stream:
      case protocol::frame_type::settings:
        handle_settings(header, ec);
        break;
      //case protocol::frame_type::push_promise:
      case protocol::frame_type::ping:
        handle_ping(header, ec);
        break;
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
  for (auto& s : this->streams) {
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
  for (auto& s : this->streams) {
    detail::checked_adjust_window(s.outbound_window, increment, ec);
    if (ec) {
      return;
    }
  }
  // TODO: schedule writes if increment > 0
}

} // namespace nexus::http2
