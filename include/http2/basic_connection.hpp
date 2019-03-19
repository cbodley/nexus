#pragma once

#include <optional>

#include <boost/asio/streambuf.hpp>

#include <http2/error.hpp>
#include <http2/protocol.hpp>
#include <http2/detail/frame.hpp>
#include <http2/detail/settings.hpp>

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
  next_layer_type stream;
  std::optional<boost::asio::streambuf> framebuf; // TODO: buffer type as template param

  struct endpoint {
    protocol::setting_values settings = protocol::default_settings;
    protocol::stream_identifier stream_in_headers = 0;
    protocol::stream_identifier next_stream_id;

    explicit constexpr endpoint(client_tag_t) : next_stream_id(1) {}
    explicit constexpr endpoint(server_tag_t) : next_stream_id(2) {}
  };
  endpoint self;
  endpoint peer;

  protocol::setting_values settings_sent = protocol::default_settings;
  protocol::setting_values settings_desired;

  void send_settings(boost::system::error_code& ec);

  void handle_settings(const protocol::frame_header& header,
                       boost::system::error_code& ec);
  void handle_settings_ack(const protocol::frame_header& header,
                           boost::system::error_code& ec);
 public:
  template <typename ...Args>
  basic_connection(client_tag_t, const protocol::setting_values& settings,
                   Args&& ...args)
    : stream(std::forward<Args>(args)...),
      framebuf(protocol::default_setting_max_frame_size),
      self(client_tag),
      peer(server_tag),
      settings_desired(settings)
  {}
  template <typename ...Args>
  basic_connection(server_tag_t, const protocol::setting_values& settings,
                   Args&& ...args)
    : stream(std::forward<Args>(args)...),
      framebuf(protocol::default_setting_max_frame_size),
      self(server_tag),
      peer(client_tag),
      settings_desired(settings)
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

  void run(boost::system::error_code& ec);
};

template <typename Stream>
void basic_connection<Stream>::send_settings(boost::system::error_code& ec)
{
  if (self.settings != settings_sent) {
    // our last settings haven't been acked yet
    ec = make_error_code(protocol::error::settings_timeout);
    return;
  }
  protocol::setting_parameters settings;
  auto end = protocol::detail::copy_changes(settings.begin(),
                                            settings_sent,
                                            settings_desired);
  settings_sent = settings_desired;

  detail::write_settings(next_layer(), *framebuf, settings.begin(), end, ec);
  // TODO: start timer for SETTINGS_TIMEOUT
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
  {
    // read the payload
    auto buf = this->framebuf->prepare(header.length);
    const auto bytes_read = boost::asio::read(next_layer(), buf, ec);
    if (ec) {
      return;
    }
    this->framebuf->commit(bytes_read);
  }
  protocol::setting_values& values = this->peer.settings;
  const protocol::setting_values oldvalues = values;
  {
    // decode changes and process each in order
    auto buf = this->framebuf->data();
    auto pos = boost::asio::buffers_begin(buf);
    auto end = boost::asio::buffers_end(buf);
    while (pos != end) {
      protocol::setting_parameter_pair param;
      pos = protocol::detail::decode_setting(pos, param);

      switch (static_cast<protocol::setting_parameter>(param.identifier)) {
        case protocol::setting_parameter::header_table_size:
          values.header_table_size = param.value;
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
    this->framebuf->consume(header.length);
  }
  // reallocate frame buffer after all settings are decoded
  if (values.max_frame_size != oldvalues.max_frame_size) {
    framebuf.emplace(values.max_frame_size);
  }
  if (values.initial_window_size != oldvalues.initial_window_size) {
    // TODO: adjust connection and stream windows
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
  self.settings = settings_sent;
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
      //case protocol::frame_type::data:
      //case protocol::frame_type::headers:
      //case protocol::frame_type::priority:
      //case protocol::frame_type::rst_stream:
      case protocol::frame_type::settings:
        handle_settings(header, ec);
        break;
      //case protocol::frame_type::push_promise:
      //case protocol::frame_type::ping:
      //case protocol::frame_type::goaway:
      //case protocol::frame_type::window_update:
      //case protocol::frame_type::continuation:
      default:
        ec = make_error_code(protocol::error::protocol_error);
        return;
    }
  }
}

} // namespace http2
