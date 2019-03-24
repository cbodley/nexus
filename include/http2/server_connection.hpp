#pragma once

#include <boost/asio/read.hpp>

#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/write.hpp>

#include <http2/basic_connection.hpp>
#include <http2/detail/base64url.hpp>

namespace http2 {

// TODO: bool valid_upgrade_request(boost::beast::http::request<...>&);

template <typename Stream>
class server_connection : public basic_connection<Stream> {
 public:
  template <typename ...Args>
  server_connection(const protocol::setting_values& settings, Args&& ...args)
    : basic_connection<Stream>(server_tag, settings, std::forward<Args>(args)...)
  {}

  // accept a new client with prior knowledge of http/2 support, skipping the
  // Upgrade request/response
  void accept(boost::system::error_code& ec);

  // upgrade in response to an http/1.1 request with the headers
  // 'Upgrade: h2c' and 'HTTP2-Settings'
  void upgrade(std::string_view base64url_encoded_http2_settings,
               boost::system::error_code& ec);
};

template <typename Stream>
void server_connection<Stream>::accept(boost::system::error_code& ec)
{
  // read client connection preface
  std::string preface(protocol::client_connection_preface.size(), '\0');
  // TODO: use read_some for preface so we can fail early on mismatch
  boost::asio::read(this->next_layer(), boost::asio::buffer(preface), ec);
  if (ec) {
    return;
  }
  if (preface != protocol::client_connection_preface) {
    ec = make_error_code(protocol::error::http_1_1_required);
    return;
  }
  // send a SETTINGS frame
  this->send_settings(ec);
}

template <typename Stream>
void server_connection<Stream>::upgrade(std::string_view client_settings,
                                        boost::system::error_code& ec)
{
  // respond to the client with 101 Switching Protocols
  namespace http = boost::beast::http;
  http::response<http::empty_body> res{http::status::switching_protocols, 11};
  res.set(http::field::upgrade, "h2c");
  res.insert(http::field::connection, "Upgrade");
  http::write(this->next_layer(), res, ec);
  if (ec) {
    return;
  }
  // decode and apply client settings
  auto base64url = boost::asio::buffer(client_settings.data(),
                                       client_settings.size());
  auto& buffer = this->input_buffers();
  detail::base64url::decode(base64url, buffer);
  this->apply_settings(buffer.data(), ec);
  buffer.consume(buffer.size());
  if (ec) {
    return;
  }
  // TODO: register stream 1 as half closed (client)
  // send a SETTINGS frame
  this->send_settings(ec);
  if (ec) {
    return;
  }
  // read client connection preface
  std::string preface(protocol::client_connection_preface.size(), '\0');
  boost::asio::read(this->next_layer(), boost::asio::buffer(preface), ec);
  if (ec) {
    return;
  }
  if (protocol::client_connection_preface != preface) {
    ec = make_error_code(protocol::error::protocol_error);
    return;
  }
  // read SETTINGS frame
  protocol::frame_header header;
  detail::read_frame_header(this->next_layer(), header, ec);
  if (ec) {
    return;
  }
  if (header.length > this->self.settings.max_frame_size) {
    ec = make_error_code(protocol::error::frame_size_error);
    return;
  }
  if (static_cast<protocol::frame_type>(header.type) != protocol::frame_type::settings) {
    ec = make_error_code(protocol::error::protocol_error);
    return;
  }
  if (header.flags & protocol::frame_flag_ack) {
    ec = make_error_code(protocol::error::protocol_error);
    return;
  }
  this->handle_settings(header, ec);
}

} // namespace http2
