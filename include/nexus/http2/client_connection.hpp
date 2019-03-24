#pragma once

#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/write.hpp>

#include <nexus/http2/basic_connection.hpp>
#include <nexus/http2/detail/base64url.hpp>

namespace nexus::http2 {

using string_view = boost::beast::string_view;

template <typename Stream>
class client_connection : public basic_connection<Stream> {
 public:
  template <typename ...Args>
  client_connection(const protocol::setting_values& settings, Args&& ...args)
    : basic_connection<Stream>(client_tag, settings, std::forward<Args>(args)...)
  {}
  void upgrade(string_view host, string_view target,
               boost::system::error_code& ec);
};

// negotiate http2 client startup over an http connection
template <typename Stream>
void client_connection<Stream>::upgrade(string_view host, string_view target,
                                        boost::system::error_code& ec)
{
  namespace http = boost::beast::http;
  {
    // encode the HTTP2-Settings header
    auto& buffer = this->output_buffers();
    this->prepare_settings(buffer, ec);
    if (ec) {
      return;
    }
    std::string settings; // TODO: encode into frame buffer
    auto base64url = boost::asio::dynamic_buffer(settings);
    detail::base64url::encode(buffer.data(), base64url);
    buffer.consume(buffer.size());

    // send an upgrade request with http/1.1
    http::request<http::empty_body> req(http::verb::get, target, 11);
    req.set(http::field::host, host);
    req.set("HTTP2-Settings", std::move(settings));
    req.insert(http::field::connection, "HTTP2-Settings");
    req.set(http::field::upgrade, "h2c");
    req.insert(http::field::connection, "Upgrade");
    http::write(this->next_layer(), req, ec);
    if (ec) {
      return;
    }
  }
  // read the response
  http::response<http::empty_body> res;
  http::read(this->next_layer(), this->input_buffers(), res, ec);
  if (ec) {
    return;
  }
  if (res.result() != http::status::switching_protocols) {
    ec = make_error_code(protocol::error::http_1_1_required);
    return;
  }
  // 101 Switching Protocols counts as settings ack
  this->on_settings_ack();
  // send the client connection preface
  auto preface = boost::asio::buffer(protocol::client_connection_preface.data(),
                                     protocol::client_connection_preface.size());
  boost::asio::write(this->next_layer(), preface, ec);
  if (ec) {
    return;
  }
  // TODO: register stream 1 as half closed
  // send a SETTINGS frame
  this->send_settings(ec);
}

} // namespace nexus::http2
