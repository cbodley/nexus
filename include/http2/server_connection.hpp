#pragma once

#include <http2/basic_connection.hpp>

#include <boost/asio/read.hpp>

#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/write.hpp>

namespace http2 {

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
    ec = make_error_code(protocol::error::http_1_1_required); // XXX
    return;
  }
  // send a SETTINGS frame
  this->send_settings(ec);
}

template <typename Stream>
void server_connection<Stream>::upgrade([[maybe_unused]] std::string_view client_settings,
                                        boost::system::error_code& ec)
{
  // respond to the client with 101 Switching Protocols
  namespace http = boost::beast::http;
  http::response<http::empty_body> res{http::status::switching_protocols, 11};
  http::write(this->next_layer(), res, ec);
  if (ec) {
    return;
  }
  // TODO: decode client_settings
  // send a SETTINGS frame
  // read client connection preface
  std::string preface(protocol::client_connection_preface.size(), '\0');
  boost::system::error_code preface_ec;
  boost::asio::read(this->stream, boost::asio::buffer(preface), preface_ec);
  if (protocol::client_connection_preface != preface) {
    using protocol::make_error_code;
    ec = make_error_code(protocol::error::protocol_error);
    return;
  }
  // read SETTINGS frame
}

} // namespace http2
