#pragma once

#include <boost/asio/buffer.hpp>

#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/write.hpp>

#include <http2/basic_connection.hpp>

namespace http2 {

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
  // send an upgrade request with http/1.1
  http::request<http::empty_body> req(http::verb::get, target, 11);
  req.set(http::field::host, host);
  http::write(this->next_layer(), req, ec);
  if (ec) {
    return;
  }
  // read the response
  http::response<http::empty_body> res;
  http::read(this->next_layer(), this->input_buffers(), res, ec);
  if (ec) {
    return;
  }
  // send the client connection preface
  auto preface = boost::asio::buffer(protocol::client_connection_preface.data(),
                                     protocol::client_connection_preface.size());
  boost::asio::write(this->next_layer(), preface, ec);
  if (ec) {
    return;
  }
  // send a SETTINGS frame
  this->send_settings(ec);
}

} // namespace http2
