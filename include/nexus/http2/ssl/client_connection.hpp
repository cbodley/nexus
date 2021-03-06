#pragma once

#include <boost/asio/buffer.hpp>
#include <boost/asio/write.hpp>

#include <nexus/http2/basic_connection.hpp>
#include <nexus/http2/ssl/alpn.hpp>

namespace nexus::http2::ssl {

template <typename Stream>
class client_connection : public basic_connection<Stream> {
 public:
  template <typename ...Args>
  client_connection(const protocol::setting_values& settings, Args&& ...args)
    : basic_connection<Stream>(client_tag, settings, std::forward<Args>(args)...)
  {}
  void handshake(boost::system::error_code& ec);
};

template <typename Stream>
void client_connection<Stream>::handshake(boost::system::error_code& ec)
{
  // request h2 protocol with alpn
  auto protocols = http2::ssl::alpn::make_protocol_list("h2");
  http2::ssl::set_alpn_protos(this->next_layer(), protocols, ec);
  if (ec) {
    return;
  }
  // perform the ssl handshake
  this->stream.handshake(boost::asio::ssl::stream_base::client, ec);
  if (ec) {
    return;
  }
  // require h2 protocol
  if (http2::ssl::get_alpn_selected(this->next_layer()) != "h2") {
    using protocol::make_error_code;
    ec = make_error_code(protocol::error::http_1_1_required);
    return;
  }
  // send the client connection preface
  auto buffer = boost::asio::buffer(protocol::client_connection_preface.data(),
                                    protocol::client_connection_preface.size());
  boost::asio::write(this->next_layer(), buffer, ec);
  if (ec) {
    return;
  }
  // send a SETTINGS frame
  this->send_settings(ec);
}

} // namespace nexus::http2::ssl
