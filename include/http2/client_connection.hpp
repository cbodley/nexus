#pragma once

#include <http2/basic_connection.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/write.hpp>

namespace http2 {

template <typename Stream>
class client_connection : public basic_connection<Stream> {
 public:
  template <typename ...Args>
  client_connection(const protocol::setting_values& settings, Args&& ...args)
    : basic_connection<Stream>(client_tag, settings, std::forward<Args>(args)...)
  {}
  void upgrade(std::string_view host, std::string_view target,
               boost::system::error_code& ec);
};

// negotiate http2 client startup over an http connection
template <typename Stream>
void client_connection<Stream>::upgrade([[maybe_unused]] std::string_view host,
                                        [[maybe_unused]] std::string_view target,
                                        boost::system::error_code& ec)
{
  // send an upgrade request with http/1.1
  // read the response
  // send the client connection preface
  auto buffer = boost::asio::buffer(protocol::client_connection_preface.data(),
                                    protocol::client_connection_preface.size());
  boost::asio::write(this->stream, buffer, ec);
  // send a SETTINGS frame
}

} // namespace http2
