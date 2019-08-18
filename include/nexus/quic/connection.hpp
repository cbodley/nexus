#pragma once

#include <boost/asio/streambuf.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <nexus/quic/detail/encoding/packet.hpp>

namespace nexus::quic {

using proto = boost::asio::ip::udp;

class connection {
  detail::connection_id_t id;
  proto::socket socket;
  proto::endpoint local_endpoint;
  proto::endpoint remote_endpoint;
  boost::asio::streambuf buffer;
 public:
  connection(boost::asio::io_context& context, proto::endpoint remote_endpoint)
    : socket(context, proto::v4()),
      remote_endpoint(remote_endpoint)
  {}

  void send_initial() {
    detail::long_header header;
    header.version = 1;
    detail::encode_header(0xc0, header, buffer);
    detail::initial_packet packet;
    detail::encode_packet(packet, buffer);
    socket.send_to(buffer.data(), remote_endpoint);
    buffer.consume(buffer.size());
  }

  void send_zero_rtt() {
    detail::long_header header;
    header.version = 1;
    detail::encode_header(0xd0, header, buffer);
    detail::zero_rtt_packet packet;
    detail::encode_packet(packet, buffer);
    socket.send_to(buffer.data(), remote_endpoint);
    buffer.consume(buffer.size());
  }
};

} // namespace nexus::quic
