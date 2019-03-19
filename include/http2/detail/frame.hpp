#pragma once

#include <type_traits>

#include <boost/asio/buffers_iterator.hpp>
#include <boost/asio/read.hpp>

#include <http2/protocol.hpp>

namespace http2 {
namespace protocol::detail {

template <typename OutputIterator>
OutputIterator encode_frame_header(const frame_header& header,
                                   OutputIterator pos)
{
  *pos++ = header.length >> 16;
  *pos++ = header.length >> 8;
  *pos++ = header.length;
  *pos++ = header.type;
  *pos++ = header.flags;
  // highest bit of stream_id is reserved and sender must write 0
  const auto stream_id = header.stream_id & protocol::stream_identifier_mask;
  *pos++ = stream_id >> 24;
  *pos++ = stream_id >> 16;
  *pos++ = stream_id >> 8;
  *pos++ = stream_id;
  return pos;
}

template <typename InputIterator>
InputIterator decode_frame_header(InputIterator pos, frame_header& header)
{
  header.length = static_cast<uint32_t>(*pos++) << 16;
  header.length |= static_cast<uint32_t>(*pos++) << 8;
  header.length |= static_cast<uint32_t>(*pos++);
  header.type = *pos++;
  header.flags = *pos++;
  header.stream_id = static_cast<protocol::stream_identifier>(*pos++) << 24;
  header.stream_id |= static_cast<protocol::stream_identifier>(*pos++) << 16;
  header.stream_id |= static_cast<protocol::stream_identifier>(*pos++) << 8;
  header.stream_id |= static_cast<protocol::stream_identifier>(*pos++);
  return pos;
}

} // namespace protocol::detail

namespace detail {

template <typename SyncReadStream>
void read_frame_header(SyncReadStream& stream,
                       protocol::frame_header& header,
                       boost::system::error_code& ec)
{
  uint8_t buffer[9];
  boost::asio::read(stream, boost::asio::buffer(buffer), ec);
  if (ec) {
    return;
  }
  protocol::detail::decode_frame_header(buffer, header);
}

} // namespace detail
} // namespace http2
