#pragma once

#include <type_traits>

#include <boost/asio/buffers_iterator.hpp>

#include <http2/protocol.hpp>

namespace http2::detail {

template <typename DynamicBuffer>
size_t encode_frame_header(const protocol::frame_header& header,
                           DynamicBuffer& buffers)
{
  auto buf = buffers.prepare(9);
  auto pos = boost::asio::buffers_begin(buf);
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
  buffers.commit(9);
  return 9;
}

template <typename InputIterator>
InputIterator decode_frame_header(InputIterator pos,
                                  protocol::frame_header& header)
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

} // namespace http2::detail
