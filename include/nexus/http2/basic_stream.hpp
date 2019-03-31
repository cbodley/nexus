#pragma once

#include <nexus/http2/detail/stream_scheduler.hpp>

#include <boost/asio/error.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/type_traits.hpp>

namespace nexus::http2 {

class basic_stream {
  detail::stream_scheduler& scheduler;
  protocol::stream_identifier stream_id = 0; // no id until headers
 public:
  basic_stream(detail::stream_scheduler& scheduler) : scheduler(scheduler) {}

  // TODO: get/set flow control window size
  // TODO: get/set priority

  template <bool isRequest, typename Body, typename Fields>
  size_t read(boost::beast::http::message<isRequest, Body, Fields>& message,
              boost::system::error_code& ec);
  template <bool isRequest, typename Body, typename Fields>
  size_t read_some(boost::beast::http::message<isRequest, Body, Fields>& message,
                   boost::system::error_code& ec);

  template <typename Fields>
  auto read_header(Fields& fields, boost::system::error_code& ec)
    -> std::enable_if_t<detail::is_fields_v<Fields>, size_t>;
  template <typename Fields>
  auto read_some_header(Fields& fields, boost::system::error_code& ec)
    -> std::enable_if_t<detail::is_fields_v<Fields>, size_t>;

  template <typename BodyReader>
  auto read_body(BodyReader& body, boost::system::error_code& ec)
    -> std::enable_if_t<detail::is_body_reader_v<BodyReader>, size_t>;
  template <typename BodyReader>
  auto read_some_body(BodyReader& body, boost::system::error_code& ec)
    -> std::enable_if_t<detail::is_body_reader_v<BodyReader>, size_t>;

  template <bool isRequest, typename Body, typename Fields>
  size_t write(boost::beast::http::message<isRequest, Body, Fields>& message,
               boost::system::error_code& ec);
  template <bool isRequest, typename Body, typename Fields>
  size_t write_some(boost::beast::http::message<isRequest, Body, Fields>& message,
                    boost::system::error_code& ec);

  template <typename Fields>
  auto write_header(Fields& fields, boost::system::error_code& ec)
    -> std::enable_if_t<detail::is_fields_v<Fields>, size_t>;
  template <typename Fields>
  auto write_some_header(Fields& fields, boost::system::error_code& ec)
    -> std::enable_if_t<detail::is_fields_v<Fields>, size_t>;

  template <typename BodyWriter>
  auto write_body(BodyWriter& body, boost::system::error_code& ec)
    -> std::enable_if_t<detail::is_body_writer_v<BodyWriter>, size_t>;
  template <typename BodyWriter>
  auto write_some_body(BodyWriter& body, boost::system::error_code& ec)
    -> std::enable_if_t<detail::is_body_writer_v<BodyWriter>, size_t>;
};

template <bool isRequest, typename Body, typename Fields>
size_t basic_stream::read(
    boost::beast::http::message<isRequest, Body, Fields>& message,
    boost::system::error_code& ec)
{
  size_t count = scheduler.read_header(stream_id, message.base(), ec);
  if (ec) {
    return count;
  }
  auto payload_size = message.payload_size();
  if (payload_size && *payload_size == 0) {
    return count;
  }
  typename Body::reader body{message};
  body.init(boost::none, ec);
  while (!ec) {
    count += scheduler.read_some_body(stream_id, body, ec);
  }
  if (ec == boost::asio::error::eof) {
    body.finish(ec);
  }
  return count;
}

} // namespace nexus::http2
