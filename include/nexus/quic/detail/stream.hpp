#pragma once

#include <array>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <optional>

#include <boost/asio/buffers_iterator.hpp>
#include <boost/smart_ptr/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>

#include <nexus/quic/detail/engine.hpp>
#include <nexus/quic/detail/request.hpp>
#include <nexus/quic/error.hpp>
#include <nexus/quic/http3/fields.hpp>

struct lsquic_stream;

namespace nexus {
namespace quic::detail {

struct stream_read_state {
  stream_data_request* data = nullptr;
  stream_header_read_request* header = nullptr;
};
struct stream_write_state {
  stream_data_request* data = nullptr;
  stream_header_write_request* header = nullptr;
};

struct stream_state : public boost::intrusive::list_base_hook<> {
  connection_state& conn;
  lsquic_stream* handle = nullptr;
  stream_read_state in;
  stream_write_state out;

  stream_open_request* open = nullptr;
  stream_close_request* close_ = nullptr;

  explicit stream_state(connection_state& conn) : conn(conn) {}

  void read_headers(http3::fields& fields, error_code& ec);

  size_t read(stream_data_request& req, error_code& ec);

  template <typename MutableBufferSequence>
  std::enable_if_t<boost::asio::is_mutable_buffer_sequence<
      MutableBufferSequence>::value, size_t>
  read(const MutableBufferSequence& buffers, error_code& ec)
  {
    // count the buffer segments
    const auto begin = boost::asio::buffer_sequence_begin(buffers);
    const auto end = boost::asio::buffer_sequence_end(buffers);
    const auto count = std::distance(begin, end);
    // stack-allocate enough iovs for the request
    auto p = ::alloca(count * sizeof(iovec));

    stream_data_request req;
    req.iovs = reinterpret_cast<iovec*>(p);
    for (auto i = begin; i != end; ++i, ++req.num_iovs) {
      req.iovs[req.num_iovs].iov_base = i->data();
      req.iovs[req.num_iovs].iov_len = i->size();
    }
    return read(req, ec);
  }

  void write_headers(const http3::fields& fields, error_code& ec);

  size_t write(stream_data_request& req, error_code& ec);

  template <typename ConstBufferSequence>
  std::enable_if_t<boost::asio::is_const_buffer_sequence<
      ConstBufferSequence>::value, size_t>
  write(const ConstBufferSequence& buffers, error_code& ec)
  {
    // count the buffer segments
    const auto begin = boost::asio::buffer_sequence_begin(buffers);
    const auto end = boost::asio::buffer_sequence_end(buffers);
    const auto count = std::distance(begin, end);
    // stack-allocate enough iovs for the request
    auto p = ::alloca(count * sizeof(iovec));

    stream_data_request req;
    req.iovs = reinterpret_cast<iovec*>(p);
    for (auto i = begin; i != end; ++i, ++req.num_iovs) {
      req.iovs[req.num_iovs].iov_base = i->data();
      req.iovs[req.num_iovs].iov_len = i->size();
    }
    return write(req, ec);
  }

  void flush(error_code& ec);
  void shutdown(int how, error_code& ec);
  void close(error_code& ec);
};

} // namespace quic::detail
} // namespace nexus
