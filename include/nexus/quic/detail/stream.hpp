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
#if 0
struct header_transfer_state {
  static constexpr uint16_t max_headers = 64; // XXX
  std::array<lsxpack_header, max_headers> headers;
  uint16_t num_headers = 0;

  std::optional<error_code> ec;
  std::condition_variable cond;

  void write(const http3::fields& fields) {
    for (auto f = fields.begin();
         f != fields.end() && num_headers < max_headers;
         ++f, ++num_headers) {
      auto& header = headers[num_headers];
      const char* buf = f->data();
      const size_t name_offset = std::distance(buf, f->name().data());
      const size_t name_len = f->name().size();
      const size_t val_offset = std::distance(buf, f->value().data());
      const size_t val_len = f->value().size();
      lsxpack_header_set_offset2(&header, buf, name_offset, name_len,
                                 val_offset, val_len);
      header.indexed_type = static_cast<uint8_t>(f->index());
    }
  }

  void read(http3::fields& fields) {
    const auto begin = headers.cbegin();
    const auto end = begin + num_headers;
    for (auto h = begin; h != end; ++h) {
      auto name = std::string_view{h->buf + h->name_offset, h->name_len};
      auto value = std::string_view{h->buf + h->val_offset, h->val_len};
      auto index = static_cast<http3::should_index>(h->indexed_type);
      fields.insert(name, value, index);
    }
  }

  void wait(std::unique_lock<std::mutex>& lock, error_code& ec) {
    cond.wait(lock, [this] { return this->ec; });
    ec = *this->ec;
  }
  void notify(const error_code& ec) {
    this->ec = ec;
    cond.notify_one();
  }
};

struct data_transfer_state {
  static constexpr uint16_t max_iovs = 64;
  std::array<iovec, max_iovs> iovs;
  uint16_t num_iovs = 0;

  std::optional<error_code> ec;
  size_t bytes_transferred = 0;
  std::condition_variable cond;

  template <typename BufferSequence>
  void request(const BufferSequence& buffers) {
    const auto end = boost::asio::buffer_sequence_end(buffers);
    for (auto i = boost::asio::buffer_sequence_begin(buffers);
         i != end && num_iovs < max_iovs; ++i, ++num_iovs) {
      iovs[num_iovs].iov_base = i->data();
      iovs[num_iovs].iov_len = i->size();
    }
  }
  size_t wait(std::unique_lock<std::mutex>& lock, error_code& ec) {
    cond.wait(lock, [this] { return this->ec; });
    ec = *this->ec;
    return bytes_transferred;
  }
  void notify(const error_code& ec, size_t bytes) {
    this->ec = ec;
    bytes_transferred = bytes;
    cond.notify_one();
  }
};
#endif
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
