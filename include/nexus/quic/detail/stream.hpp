#pragma once

#include <asio/buffers_iterator.hpp>

#include <nexus/quic/detail/request.hpp>
#include <nexus/quic/error.hpp>
#include <nexus/quic/http3/fields.hpp>

struct lsquic_stream;

namespace nexus {
namespace quic::detail {

struct connection_state;

struct stream_read_state {
  stream_data_request* data = nullptr;
  std::unique_ptr<stream_data_completion> async_data;
  stream_header_read_request* header = nullptr;
  std::unique_ptr<stream_header_read_completion> async_header;
};

struct stream_write_state {
  stream_data_request* data = nullptr;
  std::unique_ptr<stream_data_completion> async_data;
  stream_header_write_request* header = nullptr;
  std::unique_ptr<stream_header_write_completion> async_header;
};

struct stream_state : public boost::intrusive::list_base_hook<> {
  connection_state& conn;
  lsquic_stream* handle = nullptr;
  stream_read_state in;
  stream_write_state out;

  stream_connect_request* connect_ = nullptr;
  std::unique_ptr<stream_connect_completion> async_connect_;

  stream_accept_request* accept_ = nullptr;
  std::unique_ptr<stream_accept_completion> async_accept_;

  template <typename BufferSequence>
  void init_request(const BufferSequence& buffers,
                    stream_data_request& req) {
    const auto end = asio::buffer_sequence_end(buffers);
    for (auto i = asio::buffer_sequence_begin(buffers);
         i != end && req.num_iovs < req.max_iovs;
         ++i, ++req.num_iovs) {
      req.iovs[req.num_iovs].iov_base = i->data();
      req.iovs[req.num_iovs].iov_len = i->size();
    }
  }

  explicit stream_state(connection_state& conn) : conn(conn) {}
  ~stream_state() {
    error_code ec_ignored;
    close(ec_ignored);
  }

  using executor_type = asio::any_io_executor;
  executor_type get_executor();

  void connect(error_code& ec);
  void async_connect(std::unique_ptr<stream_connect_completion>&& c);

  void accept(error_code& ec);
  void async_accept(std::unique_ptr<stream_accept_completion>&& c);

  void read_headers(http3::fields& fields, error_code& ec);

  void async_read(std::unique_ptr<stream_data_completion>&& c);
  size_t read(stream_data_request& req, error_code& ec);

  template <typename MutableBufferSequence, typename Handler>
  void async_read(const MutableBufferSequence& buffers, Handler&& h) {
    auto c = stream_data_completion::create(get_executor(), std::move(h));
    init_request(buffers, c->user);
    async_read(std::move(c));
  }

  template <typename MutableBufferSequence>
  std::enable_if_t<asio::is_mutable_buffer_sequence<
      MutableBufferSequence>::value, size_t>
  read(const MutableBufferSequence& buffers, error_code& ec) {
    stream_data_request req;
    init_request(buffers, req);
    return read(req, ec);
  }

  void write_headers(const http3::fields& fields, error_code& ec);

  void async_write(std::unique_ptr<stream_data_completion>&& c);
  size_t write(stream_data_request& req, error_code& ec);

  template <typename ConstBufferSequence, typename Handler>
  void async_write(const ConstBufferSequence& buffers, Handler&& h) {
    auto c = stream_data_completion::create(get_executor(), std::move(h));
    init_request(buffers, c->user);
    async_write(std::move(c));
  }

  template <typename ConstBufferSequence>
  std::enable_if_t<asio::is_const_buffer_sequence<
      ConstBufferSequence>::value, size_t>
  write(const ConstBufferSequence& buffers, error_code& ec) {
    stream_data_request req;
    init_request(buffers, req);
    return write(req, ec);
  }

  void flush(error_code& ec);
  void shutdown(int how, error_code& ec);
  void close(error_code& ec);
};

} // namespace quic::detail
} // namespace nexus
