#pragma once

#include <asio/any_io_executor.hpp>
#include <asio/buffers_iterator.hpp>

#include <nexus/quic/detail/operation.hpp>
#include <nexus/quic/error.hpp>
#include <nexus/quic/http3/fields.hpp>

struct lsquic_stream;

namespace nexus {
namespace quic::detail {

struct connection_state;

struct stream_read_state {
  stream_data_operation* data = nullptr;
  stream_header_read_operation* header = nullptr;
};

struct stream_write_state {
  stream_data_operation* data = nullptr;
  stream_header_write_operation* header = nullptr;
};

struct stream_state : public boost::intrusive::list_base_hook<> {
  connection_state& conn;
  lsquic_stream* handle = nullptr;
  stream_read_state in;
  stream_write_state out;

  stream_connect_operation* connect_ = nullptr;
  stream_accept_operation* accept_ = nullptr;

  template <typename BufferSequence>
  void init_op(const BufferSequence& buffers, stream_data_operation& op) {
    const auto end = asio::buffer_sequence_end(buffers);
    for (auto i = asio::buffer_sequence_begin(buffers);
         i != end && op.num_iovs < op.max_iovs;
         ++i, ++op.num_iovs) {
      op.iovs[op.num_iovs].iov_base = const_cast<void*>(i->data());
      op.iovs[op.num_iovs].iov_len = i->size();
    }
  }

  explicit stream_state(connection_state& conn) : conn(conn) {}
  ~stream_state() {
    error_code ec_ignored;
    close(ec_ignored);
  }

  using executor_type = asio::any_io_executor;
  executor_type get_executor();

  void read_headers(stream_header_read_operation& op);

  template <typename CompletionToken>
  decltype(auto) async_read_headers(http3::fields& fields,
                                    CompletionToken&& token) {
    return asio::async_initiate<CompletionToken, void(error_code)>(
        [this, &fields] (auto h) {
          using Handler = std::decay_t<decltype(h)>;
          using op_type = stream_header_read_async<Handler, executor_type>;
          auto p = handler_allocate<op_type>(h, std::move(h),
                                             get_executor(), fields);
          auto op = handler_ptr<op_type, Handler>{p, &p->handler};
          read_headers(*op);
          op.release(); // release ownership
        }, token);
  }

  void read_some(stream_data_operation& op);

  template <typename MutableBufferSequence, typename CompletionToken>
  decltype(auto) async_read_some(const MutableBufferSequence& buffers,
                                 CompletionToken&& token) {
    return asio::async_initiate<CompletionToken, void(error_code)>(
        [this, &buffers] (auto h) {
          using Handler = std::decay_t<decltype(h)>;
          using op_type = stream_data_async<Handler, executor_type>;
          auto p = handler_allocate<op_type>(h, std::move(h), get_executor());
          auto op = handler_ptr<op_type, Handler>{p, &p->handler};
          init_op(buffers, *op);
          read_some(*op);
          op.release(); // release ownership
        }, token);
  }

  template <typename MutableBufferSequence>
  std::enable_if_t<asio::is_mutable_buffer_sequence<
      MutableBufferSequence>::value, size_t>
  read_some(const MutableBufferSequence& buffers, error_code& ec) {
    stream_data_sync op;
    init_op(buffers, op);
    read_some(op);
    ec = *op.ec;
    return op.bytes_transferred;
  }

  void write_headers(stream_header_write_operation& op);

  template <typename CompletionToken>
  decltype(auto) async_write_headers(const http3::fields& fields,
                                     CompletionToken&& token) {
    return asio::async_initiate<CompletionToken, void(error_code)>(
        [this, &fields] (auto h) {
          using Handler = std::decay_t<decltype(h)>;
          using op_type = stream_header_write_async<Handler, executor_type>;
          auto p = handler_allocate<op_type>(h, std::move(h),
                                             get_executor(), fields);
          auto op = handler_ptr<op_type, Handler>{p, &p->handler};
          write_headers(*op);
          op.release(); // release ownership
        }, token);
  }

  void write_some(stream_data_operation& op);

  template <typename ConstBufferSequence, typename CompletionToken>
  decltype(auto) async_write_some(const ConstBufferSequence& buffers,
                                 CompletionToken&& token) {
    return asio::async_initiate<CompletionToken, void(error_code)>(
        [this, &buffers] (auto h) {
          using Handler = std::decay_t<decltype(h)>;
          using op_type = stream_data_async<Handler, executor_type>;
          auto p = handler_allocate<op_type>(h, std::move(h), get_executor());
          auto op = handler_ptr<op_type, Handler>{p, &p->handler};
          init_op(buffers, *op);
          write_some(*op);
          op.release(); // release ownership
        }, token);
  }

  template <typename ConstBufferSequence>
  std::enable_if_t<asio::is_const_buffer_sequence<
      ConstBufferSequence>::value, size_t>
  write_some(const ConstBufferSequence& buffers, error_code& ec) {
    stream_data_sync op;
    init_op(buffers, op);
    write_some(op);
    ec = *op.ec;
    return op.bytes_transferred;
  }

  void flush(error_code& ec);
  void shutdown(int how, error_code& ec);
  void close(error_code& ec);
};

} // namespace quic::detail
} // namespace nexus
