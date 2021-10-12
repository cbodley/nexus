#pragma once

#include <asio/any_io_executor.hpp>
#include <asio/buffers_iterator.hpp>

#include <nexus/quic/detail/operation.hpp>
#include <nexus/quic/detail/service.hpp>
#include <nexus/quic/error.hpp>
#include <nexus/h3/fields.hpp>

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

struct stream_impl : public boost::intrusive::list_base_hook<>,
                     public service_list_base_hook {
  using executor_type = asio::any_io_executor;
  service<stream_impl>& svc;
  executor_type ex;
  connection_state* conn;
  // make sure that connection errors get delivered to the application
  error_code conn_err;
  lsquic_stream* handle = nullptr;
  stream_read_state in;
  stream_write_state out;

  stream_connect_operation* connect_ = nullptr;
  stream_accept_operation* accept_ = nullptr;
  stream_close_operation* close_ = nullptr;

  template <typename BufferSequence>
  static void init_op(const BufferSequence& buffers,
                      stream_data_operation& op) {
    const auto end = asio::buffer_sequence_end(buffers);
    for (auto i = asio::buffer_sequence_begin(buffers);
         i != end && op.num_iovs < op.max_iovs;
         ++i, ++op.num_iovs) {
      op.iovs[op.num_iovs].iov_base = const_cast<void*>(i->data());
      op.iovs[op.num_iovs].iov_len = i->size();
    }
  }

  stream_impl(const executor_type& ex, connection_state* conn)
      : svc(asio::use_service<service<stream_impl>>(
              asio::query(ex, asio::execution::context))),
        ex(ex), conn(conn)
  {
    // register for service_shutdown() notifications
    svc.add(*this);
  }
  ~stream_impl()
  {
    svc.remove(*this);
  }

  void service_shutdown()
  {
    // destroy any pending operations
    const error_code ec; // fake error code
    if (auto op = std::exchange(in.data, nullptr); op) {
      op->destroy(ec, 0);
    }
    if (auto op = std::exchange(in.header, nullptr); op) {
      op->destroy(ec);
    }
    if (auto op = std::exchange(out.data, nullptr); op) {
      op->destroy(ec, 0);
    }
    if (auto op = std::exchange(out.header, nullptr); op) {
      op->destroy(ec);
    }
    if (auto op = std::exchange(connect_, nullptr); op) {
      op->destroy(ec, nullptr);
    }
    if (auto op = std::exchange(accept_, nullptr); op) {
      op->destroy(ec, nullptr);
    }
    if (auto op = std::exchange(close_, nullptr); op) {
      op->destroy(ec);
    }
  }

  executor_type get_executor() const { return ex; }

  bool is_open() const;

  void read_headers(stream_header_read_operation& op);

  template <typename CompletionToken>
  decltype(auto) async_read_headers(h3::fields& fields,
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
    return asio::async_initiate<CompletionToken, void(error_code, size_t)>(
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
    op.wait();
    ec = std::get<0>(*op.result);
    return std::get<1>(*op.result);
  }

  void write_headers(stream_header_write_operation& op);

  template <typename CompletionToken>
  decltype(auto) async_write_headers(const h3::fields& fields,
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
    return asio::async_initiate<CompletionToken, void(error_code, size_t)>(
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
    op.wait();
    ec = std::get<0>(*op.result);
    return std::get<1>(*op.result);
  }

  void flush(error_code& ec);
  void shutdown(int how, error_code& ec);

  void close(stream_close_operation& op);

  template <typename CompletionToken>
  decltype(auto) async_close(CompletionToken&& token) {
    return asio::async_initiate<CompletionToken, void(error_code)>(
        [this] (auto h) {
          using Handler = std::decay_t<decltype(h)>;
          using op_type = stream_close_async<Handler, executor_type>;
          auto p = handler_allocate<op_type>(h, std::move(h), get_executor());
          auto op = handler_ptr<op_type, Handler>{p, &p->handler};
          close(*op);
          op.release(); // release ownership
        }, token);
  }

  void reset();
};

} // namespace quic::detail
} // namespace nexus
