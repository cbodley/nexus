#pragma once

#include <boost/intrusive/list.hpp>
#include <nexus/quic/detail/stream_impl.hpp>
#include <nexus/quic/detail/stream_open_handler.hpp>
#include <nexus/udp.hpp>

struct lsquic_conn;
struct lsquic_stream;

namespace nexus::quic::detail {

struct accept_operation;
struct socket_impl;

struct connection_impl : public boost::intrusive::list_base_hook<> {
  using stream_list = boost::intrusive::list<stream_impl>;
  socket_impl& socket;
  // make sure that connection errors get delivered to the application. if we
  // see a fatal connection error while there are no pending operations we can
  // deliver the error to, save it here and deliver it to the next operation
  error_code err;
  lsquic_conn* handle = nullptr;
  accept_operation* accept_ = nullptr;

  // maintain ownership of incoming/connecting/accepting streams
  stream_list incoming_streams;
  stream_list connecting_streams;
  stream_list accepting_streams;

  // connected/closing streams are owned by a quic::stream or h3::stream
  stream_list connected_streams;
  stream_list closing_streams;

  explicit connection_impl(socket_impl& socket) : socket(socket) {}
  ~connection_impl() {
    error_code ec_ignored;
    close(ec_ignored);
  }

  using executor_type = asio::any_io_executor;
  executor_type get_executor() const;

  udp::endpoint remote_endpoint();

  void connect(stream_connect_operation& op);

  template <typename Stream, typename CompletionToken>
  decltype(auto) async_connect(CompletionToken&& token) {
    return asio::async_initiate<CompletionToken, void(error_code, Stream)>(
        [this] (auto handler) {
          using Handler = std::decay_t<decltype(handler)>;
          using StreamHandler = stream_open_handler<Stream, Handler>;
          auto h = StreamHandler{std::move(handler)};
          using op_type = stream_connect_async<StreamHandler, executor_type>;
          auto p = handler_allocate<op_type>(h, std::move(h), get_executor());
          auto op = handler_ptr<op_type, StreamHandler>{p, &p->handler};
          connect(*op);
          op.release(); // release ownership
        }, token);
  }

  void accept(stream_accept_operation& op);

  template <typename Stream, typename CompletionToken>
  decltype(auto) async_accept(CompletionToken&& token) {
    return asio::async_initiate<CompletionToken, void(error_code, Stream)>(
        [this] (auto handler) {
          using Handler = std::decay_t<decltype(handler)>;
          using StreamHandler = stream_open_handler<Stream, Handler>;
          auto h = StreamHandler{std::move(handler)};
          using op_type = stream_accept_async<StreamHandler, executor_type>;
          auto p = handler_allocate<op_type>(h, std::move(h), get_executor());
          auto op = handler_ptr<op_type, StreamHandler>{p, &p->handler};
          accept(*op);
          op.release(); // release ownership
        }, token);
  }

  bool is_open() const;

  void close(error_code& ec);
};

} // namespace nexus::quic::detail
