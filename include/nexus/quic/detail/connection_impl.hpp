#pragma once

#include <boost/intrusive/list.hpp>
#include <nexus/quic/detail/connection_state.hpp>
#include <nexus/quic/detail/service.hpp>
#include <nexus/quic/detail/stream_impl.hpp>
#include <nexus/quic/detail/stream_open_handler.hpp>
#include <nexus/udp.hpp>

struct lsquic_conn;
struct lsquic_stream;

namespace nexus::quic::detail {

struct accept_operation;
struct socket_impl;

struct connection_impl : public boost::intrusive::list_base_hook<>,
                         public service_list_base_hook {
  service<connection_impl>& svc;
  socket_impl& socket;
  connection_state::variant state;

  explicit connection_impl(socket_impl& socket);
  ~connection_impl();

  void service_shutdown();

  using executor_type = asio::any_io_executor;
  executor_type get_executor() const;

  connection_id id(error_code& ec) const;
  udp::endpoint remote_endpoint(error_code& ec) const;

  void connect(stream_connect_operation& op);
  stream_impl* on_connect(lsquic_stream* stream);

  template <typename Stream, typename CompletionToken>
  decltype(auto) async_connect(Stream& stream, CompletionToken&& token) {
    auto& s = stream.impl;
    return asio::async_initiate<CompletionToken, void(error_code)>(
        [this, &s] (auto h) {
          using Handler = std::decay_t<decltype(h)>;
          using op_type = stream_connect_async<Handler, executor_type>;
          auto p = handler_allocate<op_type>(h, std::move(h), get_executor(), s);
          auto op = handler_ptr<op_type, Handler>{p, &p->handler};
          connect(*op);
          op.release(); // release ownership
        }, token);
  }

  void accept(stream_accept_operation& op);
  stream_impl* on_accept(lsquic_stream* stream);

  template <typename Stream, typename CompletionToken>
  decltype(auto) async_accept(Stream& stream, CompletionToken&& token) {
    auto& s = stream.impl;
    return asio::async_initiate<CompletionToken, void(error_code)>(
        [this, &s] (auto h) {
          using Handler = std::decay_t<decltype(h)>;
          using op_type = stream_accept_async<Handler, executor_type>;
          auto p = handler_allocate<op_type>(h, std::move(h), get_executor(), s);
          auto op = handler_ptr<op_type, Handler>{p, &p->handler};
          accept(*op);
          op.release(); // release ownership
        }, token);
  }

  bool is_open() const;

  void close(error_code& ec);

  void on_close();
  void on_handshake(int status);
  void on_conncloseframe(int app_error, uint64_t code);

  void on_incoming_stream_closed(stream_impl& s);
  void on_accepting_stream_closed(stream_impl& s);
  void on_connecting_stream_closed(stream_impl& s);
  void on_open_stream_closing(stream_impl& s);
  void on_open_stream_closed(stream_impl& s);
  void on_closing_stream_closed(stream_impl& s);
};

} // namespace nexus::quic::detail
