#pragma once

#include <queue>
#include <boost/intrusive/list.hpp>
#include <nexus/quic/detail/stream.hpp>
#include <nexus/udp.hpp>

struct lsquic_conn;
struct lsquic_stream;

namespace nexus::quic::detail {

struct accept_operation;
struct socket_state;

struct connection_state : public boost::intrusive::list_base_hook<> {
  socket_state& socket;
  lsquic_conn* handle = nullptr;
  accept_operation* accept_ = nullptr;

  boost::intrusive::list<stream_state> connecting_streams;
  boost::intrusive::list<stream_state> accepting_streams;
  std::queue<lsquic_stream*> incoming_streams;

  explicit connection_state(socket_state& socket) : socket(socket) {}
  ~connection_state() {
    error_code ec_ignored;
    close(ec_ignored);
  }

  using executor_type = asio::any_io_executor;
  executor_type get_executor();

  udp::endpoint remote_endpoint();

  void connect(stream_state& sstate, stream_connect_operation& op);

  template <typename Stream, typename CompletionToken>
  decltype(auto) async_connect(Stream& s, CompletionToken&& token) {
    auto& sstate = s.state;
    return asio::async_initiate<CompletionToken, void(error_code)>(
        [this, &sstate] (auto h) {
          using Handler = std::decay_t<decltype(h)>;
          using op_type = stream_connect_async<Handler, executor_type>;
          auto p = handler_allocate<op_type>(h, std::move(h), get_executor());
          auto op = handler_ptr<op_type, Handler>{p, &p->handler};
          connect(sstate, *op);
          op.release(); // release ownership
        }, token);
  }

  void accept(stream_state& sstate, stream_accept_operation& op);

  template <typename Stream, typename CompletionToken>
  decltype(auto) async_accept(Stream& s, CompletionToken&& token) {
    auto& sstate = s.state;
    return asio::async_initiate<CompletionToken, void(error_code)>(
        [this, &sstate] (auto h) {
          using Handler = std::decay_t<decltype(h)>;
          using op_type = stream_accept_async<Handler, executor_type>;
          auto p = handler_allocate<op_type>(h, std::move(h), get_executor());
          auto op = handler_ptr<op_type, Handler>{p, &p->handler};
          connect(sstate, *op);
          op.release(); // release ownership
        }, token);
  }

  void close(error_code& ec);
};

} // namespace nexus::quic::detail
