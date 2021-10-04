#pragma once

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
  // make sure that connection errors get delivered to the application. if we
  // see a fatal connection error while there are no pending operations we can
  // deliver the error to, save it here and deliver it to the next operation
  error_code err;
  lsquic_conn* handle = nullptr;
  accept_operation* accept_ = nullptr;

  // incoming streams ready to accept. the connection maintains ownership of
  // these until they're accepted
  boost::intrusive::list<stream_state> incoming_streams;

  boost::intrusive::list<stream_state> connecting_streams;
  boost::intrusive::list<stream_state> accepting_streams;
  boost::intrusive::list<stream_state> connected_streams;

  explicit connection_state(socket_state& socket) : socket(socket) {}
  ~connection_state() {
    error_code ec_ignored;
    close(ec_ignored);
  }

  using executor_type = asio::any_io_executor;
  executor_type get_executor() const;

  udp::endpoint remote_endpoint();

  void connect(stream_connect_operation& op);

  template <typename Stream, typename CompletionToken>
  decltype(auto) async_connect(Stream& s, CompletionToken&& token) {
    auto& sstate = s.state;
    return asio::async_initiate<CompletionToken, void(error_code)>(
        [this, &sstate] (auto h) {
          using Handler = std::decay_t<decltype(h)>;
          using op_type = stream_connect_async<Handler, executor_type>;
          auto p = handler_allocate<op_type>(h, std::move(h),
                                             get_executor(), sstate);
          auto op = handler_ptr<op_type, Handler>{p, &p->handler};
          connect(*op);
          op.release(); // release ownership
        }, token);
  }

  void accept(stream_accept_operation& op);

  template <typename Stream, typename CompletionToken>
  decltype(auto) async_accept(Stream& s, CompletionToken&& token) {
    auto& sstate = s.state;
    return asio::async_initiate<CompletionToken, void(error_code)>(
        [this, &sstate] (auto h) {
          using Handler = std::decay_t<decltype(h)>;
          using op_type = stream_accept_async<Handler, executor_type>;
          auto p = handler_allocate<op_type>(h, std::move(h),
                                             get_executor(), sstate);
          auto op = handler_ptr<op_type, Handler>{p, &p->handler};
          accept(*op);
          op.release(); // release ownership
        }, token);
  }

  void close(error_code& ec);
};

} // namespace nexus::quic::detail
