#pragma once

#include <boost/intrusive/list.hpp>
#include <boost/circular_buffer.hpp>
#include <nexus/ssl.hpp>
#include <nexus/quic/detail/connection.hpp>

struct lsquic_out_spec;

namespace nexus::quic::detail {

class engine_state;
struct connection_state;

union sockaddr_union {
  sockaddr_storage storage;
  sockaddr addr;
  sockaddr_in addr4;
  sockaddr_in6 addr6;
};

struct socket_state : boost::intrusive::list_base_hook<> {
  engine_state& engine;
  udp::socket socket;
  asio::ssl::context& ssl;
  udp::endpoint local_addr; // socket's bound address
  boost::circular_buffer<lsquic_conn*> incoming_connections;
  boost::intrusive::list<connection_state> accepting_connections;
  boost::intrusive::list<connection_state> connected;
  bool receiving = false;

  socket_state(engine_state& engine, udp::socket&& socket,
               asio::ssl::context& ssl);
  socket_state(engine_state& engine, const udp::endpoint& endpoint,
               bool is_server, asio::ssl::context& ssl);
  ~socket_state() {
    close();
  }

  using executor_type = asio::any_io_executor;
  executor_type get_executor() const;

  udp::endpoint local_endpoint() const { return local_addr; }

  void listen(int backlog);

  void connect(connection_state& cstate,
               const udp::endpoint& endpoint,
               const char* hostname);

  void accept(connection_state& cstate, accept_operation& op);

  template <typename Connection, typename CompletionToken>
  decltype(auto) async_accept(Connection& conn,
                              CompletionToken&& token) {
    auto& cstate = conn.state;
    return asio::async_initiate<CompletionToken, void(error_code)>(
        [this, &cstate] (auto h) {
          using Handler = std::decay_t<decltype(h)>;
          using op_type = accept_async<Handler, executor_type>;
          auto p = handler_allocate<op_type>(h, std::move(h), get_executor());
          auto op = handler_ptr<op_type, Handler>{p, &p->handler};
          accept(cstate, *op);
          op.release(); // release ownership
        }, token);
  }

  void close();

  const lsquic_out_spec* send_packets(const lsquic_out_spec* begin,
                                      const lsquic_out_spec* end,
                                      error_code& ec);

  size_t recv_packet(iovec iov, udp::endpoint& peer, sockaddr_union& self,
                     int& ecn, error_code& ec);
};

} // namespace nexus::quic::detail
