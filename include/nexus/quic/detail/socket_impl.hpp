#pragma once

#include <boost/intrusive/list.hpp>
#include <boost/circular_buffer.hpp>
#include <nexus/ssl.hpp>
#include <nexus/quic/detail/connection_impl.hpp>

struct lsquic_out_spec;

namespace nexus::quic::detail {

struct engine_impl;
struct connection_impl;

union sockaddr_union {
  sockaddr_storage storage;
  sockaddr addr;
  sockaddr_in addr4;
  sockaddr_in6 addr6;
};

using connection_list = boost::intrusive::list<connection_impl>;

inline void list_erase(connection_impl& s, connection_list& from)
{
  from.erase(from.iterator_to(s));
}

inline void list_transfer(connection_impl& s, connection_list& from,
                          connection_list& to)
{
  from.erase(from.iterator_to(s));
  to.push_back(s);
}

struct socket_impl : boost::intrusive::list_base_hook<> {
  engine_impl& engine;
  udp::socket socket;
  asio::ssl::context& ssl;
  udp::endpoint local_addr; // socket's bound address
  boost::circular_buffer<lsquic_conn*> incoming_connections;
  connection_list accepting_connections;
  connection_list open_connections;
  bool receiving = false;

  socket_impl(engine_impl& engine, udp::socket&& socket,
              asio::ssl::context& ssl);
  socket_impl(engine_impl& engine, const udp::endpoint& endpoint,
              bool is_server, asio::ssl::context& ssl);
  ~socket_impl() {
    close();
  }

  using executor_type = asio::any_io_executor;
  executor_type get_executor() const;

  udp::endpoint local_endpoint() const { return local_addr; }

  void listen(int backlog);

  void connect(connection_impl& c,
               const udp::endpoint& endpoint,
               const char* hostname);

  void accept(connection_impl& c, accept_operation& op);

  template <typename Connection, typename CompletionToken>
  decltype(auto) async_accept(Connection& conn,
                              CompletionToken&& token) {
    auto& c = conn.impl;
    return asio::async_initiate<CompletionToken, void(error_code)>(
        [this, &c] (auto h) {
          using Handler = std::decay_t<decltype(h)>;
          using op_type = accept_async<Handler, executor_type>;
          auto p = handler_allocate<op_type>(h, std::move(h), get_executor());
          auto op = handler_ptr<op_type, Handler>{p, &p->handler};
          accept(c, *op);
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
