#pragma once

#include <memory>
#include <mutex>
#include <queue>

#include <asio/basic_waitable_timer.hpp>
#include <boost/intrusive/list.hpp>

#include <nexus/error_code.hpp>
#include <nexus/udp.hpp>
#include <nexus/quic/detail/operation.hpp>
#include <nexus/quic/detail/socket.hpp>

struct lsquic_engine;
struct lsquic_conn;
struct lsquic_stream;
struct lsquic_out_spec;

namespace nexus {
namespace quic::detail {

struct connection_state;
struct stream_state;

struct engine_deleter { void operator()(lsquic_engine* e) const; };
using lsquic_engine_ptr = std::unique_ptr<lsquic_engine, engine_deleter>;

class engine_state {
  std::mutex mutex;
  asio::any_io_executor ex;
  ssl::certificate_provider* certs;
  asio::steady_timer timer;
  lsquic_engine_ptr handle;
  bool is_server;

  void process(std::unique_lock<std::mutex>& lock);
  void reschedule(std::unique_lock<std::mutex>& lock);
  void on_timer();

  void start_recv(socket_state& socket);
  void on_readable(socket_state& socket);
  void on_writeable(socket_state& socket);

 public:
  engine_state(const asio::any_io_executor& ex, unsigned flags,
               ssl::certificate_provider* server_certs,
               const char* client_alpn);
  ~engine_state();

  using executor_type = asio::any_io_executor;
  executor_type get_executor() { return ex; }

  // return the bound address
  udp::endpoint local_endpoint(socket_state& socket) const;
  // return the connection's remote address
  udp::endpoint remote_endpoint(connection_state& cstate);

  void close();

  void listen(socket_state& socket, int backlog);
  void close(socket_state& socket, error_code& ec);

  void connect(connection_state& cstate,
               const udp::endpoint& endpoint,
               const char* hostname);
  void on_connect(connection_state& cstate, lsquic_conn* conn);

  void accept(connection_state& cstate, accept_operation& op);
  connection_state* on_accept(lsquic_conn* conn);

  void close(connection_state& cstate, error_code& ec);
  void on_close(connection_state& cstate, lsquic_conn* conn);

  void do_close(connection_state& cstate, error_code ec);

  void stream_connect(stream_state& sstate,
                      stream_connect_operation& op);
  stream_state* on_stream_connect(connection_state& cstate,
                                  lsquic_stream* stream);

  void stream_accept(stream_state& sstate, stream_accept_operation& op);
  stream_state* on_stream_accept(connection_state& cstate,
                                 lsquic_stream* stream);
  stream_state* on_new_stream(connection_state& cstate,
                              lsquic_stream* stream);

  void stream_read(stream_state& sstate, stream_data_operation& op);
  void stream_read_headers(stream_state& sstate,
                           stream_header_read_operation& op);
  void on_stream_read(stream_state& sstate);

  void stream_write(stream_state& sstate, stream_data_operation& op);
  void stream_write_headers(stream_state& sstate,
                            stream_header_write_operation& op);
  void on_stream_write(stream_state& sstate);

  void stream_flush(stream_state& sstate, error_code& ec);
  void stream_shutdown(stream_state& sstate, int how, error_code& ec);

  void stream_close(stream_state& sstate, error_code& ec);
  void on_stream_close(stream_state& sstate);

  int send_packets(const lsquic_out_spec *specs, unsigned n_specs);
};

} // namespace quic::detail
} // namespace nexus
