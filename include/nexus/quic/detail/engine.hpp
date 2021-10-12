#pragma once

#include <memory>
#include <mutex>

#include <asio/basic_waitable_timer.hpp>
#include <boost/intrusive/list.hpp>

#include <nexus/error_code.hpp>
#include <nexus/udp.hpp>
#include <nexus/quic/settings.hpp>
#include <nexus/quic/detail/operation.hpp>
#include <nexus/quic/detail/socket.hpp>

struct lsquic_engine;
struct lsquic_conn;
struct lsquic_stream;
struct lsquic_out_spec;

namespace nexus::quic::detail {

struct connection_state;
struct stream_impl;

struct engine_deleter { void operator()(lsquic_engine* e) const; };
using lsquic_engine_ptr = std::unique_ptr<lsquic_engine, engine_deleter>;

class engine_state {
  mutable std::mutex mutex;
  asio::any_io_executor ex;
  asio::steady_timer timer;
  lsquic_engine_ptr handle;
  // pointer to client socket or null if server
  socket_state* client;

  void process(std::unique_lock<std::mutex>& lock);
  void reschedule(std::unique_lock<std::mutex>& lock);
  void on_timer();

  void start_recv(socket_state& socket);
  void on_readable(socket_state& socket);
  void on_writeable(socket_state& socket);

 public:
  engine_state(const asio::any_io_executor& ex, socket_state* client,
               const settings* s, unsigned flags);
  ~engine_state();

  using executor_type = asio::any_io_executor;
  executor_type get_executor() const { return ex; }

  // return the bound address
  udp::endpoint local_endpoint(socket_state& socket) const;
  // return the connection's remote address
  udp::endpoint remote_endpoint(connection_state& c);

  void close();

  // sockets
  void listen(socket_state& socket, int backlog);
  void close(socket_state& socket);

  int send_packets(const lsquic_out_spec *specs, unsigned n_specs);

  // connections
  void connect(connection_state& c,
               const udp::endpoint& endpoint,
               const char* hostname);
  void on_connect(connection_state& c, lsquic_conn* conn);
  void on_handshake(connection_state& c, int status);

  void accept(connection_state& c, accept_operation& op);
  connection_state* on_accept(lsquic_conn* conn);

  bool is_open(const connection_state& c) const;

  void close(connection_state& c, error_code& ec);
  void on_close(connection_state& c, lsquic_conn* conn);

  void on_conncloseframe(connection_state& c, int app_error, uint64_t code);

  int cancel(connection_state& c, error_code ec);

  // streams
  void stream_connect(connection_state& c, stream_connect_operation& op);
  stream_impl* on_stream_connect(connection_state& c, lsquic_stream* stream);

  void stream_accept(connection_state& c, stream_accept_operation& op);
  stream_impl* on_stream_accept(connection_state& c, lsquic_stream* stream);
  stream_impl* on_new_stream(connection_state& c, lsquic_stream* stream);

  bool is_open(const stream_impl& s) const;

  void stream_read(stream_impl& s, stream_data_operation& op);
  void stream_read_headers(stream_impl& s, stream_header_read_operation& op);
  void on_stream_read(stream_impl& s);

  void stream_write(stream_impl& s, stream_data_operation& op);
  void stream_write_headers(stream_impl& s, stream_header_write_operation& op);
  void on_stream_write(stream_impl& s);

  int stream_cancel_read(stream_impl& s, error_code ec);
  int stream_cancel_write(stream_impl& s, error_code ec);

  void stream_flush(stream_impl& s, error_code& ec);
  void stream_shutdown(stream_impl& s, int how, error_code& ec);

  bool try_stream_reset(stream_impl& s);
  void stream_reset(stream_impl& s);

  void stream_close(stream_impl& s, stream_close_operation& op);
  void on_stream_close(stream_impl& s);
};

} // namespace nexus::quic::detail
