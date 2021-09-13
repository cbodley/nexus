#pragma once

#include <memory>
#include <mutex>
#include <queue>

#include <asio/basic_waitable_timer.hpp>

#include <nexus/error_code.hpp>
#include <nexus/udp.hpp>
#include <nexus/quic/detail/request.hpp>

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
  udp::socket socket;
  asio::basic_waitable_timer<std::chrono::steady_clock> timer;
  lsquic_engine_ptr handle;
  udp::endpoint local_addr; // socket's bound address
  bool is_server;
  boost::intrusive::list<connection_state> accepting_connections;
  std::queue<lsquic_conn*> incoming_connections;

  void start_recv();
  void process(std::unique_lock<std::mutex>& lock);
  void reschedule(std::unique_lock<std::mutex>& lock);

  void on_readable();
  void on_writeable();
  void on_timer();

  void wait(std::unique_lock<std::mutex>& lock, engine_request& req);

 public:
  engine_state(const asio::any_io_executor& ex,
               const udp::endpoint& endpoint,
               unsigned flags);
  engine_state(udp::socket&& socket, unsigned flags);
  ~engine_state();

  using executor_type = asio::any_io_executor;
  executor_type get_executor() { return socket.get_executor(); }

  // return the bound address
  udp::endpoint local_endpoint() const;
  // return the connection's remote address
  udp::endpoint remote_endpoint(connection_state& cstate);

  void close();

  void connect(connection_state& cstate,
               const udp::endpoint& endpoint,
               const char* hostname);
  void on_connect(connection_state& cstate, lsquic_conn* conn);

  void accept(connection_state& cstate, accept_request& req);
  connection_state* on_accept(lsquic_conn* conn);

  void close(connection_state& cstate, error_code& ec);
  void on_close(connection_state& cstate, lsquic_conn* conn);

  void stream_connect(stream_state& sstate,
                      stream_connect_request& req);
  void stream_connect_async(stream_state& sstate,
                            std::unique_ptr<stream_connect_completion>&& c);
  void stream_connect_init(std::unique_lock<std::mutex>& lock,
                           stream_state& sstate,
                           stream_connect_request& req);
  stream_state& on_stream_connect(connection_state& cstate,
                                  lsquic_stream* stream);

  void stream_accept(stream_state& sstate, stream_accept_request& req);
  void stream_accept_async(stream_state& sstate,
                           std::unique_ptr<stream_accept_completion>&& c);
  void stream_accept_init(std::unique_lock<std::mutex>& lock,
                          stream_state& sstate,
                          stream_accept_request& req);
  stream_state& on_stream_accept(connection_state& cstate,
                                 lsquic_stream* stream);

  void stream_read(stream_state& sstate, stream_data_request& req);
  void stream_read_async(stream_state& sstate,
                         std::unique_ptr<stream_data_completion>&& c);
  void stream_read_init(std::unique_lock<std::mutex>& lock,
                        stream_state& sstate,
                        stream_data_request& req);

  void stream_read_headers(stream_state& sstate,
                           stream_header_read_request& req);
  void stream_read_headers_async(stream_state& sstate,
                                 stream_header_read_completion&& c);
  void stream_read_headers_init(std::unique_lock<std::mutex>& lock,
                                stream_state& sstate,
                                stream_header_read_request& req);

  void on_stream_read(stream_state& sstate);

  void stream_write(stream_state& sstate, stream_data_request& req);
  void stream_write_async(stream_state& sstate,
                          std::unique_ptr<stream_data_completion>&& c);
  void stream_write_init(std::unique_lock<std::mutex>& lock,
                         stream_state& sstate,
                         stream_data_request& req);

  void stream_write_headers(stream_state& sstate,
                            stream_header_write_request& req);
  void stream_write_headers_async(stream_state& sstate,
                                  std::unique_ptr<stream_header_write_completion>&& c);
  void stream_write_headers_init(std::unique_lock<std::mutex>& lock,
                                 stream_state& sstate,
                                 stream_header_write_request& req);

  void on_stream_write(stream_state& sstate);

  void stream_flush(stream_state& sstate, error_code& ec);
  void stream_shutdown(stream_state& sstate, int how, error_code& ec);

  void stream_close(stream_state& sstate, error_code& ec);
  void on_stream_close(stream_state& sstate);

  int send_packets(const lsquic_out_spec *specs, unsigned n_specs);
};

} // namespace quic::detail
} // namespace nexus
