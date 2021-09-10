#pragma once

#include <memory>
#include <mutex>

#include <liburing.h>
#include <netinet/ip.h>

#include <nexus/error_code.hpp>
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

union sockaddr_union {
  sockaddr_storage storage;
  sockaddr addr;
  sockaddr_in addr4;
  sockaddr_in6 addr6;
};

constexpr size_t ecn_size = sizeof(int);
#ifdef IP_RECVORIGDSTADDR
constexpr size_t dstaddr4_size = sizeof(sockaddr_in);
#else
constexpr size_t dstaddr4_size = sizeof(in_pktinfo)
#endif
constexpr size_t dstaddr_size = std::max(dstaddr4_size, sizeof(in6_pktinfo));
constexpr size_t max_control_size = CMSG_SPACE(ecn_size) + CMSG_SPACE(dstaddr_size);

class engine_state {
  enum class request_type { timer, recv, poll };
  struct timer_request {
    static constexpr size_t buffer_size = sizeof(uint64_t);
    std::array<unsigned char, buffer_size> buffer;
    bool armed = false;
  };
  struct recv_request {
    std::array<unsigned char, 4096> buffer;
    std::array<unsigned char, max_control_size> control;
    sockaddr_union addr; // address of incoming recvmsg()
    msghdr msg;
    iovec iov;
  };

  std::mutex mutex;
  io_uring ring;
  int sockfd = -1;
  int timerfd = -1;
  timer_request timer;
  recv_request recv;

  bool waiting = false; // true if waiting on io_uring_wait_cqe()

  void wait(std::unique_lock<std::mutex>& lock);
  void wait(std::unique_lock<std::mutex>& lock, engine_request& req);

  void on_timer();
  void on_recv(int bytes);
  void on_writeable();

 protected:
  lsquic_engine_ptr handle;
  sockaddr_union local_addr; // socket's bound address

  void start_recv();
  void process();
  void reschedule();
 public:
  explicit engine_state(unsigned flags);
  ~engine_state();

  void close();

  void connection_open(connection_state& cstate, conn_open_request& req);
  void on_connection_open(connection_state& cstate, lsquic_conn* conn);

  void connection_close(connection_state& cstate, conn_close_request& req);
  void on_connection_close(connection_state& cstate, lsquic_conn* conn);

  void stream_open(stream_state& sstate, stream_open_request& req);
  stream_state& on_stream_open(connection_state& cstate,
                               lsquic_stream* stream);

  void stream_read(stream_state& sstate, stream_data_request& req);
  void stream_read_headers(stream_state& sstate, stream_header_read_request& req);
  void on_stream_read(stream_state& sstate);

  void stream_write(stream_state& sstate, stream_data_request& req);
  void stream_write_headers(stream_state& sstate, stream_header_write_request& req);
  void on_stream_write(stream_state& sstate);

  void stream_flush(stream_state& sstate, stream_flush_request& req);

  void stream_shutdown(stream_state& sstate, stream_shutdown_request& req);

  void stream_close(stream_state& sstate, stream_close_request& req);
  void on_stream_close(stream_state& sstate);

  int send_packets(const lsquic_out_spec *specs, unsigned n_specs);
};

} // namespace quic::detail
} // namespace nexus
