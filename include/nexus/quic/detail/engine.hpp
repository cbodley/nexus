#pragma once

#include <chrono>
#include <memory>

#include <lsquic.h>

#include <boost/asio/executor.hpp>
#include <boost/asio/basic_waitable_timer.hpp>
#include <boost/smart_ptr/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>

#include <nexus/error_code.hpp>
#include <nexus/udp.hpp>

namespace nexus {
namespace quic::detail {

struct engine_deleter {
  void operator()(lsquic_engine_t* e) const { lsquic_engine_destroy(e); }
};
using lsquic_engine_ptr = std::unique_ptr<lsquic_engine_t, engine_deleter>;

class engine_state : public boost::intrusive_ref_counter<engine_state> {
 protected:
  lsquic_engine_ptr handle;
  udp::socket socket;
  udp::endpoint local_endpoint;

  using clock_type = std::chrono::system_clock;
  using timer_type = boost::asio::basic_waitable_timer<clock_type>;
  timer_type timer;

  auto self() { return boost::intrusive_ptr<engine_state>(this); }

 public:
  explicit engine_state(const boost::asio::executor& ex);
  ~engine_state();

  void enable_tos(error_code& ec);
  void enable_dstaddr(error_code& ec);

  void close();
  void process();
  void reschedule();
  void recv();
  void on_recv_ready(error_code ec);
  int send_packets(const lsquic_out_spec *specs, unsigned n_specs);
};

} // namespace quic::detail
} // namespace nexus
