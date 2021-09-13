#pragma once

#include <queue>
#include <boost/intrusive/list.hpp>
#include <nexus/detail/completion.hpp>
#include <nexus/quic/detail/stream.hpp>
#include <nexus/udp.hpp>

struct lsquic_conn;
struct lsquic_stream;

namespace nexus::quic::detail {

struct accept_request;
struct engine_state;

struct connection_state : public boost::intrusive::list_base_hook<> {
  engine_state& engine;
  lsquic_conn* handle = nullptr;
  accept_request* accept_ = nullptr;

  std::unique_ptr<accept_completion> async_accept_;

  boost::intrusive::list<stream_state> connecting_streams;
  boost::intrusive::list<stream_state> accepting_streams;
  std::queue<lsquic_stream*> incoming_streams;

  explicit connection_state(engine_state& engine) : engine(engine) {}
  ~connection_state() {
    error_code ec_ignored;
    close(ec_ignored);
  }

  using executor_type = asio::any_io_executor;
  executor_type get_executor();

  udp::endpoint remote_endpoint();

  void connect(const udp::endpoint& endpoint, const char* hostname);
  void accept(error_code& ec);
  void close(error_code& ec);
};

} // namespace nexus::quic::detail
