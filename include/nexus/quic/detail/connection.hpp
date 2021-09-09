#pragma once

#include <nexus/quic/detail/stream.hpp>
#include <nexus/quic/detail/request.hpp>

struct lsquic_conn;

namespace nexus::quic::detail {

struct engine_state;

struct connection_state {
  engine_state& engine;
  lsquic_conn* handle = nullptr;
  conn_open_request* open = nullptr;
  conn_close_request* close_ = nullptr;

  boost::intrusive::list<stream_state> opening_streams;
  //boost::intrusive::list<stream_state> accepting_streams;
  //boost::intrusive::list<stream_state> incoming_streams;

  explicit connection_state(engine_state& engine,
                            const sockaddr* remote_endpoint,
                            const char* remote_hostname)
      : engine(engine) {
    conn_open_request req;
    req.remote_endpoint = remote_endpoint;
    req.remote_hostname = remote_hostname;
    engine.connection_open(*this, req);
    if (*req.ec) {
      throw system_error(*req.ec);
    }
  }
  ~connection_state() {
    error_code ec_ignored;
    close(ec_ignored);
  }

  void open_stream(stream_state& sstate, error_code& ec);
  void close(error_code& ec);
};

} // namespace nexus::quic::detail
