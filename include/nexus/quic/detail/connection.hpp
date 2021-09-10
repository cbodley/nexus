#pragma once

#include <queue>
#include <boost/intrusive/list.hpp>
#include <nexus/quic/detail/socket.hpp>
#include <nexus/quic/detail/stream.hpp>
#include <nexus/quic/detail/request.hpp>
#include <nexus/quic/sockaddr.hpp>

struct lsquic_conn;
struct lsquic_stream;

namespace nexus::quic::detail {

struct engine_state;

struct connection_state : public boost::intrusive::list_base_hook<> {
  engine_state& engine;
  sockaddr_union peer; // peer address from connect/accept
  lsquic_conn* handle = nullptr;
  connect_request* connect_ = nullptr;
  accept_request* accept_ = nullptr;
  close_request* close_ = nullptr;

  boost::intrusive::list<stream_state> opening_streams;
  boost::intrusive::list<stream_state> accepting_streams;
  std::queue<lsquic_stream*> incoming_streams;

  explicit connection_state(engine_state& engine) : engine(engine) {}
  ~connection_state() {
    error_code ec_ignored;
    close(ec_ignored);
  }

  void remote_endpoint(sockaddr_union& remote);
  void connect(const sockaddr* endpoint, const char* hostname, error_code& ec);
  void accept(error_code& ec);
  void close(error_code& ec);
};

} // namespace nexus::quic::detail
