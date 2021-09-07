#pragma once

#include <memory>

#include <boost/intrusive/list.hpp>
#include <lsquic.h>

#include <nexus/quic/detail/stream.hpp>
#include <nexus/quic/detail/engine.hpp>

namespace nexus::quic::detail {

class client_engine_state;

class client_connection_state : public boost::intrusive_ref_counter<client_connection_state> {
  friend class client_engine_state;
  client_engine_state& engine;
  lsquic_conn_t* handle = nullptr;
  boost::intrusive::list<stream_state> opening_streams;
 public:
  explicit client_connection_state(client_engine_state& engine)
      : engine(engine) {}
  ~client_connection_state();

  boost::intrusive_ptr<stream_state> open_stream();
  void close();

  // stream api
  void on_open(lsquic_conn_t* conn);
  void on_close();
  boost::intrusive_ptr<stream_state> on_new_stream(lsquic_stream_t* stream);
};

class client_engine_state : public engine_state {
  friend class client_connection_state;
  std::atomic<uint32_t> num_connections;
  void on_conn_close();
 public:
  explicit client_engine_state(const boost::asio::executor& ex)
    : engine_state(ex)
  {}

  auto connect(const udp::endpoint& remote_endpoint,
               const char* remote_hostname)
      -> boost::intrusive_ptr<client_connection_state>;

  static auto create(const boost::asio::executor& ex, unsigned flags)
      -> boost::intrusive_ptr<detail::client_engine_state>;
};

} // namespace nexus::quic::detail
