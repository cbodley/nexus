#pragma once

#include <memory>
#include <mutex>

#include <asio/basic_waitable_timer.hpp>
#include <boost/intrusive/list.hpp>

#include <nexus/error_code.hpp>
#include <nexus/udp.hpp>
#include <nexus/quic/settings.hpp>
#include <nexus/quic/detail/operation.hpp>
#include <nexus/quic/detail/socket_impl.hpp>

struct lsquic_engine;
struct lsquic_conn;
struct lsquic_stream;
struct lsquic_out_spec;

namespace nexus::quic::detail {

struct connection_impl;
struct stream_impl;

struct engine_deleter { void operator()(lsquic_engine* e) const; };
using lsquic_engine_ptr = std::unique_ptr<lsquic_engine, engine_deleter>;

struct engine_impl {
  mutable std::mutex mutex;
  asio::any_io_executor ex;
  asio::steady_timer timer;
  lsquic_engine_ptr handle;
  // pointer to client socket or null if server
  socket_impl* client;
  bool is_http = false;

  void process(std::unique_lock<std::mutex>& lock);
  void reschedule(std::unique_lock<std::mutex>& lock);
  void on_timer();

  engine_impl(const asio::any_io_executor& ex, socket_impl* client,
              const settings* s, unsigned flags);
  ~engine_impl();

  using executor_type = asio::any_io_executor;
  executor_type get_executor() const { return ex; }

  void close();

  int send_packets(const lsquic_out_spec *specs, unsigned n_specs);

  stream_impl* on_new_stream(connection_impl& c, lsquic_stream* stream);
};

} // namespace nexus::quic::detail
