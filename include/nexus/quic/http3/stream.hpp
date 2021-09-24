#pragma once

#include <nexus/quic/stream.hpp>
#include <nexus/quic/http3/fields.hpp>

namespace nexus::quic::http3 {

class client_connection;
class server_connection;

class stream : public quic::stream {
  friend class client_connection;
  friend class server_connection;
 public:
  explicit stream(client_connection& c);
  explicit stream(server_connection& c);

  template <typename CompletionToken> // void(error_code)
  decltype(auto) async_read_headers(fields& f, CompletionToken&& token) {
    return state.async_read_headers(f, std::forward<CompletionToken>(token));
  }

  void read_headers(fields& f, error_code& ec);
  void read_headers(fields& f);

  template <typename CompletionToken> // void(error_code)
  decltype(auto) async_write_headers(const fields& f, CompletionToken&& token) {
    return state.async_write_headers(f, std::forward<CompletionToken>(token));
  }

  void write_headers(const fields& f, error_code& ec);
  void write_headers(const fields& f);
};

} // namespace nexus::quic::http3
