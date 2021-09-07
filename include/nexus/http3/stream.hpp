#pragma once

#include <nexus/http3/client.hpp>
#include <nexus/http3/fields.hpp>
#include <nexus/quic/stream.hpp>

namespace nexus {
namespace http3 {

class stream : public quic::stream {
 public:
  explicit stream(client_connection& conn) : quic::stream(conn.open_stream()) {}
  void read_headers(fields& f, error_code& ec) {
    state->read_headers(f, ec);
  }
  template <typename Fields>
  void read_headers(Fields& fields) {
    error_code ec;
    state->read_headers(fields, ec);
    if (ec) {
      throw boost::system::system_error(ec);
    }
  }

  void write_headers(const fields& f, error_code& ec) {
    state->write_headers(f, ec);
  }
  void write_headers(const fields& f) {
    error_code ec;
    state->write_headers(f, ec);
    if (ec) {
      throw boost::system::system_error(ec);
    }
  }
};

} // namespace http3
} // namespace nexus
