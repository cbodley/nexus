#include <nexus/quic/detail/connection.hpp>
#include <nexus/quic/detail/engine.hpp>
#include <nexus/quic/detail/stream.hpp>
#include <nexus/quic/http3/fields.hpp>

#include <lsquic.h>
#include <lsxpack_header.h>

namespace nexus::quic::detail {

stream_state::executor_type stream_state::get_executor()
{
  return conn.get_executor();
}

void stream_state::connect(error_code& ec)
{
  stream_connect_request req;
  conn.engine.stream_connect(*this, req);
  ec = *req.ec;
}

void stream_state::accept(error_code& ec)
{
  stream_accept_request req;
  conn.engine.stream_accept(*this, req);
  ec = *req.ec;
}

void stream_state::read_headers(http3::fields& fields, error_code& ec)
{
  stream_header_read_request req;
  req.fields = &fields;
  conn.engine.stream_read_headers(*this, req);
  ec = *req.ec;
}

size_t stream_state::read(stream_data_request& req, error_code& ec)
{
  conn.engine.stream_read(*this, req);
  ec = *req.ec;
  return req.bytes_transferred;
}

size_t stream_state::write(stream_data_request& req, error_code& ec)
{
  conn.engine.stream_write(*this, req);
  ec = *req.ec;
  return req.bytes_transferred;
}

void stream_state::write_headers(const http3::fields& fields, error_code& ec)
{
  stream_header_write_request req;
  req.fields = &fields;
  conn.engine.stream_write_headers(*this, req);
  ec = *req.ec;
}

void stream_state::flush(error_code& ec)
{
  conn.engine.stream_flush(*this, ec);
}

void stream_state::shutdown(int how, error_code& ec)
{
  conn.engine.stream_shutdown(*this, how, ec);
}

void stream_state::close(error_code& ec)
{
  conn.engine.stream_close(*this, ec);
}

} // namespace nexus::quic::detail
