#include <nexus/quic/detail/connection.hpp>
#include <nexus/quic/detail/engine.hpp>
#include <nexus/quic/detail/stream.hpp>
#include <nexus/quic/http3/fields.hpp>

#include <lsquic.h>
#include <lsxpack_header.h>

namespace nexus::quic::detail {

void stream_state::read_headers(http3::fields& fields, error_code& ec)
{
  stream_header_request req;
  conn.engine.stream_read_headers(*this, req);
  ec = *req.ec;
  // TODO: copy out headers
}

size_t stream_state::read(stream_data_request& req, error_code& ec)
{
  conn.engine.stream_read(*this, req);
  ec = *req.ec;
  return req.bytes;
}

size_t stream_state::write(stream_data_request& req, error_code& ec)
{
  conn.engine.stream_write(*this, req);
  ec = *req.ec;
  return req.bytes;
}

void stream_state::write_headers(const http3::fields& fields, error_code& ec)
{
  // stack-allocate enough headers for the request
  const auto count = fields.size();
  auto p = ::alloca(count * sizeof(lsxpack_header));
  stream_header_request req;
  req.headers = reinterpret_cast<lsxpack_header*>(p);

  for (auto f = fields.begin(); f != fields.end(); ++f, ++req.num_headers) {
    auto& header = req.headers[req.num_headers];
    const char* buf = f->data();
    const size_t name_offset = std::distance(buf, f->name().data());
    const size_t name_len = f->name().size();
    const size_t val_offset = std::distance(buf, f->value().data());
    const size_t val_len = f->value().size();
    lsxpack_header_set_offset2(&header, buf, name_offset, name_len,
                               val_offset, val_len);
    header.indexed_type = static_cast<uint8_t>(f->index());
  }
  conn.engine.stream_write_headers(*this, req);
  ec = *req.ec;
}

void stream_state::flush(error_code& ec)
{
  stream_flush_request req;
  conn.engine.stream_flush(*this, req);
  ec = *req.ec;
}

void stream_state::shutdown(int how, error_code& ec)
{
  stream_shutdown_request req;
  req.how = how;
  conn.engine.stream_shutdown(*this, req);
  ec = *req.ec;
}

void stream_state::close(error_code& ec)
{
  stream_close_request req;
  conn.engine.stream_close(*this, req);
  ec = *req.ec;
}

} // namespace nexus::quic::detail
