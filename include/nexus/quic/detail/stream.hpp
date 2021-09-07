#pragma once

#include <array>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <optional>

#include <lsquic.h>
#include <lsxpack_header.h>

#include <boost/asio/buffers_iterator.hpp>
#include <boost/smart_ptr/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>

#include <nexus/error_code.hpp>
#include <nexus/http3/fields.hpp>
#include <nexus/quic/detail/engine.hpp>

namespace nexus {
namespace quic::detail {

struct header_transfer_state {
  static constexpr uint16_t max_headers = 64; // XXX
  std::array<lsxpack_header, max_headers> headers;
  uint16_t num_headers = 0;

  std::optional<error_code> ec;
  std::condition_variable cond;

  void write(const http3::fields& fields) {
    for (auto f = fields.begin();
         f != fields.end() && num_headers < max_headers;
         ++f, ++num_headers) {
      auto& header = headers[num_headers];
      const char* buf = f->data();
      const size_t name_offset = std::distance(buf, f->name().data());
      const size_t name_len = f->name().size();
      const size_t val_offset = std::distance(buf, f->value().data());
      const size_t val_len = f->value().size();
      lsxpack_header_set_offset2(&header, buf, name_offset, name_len,
                                 val_offset, val_len);
      header.indexed_type = static_cast<uint8_t>(f->index());
    }
  }

  void read(http3::fields& fields) {
    const auto begin = headers.cbegin();
    const auto end = begin + num_headers;
    for (auto h = begin; h != end; ++h) {
      auto name = std::string_view{h->buf + h->name_offset, h->name_len};
      auto value = std::string_view{h->buf + h->val_offset, h->val_len};
      auto index = static_cast<http3::should_index>(h->indexed_type);
      fields.insert(name, value, index);
    }
  }

  void wait(std::unique_lock<std::mutex>& lock, error_code& ec) {
    cond.wait(lock, [this] { return this->ec; });
    ec = *this->ec;
  }
  void notify(const error_code& ec) {
    this->ec = ec;
    cond.notify_one();
  }
};

struct data_transfer_state {
  static constexpr uint16_t max_iovs = 64;
  std::array<iovec, max_iovs> iovs;
  uint16_t num_iovs = 0;

  std::optional<error_code> ec;
  size_t bytes_transferred = 0;
  std::condition_variable cond;

  template <typename BufferSequence>
  void request(const BufferSequence& buffers) {
    const auto end = boost::asio::buffer_sequence_end(buffers);
    for (auto i = boost::asio::buffer_sequence_begin(buffers);
         i != end && num_iovs < max_iovs; ++i, ++num_iovs) {
      iovs[num_iovs].iov_base = i->data();
      iovs[num_iovs].iov_len = i->size();
    }
  }
  size_t wait(std::unique_lock<std::mutex>& lock, error_code& ec) {
    cond.wait(lock, [this] { return this->ec; });
    ec = *this->ec;
    return bytes_transferred;
  }
  void notify(const error_code& ec, size_t bytes) {
    this->ec = ec;
    bytes_transferred = bytes;
    cond.notify_one();
  }
};

struct stream_transfer_state {
  data_transfer_state* data = nullptr;
  header_transfer_state* header = nullptr;
};

class stream_state : public boost::intrusive::list_base_hook<>,
                     public boost::intrusive_ref_counter<stream_state> {
  engine_state& engine;
  lsquic_stream_t* handle = nullptr;
  stream_transfer_state in;
  stream_transfer_state out;
  bool pending_flush = false;
  bool pending_read_shutdown = false;
  bool pending_write_shutdown = false;
  bool closed = false;
  std::mutex mutex;
 public:
  explicit stream_state(engine_state& engine) : engine(engine) {}

  ~stream_state() {
    std::cout << "~stream_state " << this << std::endl;
    error_code ec_ignored;
    close(ec_ignored);
  }

  void read_headers(http3::fields& fields, error_code& ec) {
    auto lock = std::unique_lock{mutex};
    if (closed || pending_read_shutdown) {
      ec = make_error_code(errc::bad_file_descriptor);
      return;
    }
    auto xfer = header_transfer_state{};
    in.header = &xfer;
    if (handle && lsquic_stream_wantread(handle, 1) == -1) {
      ec.assign(errno, system_category());
      in.header = nullptr;
      return;
    }
    engine.reschedule();
    xfer.wait(lock, ec);
    xfer.read(fields);
    in.header = nullptr;
  }

  template <typename MutableBufferSequence>
  std::enable_if_t<boost::asio::is_mutable_buffer_sequence<
      MutableBufferSequence>::value, size_t>
  read(const MutableBufferSequence& buffers, error_code& ec) {
    auto lock = std::unique_lock{mutex};
    if (closed || pending_read_shutdown) {
      ec = make_error_code(errc::bad_file_descriptor);
      return 0;
    }
    auto xfer = data_transfer_state{};
    xfer.request(buffers);
    in.data = &xfer;
    if (handle && lsquic_stream_wantread(handle, 1) == -1) {
      ec.assign(errno, system_category());
      in.data = nullptr;
      return 0;
    }
    engine.reschedule();
    const auto bytes = xfer.wait(lock, ec);
    in.data = nullptr;
    return bytes;
  }

  void write_headers(const http3::fields& fields, error_code& ec) {
    auto lock = std::unique_lock{mutex};
    if (closed || pending_write_shutdown) {
      ec = make_error_code(errc::bad_file_descriptor);
      return;
    }
    auto xfer = header_transfer_state{};
    xfer.write(fields);
    out.header = &xfer;
    if (handle && lsquic_stream_wantwrite(handle, 1) == -1) {
      ec.assign(errno, system_category());
      out.header = nullptr;
      return;
    }
    engine.reschedule();
    xfer.wait(lock, ec);
    out.header = nullptr;
  }

  template <typename ConstBufferSequence>
  std::enable_if_t<boost::asio::is_const_buffer_sequence<
      ConstBufferSequence>::value, size_t>
  write(const ConstBufferSequence& buffers, error_code& ec) {
    auto lock = std::unique_lock{mutex};
    if (closed || pending_write_shutdown) {
      ec = make_error_code(errc::bad_file_descriptor);
      return 0;
    }
    auto xfer = data_transfer_state{};
    xfer.request(buffers);
    out.data = &xfer;
    if (handle && lsquic_stream_wantwrite(handle, 1) == -1) {
      ec.assign(errno, system_category());
      out.data = nullptr;
      return 0;
    }
    engine.reschedule();
    const auto bytes = xfer.wait(lock, ec);
    out.data = nullptr;
    return bytes;
  }

  void flush(error_code& ec) {
    auto lock = std::unique_lock{mutex};
    if (closed) {
      ec = make_error_code(errc::bad_file_descriptor);
    } else if (handle) {
      if (lsquic_stream_flush(handle) == -1) {
        ec = make_error_code(errc::io_error);
      } else {
        engine.reschedule();
      }
    }
  }

  void shutdown(int how, error_code& ec) {
    const bool shutdown_read = (how == 0 || how == 2);
    const bool shutdown_write = (how == 1 || how == 2);
    auto lock = std::scoped_lock{mutex};
    if (closed) {
      ec = make_error_code(errc::bad_file_descriptor);
    } else if (!handle) {
      // wait until on_open() to call lsquic_stream_shutdown()
      pending_read_shutdown = shutdown_read;
      pending_write_shutdown = shutdown_write;
    } else if (lsquic_stream_shutdown(handle, how) == -1) {
      ec.assign(errno, system_category());
    } else {
      engine.reschedule();
    }
    if (shutdown_read) {
      if (in.header) {
        in.header->notify(boost::asio::error::operation_aborted);
        in.header = nullptr;
      }
      if (in.data) {
        in.data->notify(boost::asio::error::operation_aborted, 0);
        in.data = nullptr;
      }
    }
    if (shutdown_write) {
      if (out.header) {
        out.header->notify(boost::asio::error::operation_aborted);
        out.header = nullptr;
      }
      if (out.data) {
        out.data->notify(boost::asio::error::operation_aborted, 0);
        out.data = nullptr;
      }
    }
  }

  void close(error_code& ec) {
    auto lock = std::scoped_lock{mutex};
    if (closed) {
      ec = make_error_code(errc::bad_file_descriptor);
    } else if (!handle) {
      // wait until on_open() to call lsquic_stream_close()
      closed = true;
    } else if (lsquic_stream_close(handle) == -1) {
      ec.assign(errno, system_category());
    } else {
      engine.reschedule();
    }
    if (in.header) {
      in.header->notify(boost::asio::error::operation_aborted);
      in.header = nullptr;
    }
    if (in.data) {
      in.data->notify(boost::asio::error::operation_aborted, 0);
      in.data = nullptr;
    }
    if (out.header) {
      out.header->notify(boost::asio::error::operation_aborted);
      out.header = nullptr;
    }
    if (out.data) {
      out.data->notify(boost::asio::error::operation_aborted, 0);
      out.data = nullptr;
    }
  }

  void on_open(lsquic_stream_t* stream) {
    std::cerr << "stream_state on_open " << this << std::endl;
    auto lock = std::scoped_lock{mutex};
    // handle early close()
    if (closed) {
      lsquic_stream_close(stream);
      return;
    }
    handle = stream;
    //  handle early shutdown()
    if (pending_read_shutdown && pending_write_shutdown) {
      lsquic_stream_shutdown(handle, 2);
    } else if (pending_read_shutdown) {
      lsquic_stream_shutdown(handle, 0);
    } else if (pending_write_shutdown) {
      lsquic_stream_shutdown(handle, 1);
    }
    // handle early read()
    if ((in.header || in.data) && lsquic_stream_wantread(handle, 1) == -1) {
      if (in.header) {
        in.header->notify({errno, system_category()});
      } else {
        in.data->notify({errno, system_category()}, 0);
      }
    }
    // handle early write()
    if ((out.header || out.data) && lsquic_stream_wantwrite(handle, 1) == -1) {
      if (out.header) {
        out.header->notify({errno, system_category()});
      } else {
        out.data->notify({errno, system_category()}, 0);
      }
    }
  }
  void on_read() {
    std::cerr << "stream_state on_read " << this << std::endl;
    auto lock = std::scoped_lock{mutex};
    if (in.header) { // TODO
    } else if (in.data) {
      const auto bytes = lsquic_stream_readv(handle, in.data->iovs.data(),
                                             in.data->num_iovs);
      if (bytes == -1) {
        in.data->notify({errno, system_category()}, 0);
      } else if (bytes == 0) {
        in.data->notify(boost::asio::error::eof, 0);
      } else {
        in.data->notify({}, bytes);
      }
    }
    lsquic_stream_wantread(handle, 0);
  }
  void on_write() {
    std::cerr << "stream_state on_write " << this << std::endl;
    auto lock = std::scoped_lock{mutex};
    if (out.header) {
      auto headers = lsquic_http_headers{out.header->num_headers,
                                         out.header->headers.data()};
      error_code ec;
      if (lsquic_stream_send_headers(handle, &headers, 0) == -1) {
        ec.assign(errno, system_category());
      }
      out.header->notify(ec);
    } else if (out.data) {
      const auto bytes = lsquic_stream_writev(handle, out.data->iovs.data(),
                                              out.data->num_iovs);
      if (bytes == -1) {
        out.data->notify(make_error_code(errc::io_error), 0);
      } else {
        out.data->notify({}, bytes);
      }
    }
    lsquic_stream_wantwrite(handle, 0);
  }
  void on_close() {
    std::cerr << "stream_state on_close " << this << std::endl;
    auto lock = std::scoped_lock{mutex};
    if (in.header) {
      in.header->notify(make_error_code(errc::connection_reset));
    }
    if (in.data) {
      in.data->notify(make_error_code(errc::connection_reset), 0);
    }
    if (out.header) {
      out.header->notify(make_error_code(errc::connection_reset));
    }
    if (out.data) {
      out.data->notify(make_error_code(errc::connection_reset), 0);
    }
    handle = nullptr;
    closed = true;
  }
};

} // namespace quic::detail
} // namespace nexus
