#pragma once

#include <condition_variable>
#include <mutex>
#include <optional>

#include <boost/beast/core/buffers_suffix.hpp>
#include <boost/beast/http/type_traits.hpp>

#include <nexus/http2/error.hpp>
#include <nexus/http2/detail/stream.hpp>

namespace nexus::http2::detail {

namespace bi = boost::intrusive;

template <typename T>
constexpr bool is_fields_v = boost::beast::http::is_fields<T>::value;
template <typename T>
constexpr bool is_body_reader_v = boost::beast::http::is_body_reader<T>::value;
template <typename T>
constexpr bool is_body_writer_v = boost::beast::http::is_body_writer<T>::value;

class stream_scheduler {
 protected:
  stream_set streams;

  struct waiter : stream_waiter {
    protocol::stream_identifier stream_id;
    std::mutex mutex;
    std::condition_variable cond;
  };

  struct writer : waiter, bi::list_base_hook<> {
    size_t size; // number of output bytes available
  };
  // writers with flow control window available: min(size, frame_size)
  bi::list<writer> writers_ready;

  struct reader : waiter {
    std::optional<boost::system::error_code> result;
    void complete(boost::system::error_code ec) override {
      std::scoped_lock lock{mutex};
      result = ec;
      cond.notify_one();
    }
  };
  struct accepter : reader, bi::list_base_hook<> {};

  // waiters for the next incoming stream
  bi::list<accepter> accept_waiters;
  // remote streams that haven't been accepted yet
  bi::list<stream_impl> accept_streams;
 public:
  ~stream_scheduler() {
    streams.clear_and_dispose(std::default_delete<stream_impl>{});
  }

  template <typename Fields>
  auto read_header(protocol::stream_identifier& stream_id,
                   Fields& fields, boost::system::error_code& ec)
    -> std::enable_if_t<is_fields_v<Fields>, size_t>;

  template <typename BodyReader>
  size_t read_some_body(protocol::stream_identifier stream_id,
                        BodyReader& body,
                        boost::system::error_code& ec);

  template <typename Fields>
  auto write_header(protocol::stream_identifier& stream_id,
                    const Fields& fields, boost::system::error_code& ec)
    -> std::enable_if_t<is_fields_v<Fields>>;

  template <typename BodyWriter>
  size_t write_some_body(protocol::stream_identifier stream_id,
                         const BodyWriter& body,
                         boost::system::error_code& ec);
};

template <typename Fields>
auto stream_scheduler::read_header(
    protocol::stream_identifier& stream_id,
    Fields& fields,
    boost::system::error_code& ec)
  -> std::enable_if_t<is_fields_v<Fields>, size_t>
{
  auto stream = streams.end();
  if (stream_id == 0) {
    // take the first accept stream
    if (accept_streams.empty()) {
      accepter a;
      std::unique_lock lock{a.mutex};
      accept_waiters.push_back(a);
      a.cond.wait(lock, [&a] { return a.result; });
      ec = *a.result;
      accept_waiters.erase(accept_waiters.iterator_to(a));
      if (ec) {
        return 0;
      }
    }
    assert(!accept_streams.empty());
    stream = streams.iterator_to(accept_streams.front());
    accept_streams.pop_front();
    stream_id = stream->id;
  } else {
    stream = streams.find(stream_id, stream_id_less{});
    if (stream == streams.end()) {
      ec = make_error_code(protocol::error::protocol_error);
      return 0;
    }
  }
  assert(stream != streams.end());
  if (!stream->read_headers) {
    reader r;
    std::unique_lock lock{r.mutex};
    stream->reader = &r;
    r.cond.wait(lock, [&r] { return r.result; });
    ec = *r.result;
    stream->reader = nullptr;
  }
  // copy out the fields, TODO: specialize for http2::basic_fields
  auto headers = std::move(stream->headers);
  for (const auto& h : headers) {
    if (h.name() != boost::beast::http::field::unknown) {
      fields.insert(h.name(), h.value());
    } else {
      fields.insert(h.name_string(), h.value());
    }
  }
  headers.clear_and_dispose(std::default_delete<detail::field_pair<>>{});
  return 0;
}

template <typename BodyReader>
size_t stream_scheduler::read_some_body(
    protocol::stream_identifier stream_id,
    BodyReader& body,
    boost::system::error_code& ec)
{
  if (stream_id == 0) {
    ec = make_error_code(protocol::error::protocol_error);
    return 0;
  }
  auto stream = streams.find(stream_id, stream_id_less{});
  if (stream == streams.end()) {
    ec = make_error_code(protocol::error::protocol_error);
    return 0;
  }
  {
    reader r;
    std::unique_lock lock{r.mutex};
    stream->reader = &r;
    r.cond.wait(lock, [&r] { return r.result; });
    ec = *r.result;
    stream->reader = nullptr;
  }
  size_t count = 0;
  for (auto i = stream->buffers.begin(); i != stream->buffers.end(); ) {
    auto& buffer = *i;
    const size_t bytes = body.put(buffer.data(), ec);
    count += bytes;
  }
  // TODO: return buffers to the pool
  // TODO: adjust flow control window
  return count;
}

} // namespace nexus::http2::detail
