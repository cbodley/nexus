#pragma once

#include <memory>

#include <boost/intrusive/list.hpp>

#include <boost/beast/core/flat_static_buffer.hpp>

namespace nexus::http2::detail {

class stream_buffer : // TODO: custom Allocator support
    public boost::beast::flat_static_buffer_base,
    public boost::intrusive::list_base_hook<>
{
  char storage[1];
  stream_buffer(size_t n) : flat_static_buffer_base(&storage, n) {}
 public:
  static std::unique_ptr<stream_buffer> make(size_t n) {
    size_t size = sizeof(stream_buffer) + n - sizeof(storage);
    auto p = new char[size];
    return std::unique_ptr<stream_buffer>{new (p) stream_buffer(n)};
  }
  static void operator delete(void *p) {
    auto buffer = static_cast<stream_buffer*>(p);
    buffer->~stream_buffer();
    delete[] static_cast<char*>(p);
  }
};

inline auto make_stream_buffer(size_t n) { return stream_buffer::make(n); }

class stream_buffer_pool { // TODO: custom Allocator support
  size_t buffer_size;
  size_t max_buffers;
  size_t outstanding = 0;
  boost::intrusive::list<stream_buffer> buffers;
 public:
  stream_buffer_pool(size_t buffer_size, size_t max_buffers)
    : buffer_size(buffer_size), max_buffers(max_buffers) {}
  ~stream_buffer_pool() {
    clear();
  }

  std::unique_ptr<stream_buffer> get() {
    auto i = buffers.begin();
    if (i == buffers.end()) {
      if (outstanding >= max_buffers) { // TODO: test get() after 
        return {};
      }
      outstanding++;
      return make_stream_buffer(buffer_size);
    }
    outstanding++;
    auto buffer = std::unique_ptr<stream_buffer>{&*i};
    buffers.erase(i);
    return buffer;
  }
  void put(std::unique_ptr<stream_buffer>&& buffer) {
    outstanding--;
    if (buffer->max_size() == buffer_size &&
        buffers.size() < max_buffers) {
      buffers.push_back(*buffer.release());
    }
  }
  void clear() {
    buffers.clear_and_dispose(std::default_delete<stream_buffer>{});
  }

  void set_buffer_size(size_t new_buffer_size) {
    if (buffer_size == new_buffer_size) {
      return;
    }
    buffer_size = new_buffer_size;
    clear();
  }
  void set_max_buffers(size_t new_max_buffers) {
    max_buffers = new_max_buffers;
    while (max_buffers < buffers.size()) {
      buffers.pop_front_and_dispose(std::default_delete<stream_buffer>{});
    }
  }
};

} // namespace nexus::http2::detail
