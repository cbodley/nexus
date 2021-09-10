#pragma once

#include <utility>
#include <unistd.h>

namespace nexus::quic::detail {

// auto-closing file descriptor
class file_descriptor {
  int fd = -1;
 public:
  file_descriptor() = default;
  file_descriptor(int fd) : fd(fd) {}
  file_descriptor(file_descriptor&& o) : fd(std::exchange(o.fd, -1)) {}
  file_descriptor& operator=(file_descriptor&& o) {
    close();
    fd = std::exchange(o.fd, -1);
    return *this;
  }
  ~file_descriptor() { close(); }

  bool is_open() const { return fd != -1; }
  int operator*() const { return fd; }

  void close() {
    if (!is_open()) {
      return;
    }
    int r;
    do {
      r = ::close(fd);
    } while (r == -1 && errno == EINTR);
    fd = -1;
  }
};

} // namespace nexus::quic::detail
