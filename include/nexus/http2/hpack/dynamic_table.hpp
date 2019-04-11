#pragma once

#include <deque>
#include <optional>
#include <string>
#include <vector>

namespace nexus::http2::hpack {

template <typename SizeType = uint32_t,
          SizeType entry_size_overhead = 32,
          typename Allocator = std::allocator<char>>
class basic_dynamic_table {
  using size_type = SizeType;
  using allocator_type = Allocator;

  std::vector<char, allocator_type> storage;

  struct segment { size_type offset; size_type length; };
  struct entry { segment name, value; };
  using entry_allocator = typename std::allocator_traits<allocator_type>::
      template rebind_alloc<entry>;
  std::deque<entry, entry_allocator> entries;

  size_type size;
  size_type free;
  size_type pos = 0;

  void read(std::string& dst, const segment& src, char* end) {
    dst.resize(src.length);
    char* data = storage.data() + src.offset;
    const size_t remaining = std::distance(data, end);
    if (src.length <= remaining) {
      dst.assign(data, src.length);
    } else {
      dst.assign(data, remaining); // wrap at end
      dst.append(storage.data(), src.length - remaining);
    }
  }
  void write(segment& dst, std::string_view src, char* end) {
    dst.offset = pos;
    dst.length = src.size();
    char* data = storage.data() + dst.offset;
    const size_t remaining = std::distance(data, end);
    if (dst.length <= remaining) {
      pos += src.copy(data, dst.length);
    } else {
      src.copy(data, remaining); // wrap at end
      pos = src.copy(storage.data(), dst.length - remaining, remaining);
    }
  }
  bool equals(std::string_view lhs, const segment& rhs, const char* end) const {
    if (lhs.size() != rhs.length) {
      return false;
    }
    const char* data = storage.data() + rhs.offset;
    const size_t remaining = std::distance(data, end);
    if (rhs.length <= remaining) {
      return lhs.compare(0, rhs.length, data) == 0;
    }
    return lhs.compare(0, remaining, data) == 0
        && lhs.compare(0, rhs.length - remaining, storage.data()) == 0;
  }

 public:
  basic_dynamic_table(size_t max_size, allocator_type alloc = allocator_type())
    : storage(max_size, alloc),
      entries(alloc),
      size(max_size),
      free(max_size)
  {}

  size_t max_size() const { return size; }
  void set_size(size_t new_size) {
    while (size > free + new_size) {
      auto& e = entries.back();
      free += e.name.length + e.value.length + entry_size_overhead;
      entries.pop_back();
    }
    size = std::min(new_size, storage.size());
  }

  bool lookup(uint32_t index, std::string* name, std::string* value) {
    if (index >= entries.size()) {
      return false;
    }
    auto& e = entries[index];
    const auto end = storage.data() + storage.size();
    if (name) {
      read(*name, e.name, end);
    }
    if (value) {
      read(*value, e.value, end);
    }
    return true;
  }
  bool insert(std::string_view name, std::string_view value) {
    size_t esize = name.size() + value.size() + entry_size_overhead;
    if (esize > size) {
      free = size;
      entries.clear();
      return false;
    }
    while (free < esize) {
      auto& e = entries.back();
      free += e.name.length + e.value.length + entry_size_overhead;
      entries.pop_back();
    }
    free -= esize;

    entries.emplace_front();
    auto& e = entries.front();
    const auto end = storage.data() + storage.size();
    write(e.name, name, end);
    write(e.value, value, end);
    return true;
  }

  std::optional<uint32_t> search(std::string_view name,
                                 std::string_view value,
                                 bool& has_value) {
    const auto end = storage.data() + storage.size();
    std::optional<uint32_t> index;
    for (uint32_t i = 0; i < entries.size(); i++) {
      const auto& e = entries[i];
      if (equals(name, e.name, end)) {
        if (equals(value, e.value, end)) {
          index = i;
          has_value = true;
          break;
        }
        if (!index) {
          index = i;
        }
      }
    }
    return index;
  }
};

using dynamic_table = basic_dynamic_table<>;

} // namespace nexus::http2::hpack
