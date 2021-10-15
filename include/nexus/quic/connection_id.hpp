#pragma once

#include <algorithm>
#include <array>
#include <stdexcept>

namespace nexus::quic {

/// an opaque connection id string
class connection_id : public std::array<unsigned char, 20> {
  using base_type = std::array<unsigned char, 20>;
 public:
  /// default-construct an empty connection id
  constexpr connection_id() noexcept
      : base_type{}, size_(0)
  {}
  /// construct with a copy of the given array
  template <size_t Size>
  constexpr connection_id(const value_type (&data)[Size]) noexcept
      : base_type{}, size_(Size)
  {
    static_assert(Size <= max_size_);
    for (size_type i = 0; i < Size; i++) {
      (*this)[i] = data[i];
    }
  }
  /// construct with a copy of the given array
  template <size_t Size>
  constexpr connection_id(const std::array<value_type, Size>& data) noexcept
      : base_type{}, size_(Size)
  {
    static_assert(Size <= max_size_);
    for (size_type i = 0; i < Size; i++) {
      (*this)[i] = data[i];
    }
  }
  /// construct with a copy of the given string. throws std::length_error if
  /// size exceeds max_size()
  constexpr connection_id(const_pointer data, size_type size)
      : base_type{}, size_(size)
  {
    if (size > max_size_) {
      throw std::length_error("maximum connection id length (20) exceeded");
    }
    for (size_type i = 0; i < size; i++) {
      (*this)[i] = data[i];
    }
  }

  constexpr connection_id(const connection_id&) noexcept = default;
  constexpr connection_id& operator=(const connection_id&) noexcept = default;

  /// return true if empty
  constexpr bool empty() const noexcept { return size_ == 0; }
  /// return the size
  constexpr size_type size() const { return size_; }

  /// resize the connection id
  constexpr void resize(size_type size)
  {
    if (size > max_size_) {
      throw std::length_error("maximum connection id length (20) exceeded");
    }
    size_ = size;
  }

  /// return a reference to the element at the given position
  constexpr reference at(size_type p) {
    if (p >= size()) {
      throw std::out_of_range("array index out of range");
    }
    return (*this)[p];
  }

  /// return a reference to the last element
  constexpr reference back() { return *std::prev(end()); }
  constexpr const_reference back() const { return *std::prev(end()); }

  /// return an iterator past the end
  constexpr iterator end() { return std::next(begin(), size_); }
  /// \overload
  constexpr const_iterator end() const { return std::next(begin(), size_); }
  /// \overload
  constexpr const_iterator cend() const { return std::next(begin(), size_); }

  /// return a reverse iterator to the beginning
  constexpr reverse_iterator rbegin() {
    return std::next(base_type::rbegin(), max_size_ - size_);
  }
  /// \overload
  constexpr const_reverse_iterator rbegin() const {
    return std::next(base_type::rbegin(), max_size_ - size_);
  }
  /// \overload
  constexpr const_reverse_iterator crbegin() const {
    return std::next(base_type::rbegin(), max_size_ - size_);
  }

 private:
  static constexpr size_type max_size_ = 20;
  size_type size_;
};

inline bool operator==(const connection_id& l, const connection_id& r) noexcept
{
  return l.size() == r.size() && std::equal(l.begin(), l.end(), r.begin());
}
inline bool operator!=(const connection_id& l, const connection_id& r) noexcept
{
  return l.size() != r.size() || !std::equal(l.begin(), l.end(), r.begin());
}
inline bool operator<(const connection_id& l, const connection_id& r) noexcept
{
  return std::lexicographical_compare(l.begin(), l.end(), r.begin(), r.end());
}
inline bool operator>(const connection_id& l, const connection_id& r) noexcept
{
  return std::lexicographical_compare(r.begin(), r.end(), l.begin(), l.end());
}
inline bool operator<=(const connection_id& l, const connection_id& r) noexcept
{
  return !(l > r);
}
inline bool operator>=(const connection_id& l, const connection_id& r) noexcept
{
  return !(l < r);
}

inline void swap(connection_id& lhs, connection_id& rhs) noexcept
{
  auto tmp = lhs;
  lhs = std::move(rhs);
  rhs = std::move(tmp);
}

} // namespace nexus::quic
