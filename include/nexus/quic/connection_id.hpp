#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <stdexcept>

namespace nexus::quic {

/// an opaque connection id string
class connection_id {
 public:
  using value_type = unsigned char;
  using size_type = std::uint_fast8_t;
  using difference_type = std::ptrdiff_t;
  using reference = value_type&;
  using const_reference = const value_type&;
  using pointer = value_type*;
  using const_pointer = const value_type*;
  using iterator = pointer;
  using const_iterator = const_pointer;
  using reverse_iterator = std::reverse_iterator<iterator>;
  using const_reverse_iterator = std::reverse_iterator<const_iterator>;

  /// default-construct an empty connection id
  constexpr connection_id() noexcept
      : data_{}, size_(0)
  {}
  /// construct with a copy of the given array
  template <size_t Size>
  constexpr connection_id(const value_type (&data)[Size]) noexcept
      : data_{}, size_(Size)
  {
    static_assert(Size <= max_size_);
    for (size_type i = 0; i < Size; i++) {
      data_[i] = data[i];
    }
  }
  /// construct with a copy of the given array
  template <size_t Size>
  constexpr connection_id(const std::array<value_type, Size>& data) noexcept
      : data_{}, size_(Size)
  {
    static_assert(Size <= max_size_);
    for (size_type i = 0; i < Size; i++) {
      data_[i] = data[i];
    }
  }
  /// construct with a copy of the given string. throws std::length_error if
  /// size exceeds max_size()
  constexpr connection_id(const_pointer data, size_type size)
      : data_{}, size_(size)
  {
    if (size > max_size_) {
      throw std::length_error("maximum connection id length (20) exceeded");
    }
    for (size_type i = 0; i < size; i++) {
      data_[i] = data[i];
    }
  }

  /// construct with a copy of the given connection id
  constexpr connection_id(const connection_id&) noexcept = default;
  /// overwrite with a copy of the given connection id
  constexpr connection_id& operator=(const connection_id&) noexcept = default;

  /// return true if empty
  constexpr bool empty() const noexcept { return size_ == 0; }
  /// return the size
  constexpr size_type size() const { return size_; }
  /// return the maximum size
  constexpr static size_type max_size() { return max_size_; }

  /// resize the connection id
  constexpr void resize(size_type size)
  {
    if (size > max_size_) {
      throw std::length_error("maximum connection id length (20) exceeded");
    }
    size_ = size;
  }

  /// return a reference to the element at the given position. throws
  /// std::out_of_range for invalid positions
  constexpr reference at(size_type p)
  {
    if (p >= size()) {
      throw std::out_of_range("array index out of range");
    }
    return data_[p];
  }
  /// \overload
  constexpr const_reference at(size_type p) const
  {
    if (p >= size()) {
      throw std::out_of_range("array index out of range");
    }
    return data_[p];
  }

  /// return a reference to the element at the given position without
  /// bounds checking
  constexpr reference operator[](size_type p) { return data_[p]; }
  /// \overload
  constexpr const_reference operator[](size_type p) const { return data_[p]; }

  /// return a reference to the first element
  constexpr reference front() { return data_.front(); }
  /// \overload
  constexpr const_reference front() const { return data_.front(); }

  /// return a reference to the last element
  constexpr reference back() { return *std::prev(end()); }
  /// \overload
  constexpr const_reference back() const { return *std::prev(end()); }

  /// return a pointer to the underlying bytes
  constexpr pointer data() { return data_.data(); }
  /// \overload
  constexpr const_pointer data() const { return data_.data(); }

  /// return an iterator to the beginning
  constexpr iterator begin() { return data_.begin(); }
  /// \overload
  constexpr const_iterator begin() const { return data_.begin(); }
  /// \overload
  constexpr const_iterator cbegin() const { return data_.cbegin(); }

  /// return an iterator past the end
  constexpr iterator end() { return std::next(begin(), size_); }
  /// \overload
  constexpr const_iterator end() const { return std::next(begin(), size_); }
  /// \overload
  constexpr const_iterator cend() const { return std::next(begin(), size_); }

  /// return a reverse iterator to the beginning
  constexpr reverse_iterator rbegin() {
    return std::next(data_.rbegin(), max_size_ - size_);
  }
  /// \overload
  constexpr const_reverse_iterator rbegin() const {
    return std::next(data_.rbegin(), max_size_ - size_);
  }
  /// \overload
  constexpr const_reverse_iterator crbegin() const {
    return std::next(data_.rbegin(), max_size_ - size_);
  }

  /// return a reverse iterator to the endning
  constexpr reverse_iterator rend() { return data_.rend(); }
  /// \overload
  constexpr const_reverse_iterator rend() const { return data_.rend(); }
  /// \overload
  constexpr const_reverse_iterator crend() const { return data_.crend(); }

 private:
  static constexpr size_type max_size_ = 20;
  using array_type = std::array<value_type, max_size_>;
  array_type data_;
  size_type size_;
};

/// equality comparison for connection_ids
/// \relates connection_id
inline bool operator==(const connection_id& l, const connection_id& r) noexcept
{
  return l.size() == r.size() && std::equal(l.begin(), l.end(), r.begin());
}
/// inequality comparison for connection_ids
/// \relates connection_id
inline bool operator!=(const connection_id& l, const connection_id& r) noexcept
{
  return l.size() != r.size() || !std::equal(l.begin(), l.end(), r.begin());
}
/// less-than comparison for connection_ids
/// \relates connection_id
inline bool operator<(const connection_id& l, const connection_id& r) noexcept
{
  return std::lexicographical_compare(l.begin(), l.end(), r.begin(), r.end());
}
/// greater-than comparison for connection_ids
/// \relates connection_id
inline bool operator>(const connection_id& l, const connection_id& r) noexcept
{
  return std::lexicographical_compare(r.begin(), r.end(), l.begin(), l.end());
}
/// less-than-or-equal comparison for connection_ids
/// \relates connection_id
inline bool operator<=(const connection_id& l, const connection_id& r) noexcept
{
  return !(l > r);
}
/// greater-than-or-equal comparison for connection_ids
/// \relates connection_id
inline bool operator>=(const connection_id& l, const connection_id& r) noexcept
{
  return !(l < r);
}

/// swap two connection_ids
/// \relates connection_id
inline void swap(connection_id& lhs, connection_id& rhs) noexcept
{
  auto tmp = lhs;
  lhs = std::move(rhs);
  rhs = std::move(tmp);
}

} // namespace nexus::quic
