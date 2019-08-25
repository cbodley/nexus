#pragma once

#include <iterator>

#include <boost/icl/interval_set.hpp>

#include <nexus/quic/detail/frame.hpp>

namespace nexus::quic::detail {

// tracks packet ranges for acknowledgement and converts to/from ack frame ranges
template <typename T>
class ack_range_set {
  using static_interval_t = boost::icl::right_open_interval<T>; // [x,y)
  using set_t = boost::icl::interval_set<T, std::less, static_interval_t>;
  set_t intervals;

  template <typename U>
  static constexpr bool is_range_iterator_v = std::is_same_v<ack_range,
                   typename std::iterator_traits<U>::value_type>;
 public:
  bool empty() const {
    return intervals.empty();
  }

  // return the lower bound, or smallest element in the set
  T lower() const {
    return intervals.begin()->lower();
  }

  // return the upper bound, or one greater than the largest element in the set
  T upper() const {
    return intervals.rbegin()->upper();
  }

  // insert the ack range [value, value + count)
  void insert(T value, T count = 1) {
    intervals.insert({value, value + count});
  }

  // insert a range of ack ranges starting from the given lower bound
  template <typename InputIterator>
  auto insert(T lower, InputIterator begin, InputIterator end)
    -> std::enable_if_t<is_range_iterator_v<InputIterator>>
  {
    for (auto i = begin; i != end; ++i) {
      lower += i->gap;
      insert(lower, i->ack);
      lower += i->ack;
    }
  }

  // insert a range of ack ranges in reverse from the given upper bound
  template <typename InputIterator>
  auto insert_reverse(T upper, InputIterator begin, InputIterator end)
    -> std::enable_if_t<is_range_iterator_v<InputIterator>>
  {
    for (auto i = begin; i != end; ++i) {
      upper -= i->ack;
      insert(upper, i->ack);
      upper -= i->gap;
    }
  }

  // subtract the ack range [value, value + count)
  void subtract(T value, T count = 1) {
    intervals.subtract({value, value + count});
  }

  // subtract a range of ack ranges starting from the given lower bound
  template <typename InputIterator>
  auto subtract(T lower, InputIterator begin, InputIterator end)
    -> std::enable_if_t<is_range_iterator_v<InputIterator>>
  {
    for (auto i = begin; i != end; ++i) {
      lower += i->gap;
      subtract(lower, i->ack);
      lower += i->ack;
    }
  }

  // subtract a range of ack ranges in reverse from the given upper bound
  template <typename InputIterator>
  auto subtract_reverse(T upper, InputIterator begin, InputIterator end)
    -> std::enable_if_t<is_range_iterator_v<InputIterator>>
  {
    for (auto i = begin; i != end; ++i) {
      upper -= i->ack;
      subtract(upper, i->ack);
      upper -= i->gap;
    }
  }

  // const iterator that adapts the interval type to ack frame ranges
  class const_iterator {
    typename set_t::const_iterator pos;
    ack_range range = {};
    T last = 0;

    friend class ack_range_set<T>;
    const_iterator(typename set_t::const_iterator pos) : pos(pos) {}
   public:
    const_iterator() = default;

    using difference_type = std::ptrdiff_t;
    using value_type = ack_range;
    using pointer = const value_type*;
    using reference = const value_type&;
    using iterator_category = std::forward_iterator_tag;

    const_iterator& operator++() {
      last = pos->upper();
      ++pos;
      return *this;
    }
    const_iterator operator++(int) {
      const_iterator tmp = *this;
      ++*this;
      return tmp;
    }

    value_type operator*() {
      range.gap = pos->lower() - last;
      range.ack = pos->upper() - pos->lower();
      return range;
    }
    pointer operator->() {
      range.gap = pos->lower() - last;
      range.ack = pos->upper() - pos->lower();
      return &range;
    }

    friend bool operator==(const const_iterator& lhs, const const_iterator& rhs) {
      return lhs.pos == rhs.pos;
    }
    friend bool operator!=(const const_iterator& lhs, const const_iterator& rhs) {
      return lhs.pos != rhs.pos;
    }
  };

  const_iterator begin() { return intervals.begin(); }
  const_iterator begin() const { return intervals.begin(); }
  const_iterator cbegin() { return intervals.begin(); }
  const_iterator cbegin() const { return intervals.begin(); }

  const_iterator end() { return intervals.end(); }
  const_iterator end() const { return intervals.end(); }
  const_iterator cend() { return intervals.end(); }
  const_iterator cend() const { return intervals.end(); }
};

} // namespace nexus::quic::detail
