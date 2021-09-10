#pragma once

#include <cctype>
#include <memory>
#include <string_view>

#include <boost/intrusive/set.hpp>
#include <boost/intrusive/list.hpp>

namespace nexus::quic::http3 {

// controls how each header is cached by header compression
enum class should_index : uint8_t {
  yes = 0,   // LSHPACK_ADD_INDEX
  no = 1,    // LSHPACK_NO_INDEX
  never = 2, // LSHPACK_NEVER_INDEX
  value = 3, // LSHPACK_VAL_INDEX
};

// a key/value pair to represent a single header
class field : public boost::intrusive::list_base_hook<>,
              public boost::intrusive::set_base_hook<>
{
  using size_type = uint16_t;
  size_type name_size;
  size_type value_size;
  should_index index_;
  char buffer[3]; // accounts for delimiter and null terminator

  static constexpr auto delim = std::string_view{": "};

  field(std::string_view name, std::string_view value, should_index index)
      : name_size(name.size()), value_size(value.size()), index_(index) {
    auto pos = std::copy(name.begin(), name.end(), buffer);
    pos = std::copy(delim.begin(), delim.end(), pos);
    pos = std::copy(value.begin(), value.end(), pos);
    *pos = '\0';
  }
 public:
  field(const field&) = delete;
  field& operator=(const field&) = delete;

  std::string_view name() const {
    return {buffer, name_size};
  }
  std::string_view value() const {
    return {buffer + name_size + delim.size(), value_size};
  }
  should_index index() const { return index_; }

  const char* c_str() const { return buffer; }
  const char* data() const { return buffer; }
  size_type size() const { return name_size + delim.size() + value_size; }

  struct deleter {
    void operator()(field* f) {
      const size_t size = sizeof(field) + f->name_size + f->value_size;
      using Alloc = std::allocator<char>;
      using Traits = std::allocator_traits<Alloc>;
      auto alloc = Alloc{};
      Traits::destroy(alloc, f);
      Traits::deallocate(alloc, reinterpret_cast<char*>(f), size);
    }
  };
  using ptr = std::unique_ptr<field, deleter>;

  static ptr create(std::string_view name, std::string_view value,
                    should_index index)
  {
    const size_t size = sizeof(field) + name.size() + value.size();
    using Alloc = std::allocator<char>;
    using Traits = std::allocator_traits<Alloc>;
    auto alloc = Alloc{};
    auto p = Traits::allocate(alloc, size);
    try {
      return ptr{new (p) field(name, value, index)};
    } catch (const std::exception&) {
      Traits::deallocate(alloc, p, size);
      throw;
    }
  }
};

namespace detail {

// case-insensitive field comparison for sorting in multiset
struct field_compare {
  bool operator()(char lhs, char rhs) const {
    return std::tolower(lhs) < std::tolower(rhs);
  }
  bool operator()(std::string_view lhs, std::string_view rhs) const {
    return std::lexicographical_compare(lhs.begin(), lhs.end(),
                                        rhs.begin(), rhs.end(), *this);
  }
  bool operator()(const field& lhs, const field& rhs) const {
    return (*this)(lhs.name(), rhs.name());
  }
  bool operator()(std::string_view lhs, const field& rhs) const {
    return (*this)(lhs, rhs.name());
  }
  bool operator()(const field& lhs, std::string_view rhs) const {
    return (*this)(lhs.name(), rhs);
  }
};

struct field_key {
  using type = std::string_view;
  type operator()(const field& f) { return f.name(); }
};

using field_multiset = boost::intrusive::multiset<field,
      boost::intrusive::compare<field_compare>,
      boost::intrusive::key_of_value<field_key>>;

using field_list = boost::intrusive::list<field,
      boost::intrusive::constant_time_size<true>,
      boost::intrusive::cache_last<true>,
      boost::intrusive::size_type<uint16_t>>;

} // namespace detail

// an ordered list of headers for an http request or response
class fields {
  using list_type = detail::field_list;
  list_type list;
  using multiset_type = detail::field_multiset;
  multiset_type set;
 public:
  fields() = default;
  fields(fields&& o) = default;
  fields& operator=(fields&& o) {
    clear();
    list = std::move(o.list);
    set = std::move(o.set);
    return *this;
  }
  ~fields() { clear(); }

  using size_type = list_type::size_type;
  size_type size() const { return list.size(); }

  bool empty() const { return list.empty(); }

  using const_iterator = list_type::const_iterator;
  using iterator = const_iterator;

  const_iterator begin() const { return list.begin(); }
  const_iterator cbegin() const { return list.cbegin(); }

  const_iterator end() const { return list.end(); }
  const_iterator cend() const { return list.cend(); }

  size_type count(std::string_view name) const {
    return set.count(name);
  }

  const_iterator find(std::string_view name) const {
    if (auto i = set.find(name); i != set.end()) {
      return list.iterator_to(*i);
    }
    return list.end();
  }

  auto equal_range(std::string_view name) const
      -> std::pair<const_iterator, const_iterator>
  {
    auto lower = set.lower_bound(name);
    if (lower == set.end()) {
      return {list.end(), list.end()};
    }
    auto upper = set.upper_bound(name);
    auto list_upper = std::next(list.iterator_to(*std::prev(upper)));
    return {list.iterator_to(*lower), list_upper};
  }

  iterator insert(std::string_view name, std::string_view value,
                  should_index index = should_index::yes)
  {
    auto ptr = field::create(name, value, index);

    auto lower = set.lower_bound(name);
    if (lower == set.end()) {
      set.insert(set.end(), *ptr);
      return list.insert(list.end(), *ptr.release());
    }
    auto upper = set.upper_bound(name);
    auto list_upper = std::next(list.iterator_to(*std::prev(upper)));
    set.insert(upper, *ptr);
    return list.insert(list_upper, *ptr.release());
  }

  iterator assign(std::string_view name, std::string_view value,
                  should_index index = should_index::yes)
  {
    auto ptr = field::create(name, value, index);

    auto lower = set.lower_bound(name);
    if (lower == set.end()) {
      set.insert(set.end(), *ptr);
      return list.insert(list.end(), *ptr.release());
    }
    auto upper = set.upper_bound(name);
    auto list_lower = list.iterator_to(*lower);
    auto list_upper = std::next(list.iterator_to(*std::prev(upper)));
    set.erase(lower, upper);
    list.erase_and_dispose(list_lower, list_upper, field::deleter{});

    set.insert(set.end(), *ptr);
    return list.insert(list.end(), *ptr.release());
  }

  iterator erase(iterator p) {
    set.erase(set.iterator_to(*p));
    return list.erase_and_dispose(p, field::deleter{});
  }

  iterator erase(iterator begin, iterator end) {
    set.erase(set.iterator_to(*begin),
              std::next(set.iterator_to(*std::prev(end))));
    return list.erase_and_dispose(begin, end, field::deleter{});
  }

  void clear() {
    set.clear();
    list.clear_and_dispose(field::deleter{});
  }
};

} // namespace nexus::quic::http3
