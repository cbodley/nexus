#pragma once

#include <limits>
#include <memory>

#include <boost/beast/http/type_traits.hpp>
#include <boost/intrusive/list.hpp>
#include <boost/intrusive/set.hpp>
#include <boost/smart_ptr/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>

#include <nexus/http2/field.hpp>
#include <nexus/http2/detail/buffer.hpp>
#include <nexus/http2/hpack/static_table.hpp>

namespace nexus::http2 {

namespace detail {

namespace bi = boost::intrusive;

template <typename Allocator = std::allocator<char>>
class field_pair
    : public bi::list_base_hook<>,
      public bi::set_base_hook<bi::optimize_size<true>>,
      private Allocator
{
 public:
  using allocator_type = Allocator;
 private:
  using allocator_traits = std::allocator_traits<allocator_type>;
  using size_type = uint32_t;
  static constexpr size_type indexed_value = std::numeric_limits<size_type>::max();
  static constexpr size_type never_index_flag = 1 << (std::numeric_limits<size_type>::digits - 1);
  static constexpr size_type name_size_mask = never_index_flag - 1;

  using rebind_alloc = typename allocator_traits::template rebind_alloc<field_pair>;
  using rebind_traits = std::allocator_traits<rebind_alloc>;

  using byte_alloc = typename allocator_traits::template rebind_alloc<char>;
  using byte_traits = std::allocator_traits<byte_alloc>;

  const field static_field = field::unknown;
  size_type name_size = 0;
  const size_type value_size = 0;
  char storage[1];

  explicit field_pair(const allocator_type& alloc, field static_field,
                      size_type value_size) noexcept
    : Allocator(alloc), static_field(static_field), value_size(value_size)
  {}
  explicit field_pair(const allocator_type& alloc,
                      size_type name_size,
                      size_type value_size) noexcept
    : Allocator(alloc), name_size(name_size), value_size(value_size)
  {}
 public:
  allocator_type get_allocator() const { return *this; }

  field name() const {
    return static_field;
  }
  std::string_view name_string() const {
    if (static_field != field::unknown) {
      return field_name(static_field);
    }
    return {storage, name_size & name_size_mask};
  }
  std::string_view value() const {
    if (static_field != field::unknown && value_size == indexed_value) {
      const auto index = static_cast<size_t>(static_field);
      return hpack::static_table::table[index].value;
    }
    return {storage + (name_size & name_size_mask) + 1, value_size};
  }

  bool never_index() const { return name_size & never_index_flag; }
  void never_index(bool flag) {
    if (flag) {
      name_size |= never_index_flag;
    } else {
      name_size &= name_size_mask;
    }
  }

  static auto make(field static_field,
                   const allocator_type& alloc = allocator_type())
    -> std::unique_ptr<field_pair>
  {
    const size_t base_size = sizeof(field_pair) - sizeof(storage);
    const size_t size = base_size + sizeof('\0') + sizeof('\0');
    byte_alloc alloc1{alloc};
    auto p = byte_traits::allocate(alloc1, size);
    try {
      auto f = std::unique_ptr<field_pair>{
        new (p) field_pair(alloc, static_field, indexed_value)};
      auto c = f->storage;
      *c++ = '\0';
      *c = '\0';
      return f;
    } catch (const std::exception&) {
      byte_traits::deallocate(alloc1, p, size);
      throw;
    }
  }

  template <typename ConstBufferSequence>
  static auto make(field static_field, const ConstBufferSequence& value,
                   const allocator_type& alloc = allocator_type())
    -> std::enable_if_t<is_const_buffer_sequence_v<ConstBufferSequence>,
                        std::unique_ptr<field_pair>>
  {
    const size_type value_size = boost::asio::buffer_size(value);
    const size_t base_size = sizeof(field_pair) - sizeof(storage);
    const size_t size = base_size + sizeof('\0') + value_size + sizeof('\0');
    byte_alloc alloc1{alloc};
    auto p = byte_traits::allocate(alloc1, size);
    try {
      auto f = std::unique_ptr<field_pair>{
        new (p) field_pair(alloc, static_field, value_size)};
      auto c = f->storage;
      *c++ = '\0';
      c += boost::asio::buffer_copy(boost::asio::buffer(c, value_size), value);
      *c = '\0';
      return f;
    } catch (const std::exception&) {
      byte_traits::deallocate(alloc1, p, size);
      throw;
    }
  }

  template <typename ConstBufferSequence1, typename ConstBufferSequence2>
  static auto make(const ConstBufferSequence1& name,
                   const ConstBufferSequence2& value,
                   const allocator_type& alloc = allocator_type())
    -> std::enable_if_t<is_const_buffer_sequence_v<ConstBufferSequence1> &&
                        is_const_buffer_sequence_v<ConstBufferSequence2>,
                        std::unique_ptr<field_pair>>
  {
    const size_type name_size = boost::asio::buffer_size(name);
    const size_type value_size = boost::asio::buffer_size(value);
    const size_t base_size = sizeof(field_pair) - sizeof(storage);
    const size_t size = base_size + name_size + sizeof('\0')
                                  + value_size + sizeof('\0');

    byte_alloc alloc1{alloc};
    auto p = byte_traits::allocate(alloc1, size);
    try {
      auto f = std::unique_ptr<field_pair>{
        new (p) field_pair(alloc, name_size, value_size)};
      auto c = f->storage;
      c += boost::asio::buffer_copy(boost::asio::buffer(c, name_size), name);
      *c++ = '\0';
      c += boost::asio::buffer_copy(boost::asio::buffer(c, value_size), value);
      *c = '\0';
      return f;
    } catch (const std::exception&) {
      byte_traits::deallocate(alloc1, p, size);
      throw;
    }
  }

  static void operator delete(void *p) {
    auto f = static_cast<field_pair*>(p);
    const size_t base_size = sizeof(field_pair) - sizeof(storage);
    const size_t name_size = f->name_size & name_size_mask;
    const size_t size = base_size + name_size + sizeof('\0')
                                  + f->value_size + sizeof('\0');
    rebind_alloc alloc1{*f};
    rebind_traits::destroy(alloc1, f);
    byte_alloc alloc2{*f};
    byte_traits::deallocate(alloc2, reinterpret_cast<char*>(f), size);
  }
};

template <typename Allocator = std::allocator<char>>
auto make_field(field field, const Allocator& alloc = Allocator())
  -> std::enable_if_t<!is_const_buffer_sequence_v<Allocator>,
                      std::unique_ptr<field_pair<Allocator>>>
{
  return field_pair<Allocator>::make(field, alloc);
}

template <typename ConstBufferSequence,
          typename Allocator = std::allocator<char>>
auto make_field(field field, const ConstBufferSequence& value,
                const Allocator& alloc = Allocator())
  -> std::enable_if_t<is_const_buffer_sequence_v<ConstBufferSequence>,
                      std::unique_ptr<field_pair<Allocator>>>
{
  return field_pair<Allocator>::make(field, value, alloc);
}

template <typename ConstBufferSequence1,
          typename ConstBufferSequence2,
          typename Allocator = std::allocator<char>>
auto make_field(const ConstBufferSequence1& name,
                const ConstBufferSequence2& value,
                const Allocator& alloc = Allocator())
  -> std::enable_if_t<is_const_buffer_sequence_v<ConstBufferSequence1> &&
                      is_const_buffer_sequence_v<ConstBufferSequence2>,
                      std::unique_ptr<field_pair<Allocator>>>
{
  return field_pair<Allocator>::make(name, value, alloc);
}

struct name_iless : boost::beast::iless {
  template <typename Allocator1, typename Allocator2>
  constexpr bool operator()(const field_pair<Allocator1>& lhs,
                            const field_pair<Allocator2>& rhs) const {
    return operator()(lhs.name_string(), rhs.name_string());
  }
  template <typename Allocator>
  constexpr bool operator()(const field_pair<Allocator>& lhs,
                            std::string_view rhs) const {
    return operator()(lhs.name_string(), rhs);
  }
  template <typename Allocator>
  constexpr bool operator()(std::string_view lhs,
                            const field_pair<Allocator>& rhs) const {
    return operator()(lhs, rhs.name_string());
  }
  bool operator()(std::string_view lhs, std::string_view rhs) const {
    return iless::operator()({lhs.data(), lhs.size()},
                            {rhs.data(), rhs.size()});
  }
};

// function declarations only - just enough to satisfy beast::is_fields
struct mock_fields {
 protected:
  boost::beast::string_view get_method_impl() const;
  boost::beast::string_view get_target_impl() const;
  boost::beast::string_view get_reason_impl() const;
  bool get_chunked_impl() const;
  bool get_keep_alive_impl(unsigned version) const;
  bool has_content_length_impl() const;
  void set_method_impl(boost::beast::string_view s);
  void set_target_impl(boost::beast::string_view s);
  void set_reason_impl(boost::beast::string_view s);
  void set_chunked_impl(bool value);
  void set_content_length_impl(boost::optional<std::uint64_t>);
  void set_keep_alive_impl(unsigned version, bool keep_alive);
};

} // namespace detail

template <typename Allocator = std::allocator<char>>
class basic_fields : private Allocator, protected detail::mock_fields {
 public:
  using allocator_type = Allocator;
  using value_type = detail::field_pair<Allocator>;

 private:
  using list_type = boost::intrusive::list<value_type>;
  using compare_iless = boost::intrusive::compare<detail::name_iless>;
  using multiset_type = boost::intrusive::multiset<value_type, compare_iless>;
  list_type fields_by_age;
  multiset_type fields_by_name;

  struct writer;

 public:
  // for iterating fields in order of insertion
  using const_iterator = typename list_type::const_iterator;
  // for iterating fields in order of case-insensitive name
  using const_name_iterator = typename multiset_type::const_iterator;

  basic_fields(const allocator_type& alloc = allocator_type())
    : Allocator(alloc)
  {}
  ~basic_fields() {
    fields_by_name.clear();
    fields_by_age.clear_and_dispose(std::default_delete<value_type>{});
  }

  allocator_type get_allocator() const { return *this; }

  const_iterator begin() const { return fields_by_age.begin(); }
  const_iterator end() const { return fields_by_age.end(); }

  const_iterator find(field field) const {
    return find(field_name(field));
  }
  const_iterator find(std::string_view name) const {
    auto n = fields_by_name.find(name, detail::name_iless{});
    return fields_by_age.iterator_to(*n);
  }

  std::pair<const_name_iterator, const_name_iterator>
  equal_range(field field) const {
    return equal_range(field_name(field));
  }
  std::pair<const_name_iterator, const_name_iterator>
  equal_range(std::string_view name) const {
    return fields_by_name.equal_range(name, detail::name_iless{});
  }

  template <typename ConstBufferSequence>
  auto insert(field field, const ConstBufferSequence& value)
    -> std::enable_if_t<detail::is_const_buffer_sequence_v<ConstBufferSequence>,
                        const_iterator>
  {
    auto f = value_type::make(field, value, get_allocator());
    auto a = fields_by_age.insert(fields_by_age.end(), *f);
    fields_by_name.insert(*f);
    f.release();
    return a;
  }
  const_iterator insert(field field)
  {
    auto f = value_type::make(field, get_allocator());
    auto a = fields_by_age.insert(fields_by_age.end(), *f);
    fields_by_name.insert(*f);
    f.release();
    return a;
  }
  const_iterator insert(field field, std::string_view value)
  {
    return insert(field, boost::asio::buffer(value.data(), value.size()));
  }
  template <typename ConstBufferSequence1,
            typename ConstBufferSequence2>
  auto insert(const ConstBufferSequence1& name,
              const ConstBufferSequence2& value)
    -> std::enable_if_t<detail::is_const_buffer_sequence_v<ConstBufferSequence2> &&
                        detail::is_const_buffer_sequence_v<ConstBufferSequence2>,
                        const_iterator>
  {
    auto f = value_type::make(name, value, get_allocator());
    auto a = fields_by_age.insert(fields_by_age.end(), *f);
    fields_by_name.insert(*f);
    f.release();
    return a;
  }
  const_iterator insert(std::string_view name, std::string_view value)
  {
    return insert(boost::asio::buffer(name.data(), name.size()),
                  boost::asio::buffer(value.data(), value.size()));
  }
  // TODO: insert(std::unique_ptr<value_type>)
  // TODO: insert(iterator, iterator)

  // TODO: assign(iterator, iterator)

  const_iterator erase(const_iterator f)
  {
    auto a = fields_by_age.iterator_to(*f);
    auto n = fields_by_name.iterator_to(*f);
    auto result = fields_by_age.erase(a);
    fields_by_name.erase_and_dispose(n, std::default_delete<value_type>{});
    return result;
  }
  const_name_iterator erase(const_name_iterator f)
  {
    auto a = fields_by_age.iterator_to(*f);
    auto n = fields_by_name.iterator_to(*f);
    auto result = fields_by_name.erase(n);
    fields_by_age.erase_and_dispose(a, std::default_delete<value_type>{});
    return result;
  }
};

} // namespace nexus::http2
