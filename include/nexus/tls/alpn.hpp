#pragma once

#include <iterator>
#include <string_view>

#include <boost/asio/ssl.hpp>

namespace nexus::tls {

// helpers for application layer protocol negotiation
namespace alpn {

// an immutable view into a length-prefixed protocol name
class protocol_view {
  std::string_view proto;
 public:
  protocol_view() = default;
  protocol_view(std::string_view proto) : proto(proto) {}
  protocol_view& operator=(std::string_view p) { proto = p; return *this; }
  std::string_view data() const { return proto; }
  std::string_view name() const { return proto.substr(1); }
  friend bool operator==(const protocol_view& lhs, const protocol_view& rhs);
  friend bool operator!=(const protocol_view& lhs, const protocol_view& rhs);
};
inline bool operator==(const protocol_view& lhs, const protocol_view& rhs)
{
  return lhs.proto == rhs.proto;
}
inline bool operator!=(const protocol_view& lhs, const protocol_view& rhs)
{
  return lhs.proto == rhs.proto;
}

// an immutable view of contiguous length-prefixed protocol names
class protocol_list_view {
  std::string_view protos;
 public:
  explicit protocol_list_view(const unsigned char* in, unsigned int inlen)
    : protos(reinterpret_cast<const char*>(in), inlen)
  {}
  protocol_list_view(std::string_view protos) : protos(protos) {}
  protocol_list_view(const std::string& protos) : protos(protos) {}

  std::string_view data() const { return protos; }

  class const_iterator {
    std::string_view protos;
    protocol_view proto;
    size_t size() const { return static_cast<size_t>(protos[0]); }
   public:
    using difference_type = std::ptrdiff_t;
    using value_type = protocol_view;
    using pointer = const value_type*;
    using reference = const value_type&;
    using iterator_category = std::forward_iterator_tag;
    const_iterator(std::string_view protos) : protos(protos) {}
    value_type operator*() { return protos.substr(0, 1 + size()); }
    pointer operator->() {
      proto = protos.substr(0, 1 + size());
      return &proto;
    }
    const_iterator& operator++() {
      protos.remove_prefix(1 + size());
      return *this;
    }
    const_iterator operator++(int) {
      std::string_view result = protos;
      protos.remove_prefix(1 + size());
      return {result};
    }
    friend bool operator==(const const_iterator& lhs, const const_iterator& rhs);
    friend bool operator!=(const const_iterator& lhs, const const_iterator& rhs);
  };
  using iterator = const_iterator;

  const_iterator begin() { return {protos}; }
  const_iterator begin() const { return {protos}; }
  const_iterator end() { return {protos.substr(protos.size(), 0)}; }
  const_iterator end() const { return {protos.substr(protos.size(), 0)}; }
};

inline bool operator==(const protocol_list_view::const_iterator& lhs,
                       const protocol_list_view::const_iterator& rhs)
{
  return lhs.protos.data() == rhs.protos.data()
      && lhs.protos.size() == rhs.protos.size();
}
inline bool operator!=(const protocol_list_view::const_iterator& lhs,
                       const protocol_list_view::const_iterator& rhs)
{
  return lhs.protos.data() != rhs.protos.data()
      || lhs.protos.size() != rhs.protos.size();
}

void append_protocol(std::string& protocols, std::string_view arg)
{
  protocols.append(1, static_cast<char>(arg.size()));
  protocols.append(arg);
}

template <typename ...Args>
void append_protocols(std::string& protocols, Args&& ...args)
{
  (append_protocol(protocols, std::forward<Args>(args)), ...);
}

template <typename ...Args>
std::string make_protocol_list(Args&& ...args)
{
  std::string protocols;
  protocols.reserve(sizeof...(Args) + (std::string_view(args).size() + ...));
  (append_protocol(protocols, std::forward<Args>(args)), ...);
  return protocols;
}

} // namespace alpn

inline void set_alpn_protos(boost::asio::ssl::context& ctx,
                            alpn::protocol_list_view protocols,
                            boost::system::error_code& ec)
{
  auto p = reinterpret_cast<const unsigned char*>(protocols.data().data());
  auto size = static_cast<unsigned int>(protocols.data().size());
  if (::SSL_CTX_set_alpn_protos(ctx.native_handle(), p, size) != 0) {
    ec = boost::system::error_code(static_cast<int>(::ERR_get_error()),
                                   boost::asio::error::get_ssl_category());
  }
}

template <typename Stream>
void set_alpn_protos(boost::asio::ssl::stream<Stream>& stream,
                     alpn::protocol_list_view protocols,
                     boost::system::error_code& ec)
{
  auto p = reinterpret_cast<const unsigned char*>(protocols.data().data());
  auto size = static_cast<unsigned int>(protocols.data().size());
  if (::SSL_set_alpn_protos(stream.native_handle(), p, size) != 0) {
    ec = boost::system::error_code(static_cast<int>(::ERR_get_error()),
                                   boost::asio::error::get_ssl_category());
  }
}

template <typename Stream>
std::string_view get_alpn_selected(boost::asio::ssl::stream<Stream>& stream)
{
  const unsigned char* protocol = nullptr;
  unsigned int protocol_len = 0;
  ::SSL_get0_alpn_selected(stream.native_handle(), &protocol, &protocol_len);
  if (protocol == nullptr || protocol_len == 0) {
    return {};
  }
  unsigned char len = *protocol++;
  if (len + 1u != protocol_len) {
    return {};
  }
  return {reinterpret_cast<const char*>(protocol), len};
}

namespace detail {
static int accept_protocols_cb([[maybe_unused]] SSL *ssl,
                               const unsigned char **out,
                               unsigned char *outlen,
                               const unsigned char *in,
                               unsigned int inlen,
                               void *arg)
{
  auto protos = alpn::protocol_list_view(*static_cast<const std::string*>(arg));
  auto best = protos.end();

  for (auto proto : alpn::protocol_list_view(in, inlen)) {
    auto i = std::find(protos.begin(), best, proto);
    if (best != i) {
      best = i;
      if (best == protos.begin()) {
        break;
      }
    }
  }
  if (best != protos.end()) {
    auto data = best->data();
    *out = reinterpret_cast<const unsigned char*>(data.data());
    *outlen = data.size();
    return SSL_TLSEXT_ERR_OK;
  }
  return SSL_TLSEXT_ERR_ALERT_FATAL;
}
} // namespace detail

inline void accept_protocols(boost::asio::ssl::context& ctx,
                             std::string& protocols)
{
  ::SSL_CTX_set_alpn_select_cb(ctx.native_handle(),
                               detail::accept_protocols_cb, &protocols);
}

inline void set_alpn_select_cb(boost::asio::ssl::context& ctx,
                               int (*cb)(SSL* ssl,
                                         const unsigned char** out,
                                         unsigned char* outlen,
                                         const unsigned char* in,
                                         unsigned int inlen,
                                         void* arg),
                               void* arg)
{
  ::SSL_CTX_set_alpn_select_cb(ctx.native_handle(), cb, arg);
}

} // namespace nexus::tls
