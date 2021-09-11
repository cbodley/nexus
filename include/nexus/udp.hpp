#pragma once

#include <asio.hpp>
#include <nexus/error_code.hpp>

namespace nexus::udp {

using endpoint = asio::ip::udp::endpoint;
using socket = asio::ip::udp::socket;

namespace detail {

template <int Name4, int Name6>
class socket_option {
  int value;
 public:
  constexpr socket_option(bool b) : value(b ? 1 : 0) {}

  constexpr operator bool() const { return value; }

  constexpr int level(const asio::ip::udp& proto) const {
    return proto.family() == PF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP;
  }
  constexpr int name(const asio::ip::udp& proto) const {
    return proto.family() == PF_INET6 ? Name6 : Name4;
  }
  constexpr size_t size(const asio::ip::udp&) const {
    return sizeof(value);
  }
  constexpr void* data(const asio::ip::udp&) {
    return &value;
  }
  constexpr const void* data(const asio::ip::udp&) const {
    return &value;
  }
  constexpr void resize(asio::ip::udp&, std::size_t) {}
};

template <typename Option>
error_code set_option(socket& sock, Option&& option) {
  error_code ec;
  sock.set_option(option, ec);
  return ec;
}

template <typename ...Options>
error_code set_options(socket& sock, Options&& ...options) {
  error_code ec;
  // fold expression calls set_option() on each until one returns an error
  ((ec = set_option(sock, options)) || ...);
  return ec;
}

} // namespace detail

using receive_ecn = detail::socket_option<IP_RECVTOS, IPV6_RECVTCLASS>;

#ifdef IP_RECVORIGDSTADDR
using receive_dstaddr = detail::socket_option<IP_RECVORIGDSTADDR, IPV6_RECVPKTINFO>;
#else
using receive_dstaddr = detail::socket_option<IP_PKTINFO, IPV6_RECVPKTINFO>;
#endif

} // namespace nexus::udp
