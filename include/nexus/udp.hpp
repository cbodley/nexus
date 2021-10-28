#pragma once

#include <boost/asio/ip/udp.hpp>

#include <nexus/error_code.hpp>

namespace nexus {

using boost::asio::ip::udp;

namespace detail {

template <int Name4, int Name6>
class socket_option {
  int value;
 public:
  constexpr socket_option(bool b) : value(b ? 1 : 0) {}

  constexpr operator bool() const { return value; }

  template <typename Protocol>
  constexpr int level(const Protocol& proto) const {
    return proto.family() == PF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP;
  }
  template <typename Protocol>
  constexpr int name(const Protocol& proto) const {
    return proto.family() == PF_INET6 ? Name6 : Name4;
  }
  template <typename Protocol>
  constexpr size_t size(const Protocol&) const {
    return sizeof(value);
  }
  template <typename Protocol>
  constexpr void* data(const Protocol&) {
    return &value;
  }
  template <typename Protocol>
  constexpr const void* data(const Protocol&) const {
    return &value;
  }
  template <typename Protocol>
  constexpr void resize(Protocol&, std::size_t) {}
};

template <typename Socket, typename Option>
error_code set_option(Socket& sock, Option&& option) {
  error_code ec;
  sock.set_option(option, ec);
  return ec;
}

template <typename Socket, typename ...Options>
error_code set_options(Socket& sock, Options&& ...options) {
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

} // namespace nexus
