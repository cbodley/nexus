#include <nexus/quic/socket.hpp>
#include <nexus/quic/detail/socket.hpp>
#include <array>
#include <cstring>

//#include <netdb.h>
#include <lsquic.h>

namespace nexus::quic {

void prepare_socket(udp::socket& sock, bool is_server, error_code& ec)
{
  if (sock.non_blocking(true, ec); ec) {
    return;
  }
  if (sock.set_option(udp::receive_ecn{true}, ec); ec) {
    return;
  }
  if (is_server) {
    ec = udp::detail::set_options(sock, udp::receive_dstaddr{true},
                                  udp::socket::reuse_address{true});
  }
}

namespace detail {

int send_udp_packets(int fd, const lsquic_out_spec* specs, unsigned n_specs)
{
  int num_sent = 0;

  msghdr msg;
  msg.msg_flags = 0;

  for (auto spec = specs; spec < specs + n_specs; ++spec) {
    msg.msg_name = (void*) spec->dest_sa;
    if (spec->dest_sa->sa_family == AF_INET) {
      msg.msg_namelen = sizeof(struct sockaddr_in);
    } else {
      msg.msg_namelen = sizeof(struct sockaddr_in6);
    }

    msg.msg_iov = spec->iov;
    msg.msg_iovlen = spec->iovlen;

    constexpr size_t ecn_size = sizeof(int); // TODO: add DSTADDR
    constexpr size_t max_control_size = CMSG_SPACE(ecn_size);
    auto control = std::array<unsigned char, max_control_size>{};
    if (spec->ecn) {
      msg.msg_control = control.data();
      msg.msg_controllen = control.size();

      cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
      if (spec->dest_sa->sa_family == AF_INET) {
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_PKTINFO;
      } else {
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_TCLASS;
      }
      cmsg->cmsg_len = CMSG_LEN(ecn_size);
      ::memcpy(CMSG_DATA(cmsg), &spec->ecn, ecn_size);
      msg.msg_controllen = CMSG_SPACE(ecn_size);
    } else {
      msg.msg_controllen = 0;
      msg.msg_control = nullptr;
    }

    if (::sendmsg(fd, &msg, 0) == -1) {
      break;
    }
    ++num_sent;
  }
  return num_sent > 0 ? num_sent : -1;
}

} // namespace detail
} // namespace nexus::quic
