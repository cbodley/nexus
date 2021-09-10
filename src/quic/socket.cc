#include <nexus/quic/detail/socket.hpp>
#include <array>
#include <cstring>

#include <netdb.h>
#include <lsquic.h>

namespace nexus::quic::detail {

file_descriptor bind_udp_socket(const addrinfo* info, bool server,
                                sockaddr_union& addr, error_code& ec)
{
  // open the socket in non-blocking mode
  const int socket_flags = SOCK_NONBLOCK | SOCK_CLOEXEC;
  const int fd = ::socket(info->ai_family,
                          info->ai_socktype + socket_flags,
                          info->ai_protocol);
  if (fd == -1) {
    ec.assign(errno, system_category());
    ::perror("socket");
    return -1;
  }

  // enable SO_REUSEADDR
  const int on = 1;
  int r = ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  if (r == -1) {
    ec.assign(errno, system_category());
    ::perror("setsockopt SO_REUSEADDR");
    ::close(fd);
    return -1;
  }
  // enable ECN
  if (info->ai_family == AF_INET) {
    r = ::setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &on, sizeof(on));
  } else {
    r = ::setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof(on));
  }
  if (r == -1) {
    ec.assign(errno, system_category());
    ::perror("setsockopt ECN");
    ::close(fd);
    return -1;
  }
  // enable DSTADDR for server sockets
  if (server) {
    if (info->ai_family == AF_INET) {
#ifdef IP_RECVORIGDSTADDR
      const int option = IP_RECVORIGDSTADDR;
#else
      const int option = IP_PKTINFO;
#endif
      r = ::setsockopt(fd, IPPROTO_IP, option, &on, sizeof(on));
    } else {
      r = ::setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
    }
    if (r == -1) {
      ec.assign(errno, system_category());
      ::perror("setsockopt DSTADDR");
      ::close(fd);
      return -1;
    }
  }

  // bind the socket
  r = ::bind(fd, info->ai_addr, info->ai_addrlen);
  if (r == -1) {
    ec.assign(errno, system_category());
    ::perror("bind");
    ::close(fd);
    return -1;
  }

  // read the bound address
  socklen_t addrlen = sizeof(addr);
  r = ::getsockname(fd, &addr.addr, &addrlen);
  if (r == -1) {
    ec.assign(errno, system_category());
    ::perror("getsockname");
    ::close(fd);
    return -1;
  }

  return fd;
}

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

} // namespace nexus::quic::detail
