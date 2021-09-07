#include <iostream>
#include <netinet/ip.h>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <nexus/quic/detail/engine.hpp>

namespace nexus {
namespace quic::detail {

engine_state::engine_state(const boost::asio::executor& ex)
  : socket(ex, udp::endpoint{}), // open and bind the socket
    local_endpoint(this->socket.local_endpoint()), // save bound address
    timer(this->socket.get_executor())
{
  socket.non_blocking(true);
}

engine_state::~engine_state()
{
  std::cerr << "~engine_state" << std::endl;
  close();
}

static void set_socket_option(udp::socket& socket, int level, int option,
                              const void* value, socklen_t len, error_code& ec)
{
  if (::setsockopt(socket.native_handle(), level, option, value, len) == -1) {
    ec.assign(errno, system_category());
  }
}

void engine_state::enable_tos(error_code& ec) {
  const int on = 1;
  if (local_endpoint.address().is_v4()) {
    set_socket_option(socket, IPPROTO_IP, IP_RECVTOS,
                      &on, sizeof(on), ec);
  } else {
    set_socket_option(socket, IPPROTO_IPV6, IPV6_RECVTCLASS,
                      &on, sizeof(on), ec);
  }
}

void engine_state::enable_dstaddr(error_code& ec) {
  const int on = 1;
  if (local_endpoint.address().is_v4()) {
#ifdef IP_RECVORIGDSTADDR
    const int option = IP_RECVORIGDSTADDR;
#else
    const int option = IP_PKTINFO;
#endif
    set_socket_option(socket, IPPROTO_IP, option, &on, sizeof(on), ec);
  } else {
    set_socket_option(socket, IPPROTO_IPV6, IPV6_RECVPKTINFO,
                      &on, sizeof(on), ec);
  }
}

void engine_state::close() {
  lsquic_engine_cooldown(handle.get());
  timer.cancel();
  socket.close();
}

void engine_state::process() {
  std::cerr << "client process " << this << std::endl;
  lsquic_engine_process_conns(handle.get());
  reschedule();
}

void engine_state::reschedule() {
  int micros = 0;
  if (!lsquic_engine_earliest_adv_tick(handle.get(), &micros)) {
    std::cerr << "client reschedule, nothing to do" << std::endl;
    return;
  }
  std::cerr << "client reschedule in " << micros << "us" << std::endl;
  if (micros <= 0) {
    auto ex = timer.get_executor();
    boost::asio::dispatch(bind_executor(ex, [self=self()] {
          self->process();
        }));
  } else {
    timer.expires_after(std::chrono::microseconds(micros));
    timer.async_wait([self=self()] (error_code ec) {
          if (ec == error_code{}) {
            self->process();
          }
        });
  }
}

void engine_state::recv() {
  socket.async_wait(udp::socket::wait_read,
      [self=self()] (error_code ec) {
        self->on_recv_ready(ec);
      });
}

void engine_state::on_recv_ready(error_code ec) {
  if (ec) {
    std::cerr << "engine_state async_wait failed: " << ec << std::endl;
    return;
  }
  auto msg = msghdr{};

  union sockaddr_union {
    sockaddr_storage storage;
    sockaddr addr;
    sockaddr_in addr4;
    sockaddr_in6 addr6;
  };

  sockaddr_union remote;
  msg.msg_name = &remote.storage;
  msg.msg_namelen = sizeof(remote.storage);

  auto buffer = std::array<unsigned char, 4096>{};
  auto vec = iovec{buffer.data(), buffer.size()};
  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;

  constexpr size_t ecn_size = sizeof(int);
  constexpr size_t dstaddr_size =
      std::max(sizeof(in_pktinfo), sizeof(in6_pktinfo));
  constexpr size_t max_control_size =
      CMSG_SPACE(ecn_size) + CMSG_SPACE(dstaddr_size);
  auto control = std::array<unsigned char, max_control_size>{};
  msg.msg_control = control.data();
  msg.msg_controllen = control.size();

  const auto bytes = ::recvmsg(socket.native_handle(), &msg, 0);
  if (bytes == -1) {
    auto ec = error_code{errno, system_category()};
    std::cerr << "recvmsg failed: " << ec << std::endl;
    // depending on the error, retry or shutdown
    lsquic_engine_cooldown(handle.get());
    return;
  }

  int ecn = 0;
  sockaddr_union local;
  ::memcpy(&local.storage, local_endpoint.data(), local_endpoint.size());

  for (auto cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == IPPROTO_IP) {
      if (cmsg->cmsg_type == IP_TOS) {
        auto value = reinterpret_cast<const int*>(CMSG_DATA(cmsg));
        ecn = IPTOS_ECN(*value);
#ifdef IP_RECVORIGDSTADDR
      } else if (cmsg->cmsg_type == IP_ORIGDSTADDR) {
        ::memcpy(&local.storage, CMSG_DATA(cmsg), sizeof(sockaddr_in));
#else
      } else if (cmsg->cmsg_type == IP_PKTINFO) {
        auto info = reinterpret_cast<const in_pktinfo*>(CMSG_DATA(cmsg));
        local.addr4.sin_addr = info->ipi_addr;
#endif
      }
    } else if (cmsg->cmsg_level == IPPROTO_IPV6) {
      if (cmsg->cmsg_type == IPV6_TCLASS) {
        auto value = reinterpret_cast<const int*>(CMSG_DATA(cmsg));
        ecn = IPTOS_ECN(*value);
      } else if (cmsg->cmsg_type == IPV6_PKTINFO) {
        auto info = reinterpret_cast<const in6_pktinfo*>(CMSG_DATA(cmsg));
        local.addr6.sin6_addr = info->ipi6_addr;
      }
    }
  }

  int r = lsquic_engine_packet_in(handle.get(), buffer.data(), bytes,
                                  &local.addr, &remote.addr, this, ecn);
  if (r == -1) {
    std::cerr << "lsquic_engine_packet_in failed" << std::endl;
  }
  process();
  recv();
}

int engine_state::send_packets(const lsquic_out_spec *specs, unsigned n_specs) {
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

    constexpr size_t ecn_size = sizeof(int);
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

    int ret = ::sendmsg(socket.native_handle(), &msg, 0);
    if (ret == -1) {
      auto ec = error_code{errno, system_category()};
      std::cerr << "sendmsg failed: " << ec << std::endl;
      break;
    }

    ++num_sent;
  }
  std::cerr << "client send_packets sent " << num_sent << std::endl;
  return num_sent > 0 ? num_sent : -1;
}

} // namespace quic::detail
} // namespace nexus
