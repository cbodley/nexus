#pragma once

#include <nexus/error_code.hpp>
#include <nexus/quic/detail/file_descriptor.hpp>
#include <nexus/quic/sockaddr.hpp>

struct addrinfo;
struct lsquic_out_spec;

namespace nexus::quic::detail {

// open and bind a non-blocking socket with REUSEADDR and ECN options enabled.
// the DSTADDR option is enabled in server mode. the bound address is returned
// in 'addr'
file_descriptor bind_udp_socket(const addrinfo* info, bool server,
                                sockaddr_union& addr, error_code& ec);

// send each of the udp packets with sendmsg(), including control messages for
// ECN and DSTADDR
int send_udp_packets(int fd, const lsquic_out_spec* specs, unsigned n_specs);

} // namespace nexus::quic::detail
