#pragma once

struct lsquic_out_spec;

namespace nexus::quic::detail {

// send each of the udp packets with sendmsg(), including control messages for
// ECN and DSTADDR
int send_udp_packets(int fd, const lsquic_out_spec* specs, unsigned n_specs);

} // namespace nexus::quic::detail
