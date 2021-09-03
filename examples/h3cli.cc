#include <algorithm>
#include <array>
#include <iostream>
#include <memory>

#include <netinet/ip.h>
#include <sys/socket.h>

#include <boost/asio.hpp>
#include <boost/iterator/transform_iterator.hpp>

#include <lsquic.h>
#include <lsxpack_header.h>

#include <nexus/quic/global_context.hpp>

using boost::system::error_code;

using udp = boost::asio::ip::udp;
using Timer = boost::asio::basic_waitable_timer<std::chrono::system_clock>;

struct engine_deleter {
  void operator()(lsquic_engine_t* e) const { lsquic_engine_destroy(e); }
};
using engine_ptr = std::unique_ptr<lsquic_engine_t, engine_deleter>;

struct h3cli {
  udp::socket socket;
  udp::endpoint local_endpoint;
  Timer timer;
  engine_ptr engine;
  lsquic_conn_t* conn = nullptr;
  std::string_view hostname;
  std::string_view path;

  h3cli(udp::socket&& socket, const udp::endpoint& local_endpoint,
        std::string_view hostname, std::string_view path)
    : socket(std::move(socket)), local_endpoint(local_endpoint),
      timer(this->socket.get_executor()), hostname(hostname), path(path)
  {}

  void process() {
    lsquic_engine_process_conns(engine.get());
    reschedule();
  }

  void reschedule() {
    int micros = 0;
    lsquic_engine_earliest_adv_tick(engine.get(), &micros);

    timer.expires_after(std::chrono::microseconds(micros));
    timer.async_wait([this] (error_code ec) {
        if (ec == error_code{}) {
          process();
        }
      });
  }

  void recv() {
    // non-blocking socket, so wait until it's readable
    socket.async_wait(udp::socket::wait_read,
        [this] (error_code ec) {
          on_recv_ready(ec);
        });
  }

  int read_ecn(msghdr* m) {
    const auto match = [] (const cmsghdr* c, int level, int type) {
          return c->cmsg_level == level && c->cmsg_type == type;
        };
    for (auto c = CMSG_FIRSTHDR(m); c; c = CMSG_NXTHDR(m, c)) {
      if (match(c, IPPROTO_IP, IP_TOS) ||
          match(c, IPPROTO_IPV6, IPV6_TCLASS)) {
        int ecn = 0;
        memcpy(&ecn, CMSG_DATA(c), sizeof(ecn));
        return ecn & IPTOS_ECN_MASK;
      }
    }
    return 0;
  }

  void on_recv_ready(error_code ec) {
    if (ec) {
      std::cerr << "on_recv_ready failed: " << ec << std::endl;
      socket.close();
      timer.cancel();
      return;
    }

    // XXX: need to call ::recvmsg() directly because socket.recv_from()
    // doesn't support ancillary data for ECN
    auto msg = msghdr{};

    auto remote_endpoint = udp::endpoint{};
    msg.msg_name = remote_endpoint.data();
    msg.msg_namelen = remote_endpoint.size();

    // ancillary data for ECN support
    auto control = std::array<unsigned char, CMSG_SPACE(sizeof(int))>{};
    msg.msg_control = control.data();
    msg.msg_controllen = control.size();

    auto buffer = std::array<unsigned char, 4096>{};
    auto vec = iovec{buffer.data(), buffer.size()};
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;

    const auto bytes = ::recvmsg(socket.native_handle(), &msg, 0);
    if (bytes == -1) {
      if (EAGAIN != errno && EWOULDBLOCK != errno) {
        std::cerr << "recvmsg: " << strerror(errno) << std::endl;
      }
      return;
    }

    const int ecn = read_ecn(&msg);

    int r = lsquic_engine_packet_in(engine.get(), buffer.data(), bytes,
                                    local_endpoint.data(),
                                    remote_endpoint.data(),
                                    this, ecn);
    if (r == -1) {
      std::cerr << "lsquic_engine_packet_in failed" << std::endl;
    }

    reschedule();
    recv();
  }
};

// by Chris Kohlhoff in https://sourceforge.net/p/asio/feature-requests/18/
class iovec_buffer_sequence {
  const iovec* begin_;
  const iovec* end_;
  struct to_buffer {
    using result_type = boost::asio::mutable_buffer;
    result_type operator()(iovec i) const { return {i.iov_base, i.iov_len}; }
  };
 public:
  using value_type = boost::asio::mutable_buffer;
  using const_iterator = boost::transform_iterator<to_buffer, const iovec*>;

  iovec_buffer_sequence(const iovec* iov, size_t iovlen)
    : begin_(iov), end_(iov + iovlen) {}

  iovec_buffer_sequence(const iovec* begin, const iovec* end)
    : begin_(begin), end_(end) {}

  const_iterator begin() const { return const_iterator{begin_}; }
  const_iterator end() const { return const_iterator{end_}; }
};

static int send_packets(void* ctx, const lsquic_out_spec *specs,
                        unsigned n_specs)
{
  auto h3 = static_cast<h3cli*>(ctx);

  int num_sent = 0;
  for (auto spec = specs; spec < specs + n_specs; ++spec) {
    auto dest = udp::endpoint{};
    if (spec->dest_sa->sa_family == AF_INET) {
      const auto sa4 = reinterpret_cast<const sockaddr_in*>(spec->dest_sa);
      dest.port(::htons(sa4->sin_port));
      dest.address(boost::asio::ip::address_v4{::htonl(sa4->sin_addr.s_addr)});
    } else if (spec->dest_sa->sa_family == AF_INET6) {
      const auto sa6 = reinterpret_cast<const sockaddr_in6*>(spec->dest_sa);
      dest.port(::htons(sa6->sin6_port));
      std::array<unsigned char, 16> arr;
      std::copy(std::begin(sa6->sin6_addr.s6_addr),
                std::end(sa6->sin6_addr.s6_addr),
                std::begin(arr));
      dest.address(boost::asio::ip::address_v6{arr, sa6->sin6_scope_id});
    } else {
      break; // this is an error, stop sending
    }

    const auto buffers = iovec_buffer_sequence{spec->iov, spec->iovlen};
    const int flags = 0;
    error_code ec;
    const auto bytes = h3->socket.send_to(buffers, dest, flags, ec);
    if (ec) {
      std::cerr << "send_to failed: " << ec << std::endl;
      break;
    }
    ++num_sent;
  }
  return num_sent > 0 ? num_sent : -1;
}

static lsquic_conn_ctx_t* on_new_conn(void* ctx, lsquic_conn_t* conn)
{
  std::cout << "on_new_conn " << conn << std::endl;
  lsquic_conn_make_stream(conn);
  return static_cast<lsquic_conn_ctx_t*>(ctx);
}

static lsquic_stream_ctx_t* on_new_stream(void* ctx, lsquic_stream_t* stream)
{
  std::cout << "on_new_stream " << stream << std::endl;
  lsquic_stream_wantwrite(stream, 1);
  return static_cast<lsquic_stream_ctx_t*>(ctx);
}

static void on_read(lsquic_stream_t* stream, lsquic_stream_ctx_t* ctx)
{
  std::cout << "on_read " << stream << std::endl;
  char buf[0x1000];
  const auto bytes = lsquic_stream_read(stream, buf, sizeof(buf));
  if (bytes == -1) {
    std::cerr << "on_read failed with " << errno << std::endl;
  } else if (bytes == 0) { // EOF
    lsquic_stream_shutdown(stream, 0);
    auto conn = lsquic_stream_conn(stream);
    lsquic_conn_close(conn);
  } else {
    std::cout.write(buf, bytes);
  }
}

static char* add_header(lsxpack_header* header, char* pos, char* end,
                        std::string_view name, std::string_view value)
{
  char* const begin = pos;
  if (pos + name.size() > end) {
    return pos + name.size();
  }
  pos = std::copy(name.begin(), name.end(), pos);
  if (pos + value.size() > end) {
    return pos + value.size();
  }
  lsxpack_header_set_offset2(header, begin, 0, name.size(),
                             name.size(), value.size());
  return std::copy(value.begin(), value.end(), pos);
}

static void on_write(lsquic_stream_t* stream, lsquic_stream_ctx_t* ctx)
{
  std::cout << "on_write " << stream << std::endl;
  auto h3 = reinterpret_cast<const h3cli*>(ctx);

  // format the headers for packing
  lsxpack_header harray[5];
  const lsquic_http_headers headers = {5, harray};

  char data[4096];
  char* pos = data;
  char* const end = std::end(data);
  pos = add_header(&harray[0], pos, end, ":method", "HEAD");
  pos = add_header(&harray[1], pos, end, ":scheme", "https");
  pos = add_header(&harray[2], pos, end, ":path", h3->path);
  pos = add_header(&harray[3], pos, end, ":authority", h3->hostname);
  pos = add_header(&harray[4], pos, end, "user-agent", "h3cli/lsquic");
  if (pos > end) { // overflow
    std::cerr << "on_write header overflow" << std::endl;
    auto conn = lsquic_stream_conn(stream);
    lsquic_conn_abort(conn);
    return;
  }
  // send the headers
  if (lsquic_stream_send_headers(stream, &headers, 0) == -1) {
    std::cerr << "on_write lsquic_stream_send_header failed" << std::endl;
    auto conn = lsquic_stream_conn(stream);
    lsquic_conn_abort(conn);
    return;
  }
  // done writing
  lsquic_stream_shutdown(stream, 1);
  lsquic_stream_wantread(stream, 1);
}

static void on_close(lsquic_stream_t* stream, lsquic_stream_ctx_t* ctx)
{
  std::cout << "on_close " << stream << std::endl;
}

static void on_conn_closed(lsquic_conn_t* conn)
{
  std::cout << "on_conn_closed " << conn << std::endl;
  auto ctx = reinterpret_cast<h3cli*>(lsquic_conn_get_ctx(conn));
  ctx->socket.close();
  ctx->timer.cancel();
}

constexpr lsquic_stream_if make_stream_api()
{
  lsquic_stream_if api = {};
  api.on_new_conn = on_new_conn;
  api.on_conn_closed = on_conn_closed;
  api.on_new_stream = on_new_stream;
  api.on_read = on_read;
  api.on_write = on_write;
  api.on_close = on_close;
  return api;
}

int main(int argc, char** argv) {
  // parse argv for <hostname> <port> <path>
  if (argc < 4) {
    std::cerr << "Usage: " << argv[0] << " <hostname> <port> <path>" << std::endl;
    return EXIT_FAILURE;
  }
  const auto hostname = argv[1];
  const auto portstr = argv[2];
  const auto path = argv[3];

  auto ioc = boost::asio::io_context{};

  // resolve hostname
  const auto remote_endpoint = [&] {
      auto resolver = udp::resolver{ioc.get_executor()};
      return resolver.resolve(hostname, portstr)->endpoint();
    }();

  auto socket = udp::socket{ioc.get_executor(), udp::endpoint{}};
  socket.non_blocking(true);
  const auto local_endpoint = socket.local_endpoint();

  auto h3 = h3cli{std::move(socket), local_endpoint, hostname, path};

  // global init
  auto global = nexus::quic::global::init_client();
  // default settings
  lsquic_engine_settings settings;
  lsquic_engine_init_settings(&settings, LSENG_HTTP);
  char errbuf[256];
  if (lsquic_engine_check_settings(&settings, LSENG_HTTP,
                                   errbuf, sizeof(errbuf)) == -1) {
    std::cerr << "lsquic_engine_check_settings failed: " << errbuf << std::endl;
    return EXIT_FAILURE;
  }

  // construct the engine
  lsquic_engine_api api = {};
  api.ea_packets_out = send_packets;
  api.ea_packets_out_ctx = &h3;
  const lsquic_stream_if stream_api = make_stream_api();
  api.ea_stream_if = &stream_api;
  api.ea_stream_if_ctx = &h3;
  api.ea_settings = &settings;
  h3.engine.reset(lsquic_engine_new(LSENG_HTTP, &api));

  h3.conn = lsquic_engine_connect(h3.engine.get(),
      N_LSQVER, local_endpoint.data(), remote_endpoint.data(),
      &h3, nullptr, hostname, 0, nullptr, 0, nullptr, 0);
  if (!h3.conn) {
    std::cerr << "lsquic_engine_connect returned null" << std::endl;
    return EXIT_FAILURE;
  }
  h3.recv(); // start reading packets
  h3.reschedule();
  ioc.run();
  return 0;
}
