#include <algorithm>
#include <array>
#include <iostream>
#include <memory>
#include <thread>

#include <netinet/ip.h>
#include <sys/socket.h>

#include <boost/asio.hpp>
#include <boost/iterator/transform_iterator.hpp>

#include <nexus/quic/global_context.hpp>
#include <nexus/http3/client.hpp>
#include <nexus/http3/stream.hpp>

using boost::asio::ip::udp;

int main(int argc, char** argv) {
  // parse argv for <hostname> <port> <path>
  if (argc < 4) {
    std::cerr << "Usage: " << argv[0] << " <hostname> <port> <path>" << std::endl;
    return EXIT_FAILURE;
  }
  const char* hostname = argv[1];
  const std::string_view portstr = argv[2];
  const std::string_view path = argv[3];

  auto ioc = boost::asio::io_context{};

  auto work = boost::asio::make_work_guard(ioc);
  auto thread = std::thread{[&ioc] { ioc.run(); }};

  // resolve hostname
  const auto remote_endpoint = [&] {
      auto resolver = udp::resolver{ioc.get_executor()};
      return resolver.resolve(hostname, portstr)->endpoint();
    }();

  auto global = nexus::quic::global::init_client();
  {
    auto client = nexus::http3::client{ioc.get_executor()};
    auto conn = client.connect(remote_endpoint, hostname);

    auto stream = nexus::http3::stream{conn};
    // send headers
    auto request = nexus::http3::fields{};
    request.insert(":method", "HEAD");
    request.insert(":scheme", "https");
    request.insert(":path", path);
    request.insert(":authority", hostname);
    request.insert("user-agent", "h3cli/lsquic");
    nexus::error_code ec;
    stream.write_headers(request, ec);
    stream.shutdown(1, ec);
    // read response as data
    auto response = std::array<char, 4096>{};
    do {
      const auto bytes = stream.read_some(boost::asio::buffer(response), ec);
      std::cout << "read_some returned " << ec << ' ' << bytes << std::endl;
      std::cout.write(response.data(), bytes);
    } while (!ec);
  }
  work.reset();
  thread.join();
  return 0;
}
