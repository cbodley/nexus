#include <iostream>
#include <boost/asio.hpp> // resolver

#include <nexus/quic/global_context.hpp>
#include <nexus/quic/http3/client.hpp>
#include <nexus/quic/http3/stream.hpp>

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

  // resolve hostname
  const auto remote_endpoint = [&] {
      auto ioc = boost::asio::io_context{};
      auto resolver = udp::resolver{ioc.get_executor()};
      return resolver.resolve(hostname, portstr)->endpoint();
    }();

  auto global = nexus::quic::global::init_client();
  auto client = nexus::quic::http3::client{};
  auto conn = nexus::quic::http3::client_connection{
    client, remote_endpoint.data(), hostname};
  auto stream = nexus::quic::http3::stream{conn};
  // send headers
  auto request = nexus::quic::http3::fields{};
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
    std::cout.write(response.data(), bytes);
  } while (!ec);
  return 0;
}
