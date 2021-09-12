#include <iostream>
#include <optional>
#include <thread>

#include <asio.hpp>

#include <nexus/quic/global_context.hpp>
#include <nexus/quic/http3/client.hpp>
#include <nexus/quic/http3/stream.hpp>

using asio::ip::udp;

int main(int argc, char** argv) {
  // parse argv for <hostname> <port> <path>
  if (argc < 4) {
    std::cerr << "Usage: " << argv[0] << " <hostname> <port> <path>" << std::endl;
    return EXIT_FAILURE;
  }
  const char* hostname = argv[1];
  const std::string_view portstr = argv[2];
  const std::string_view path = argv[3];

  auto ioc = asio::io_context{};
  auto ex = ioc.get_executor();
  // keep an io thread running until 'client' takes over
  std::optional work = asio::prefer(ex, asio::execution::outstanding_work.tracked);
  std::thread thread{[&ioc] { ioc.run(); }};

  // resolve hostname
  const auto remote_endpoint = [&] {
      auto resolver = udp::resolver{ex};
      return resolver.resolve(hostname, portstr)->endpoint();
    }();
  {
    auto global = nexus::quic::global::init_client();
    auto client = nexus::quic::http3::client{ex, udp::endpoint{}};
    work.reset(); // let the thread exit when client is done
    auto conn = nexus::quic::http3::client_connection{client};
    conn.connect(remote_endpoint, hostname);
    auto stream = nexus::quic::http3::stream{conn};
    stream.connect();
    // send headers
    auto request = nexus::quic::http3::fields{};
    request.insert(":method", "GET");
    request.insert(":scheme", "https");
    request.insert(":path", path);
    request.insert(":authority", hostname);
    request.insert("user-agent", "h3cli/lsquic");
    stream.write_headers(request);
    stream.shutdown(1);
    // read response headers
    auto response = nexus::quic::http3::fields{};
    stream.read_headers(response);
    for (const auto& f : response) {
      std::cout << f.c_str() << "\r\n";
    }
    std::cout << "\r\n";
    // read response body until eof
    std::error_code ec;
    do {
      auto response = std::array<char, 4096>{};
      const auto bytes = stream.read_some(asio::buffer(response), ec);
      std::cout.write(response.data(), bytes);
    } while (!ec);
  }
  thread.join();
  return 0;
}
