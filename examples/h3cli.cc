#include <iostream>
#include <optional>

#include <asio.hpp>

#include <nexus/quic/global_context.hpp>
#include <nexus/quic/http3/client.hpp>
#include <nexus/quic/http3/stream.hpp>

using asio::ip::udp;
using nexus::error_code;
using body_buffer = std::array<char, 4096>;

static void read_print_stream(nexus::quic::http3::stream& stream,
                              nexus::quic::http3::client& client,
                              body_buffer& buffer)
{
  stream.async_read_some(asio::buffer(buffer), [&] (error_code ec, size_t bytes) {
        if (ec) {
          if (ec != nexus::quic::error::end_of_stream) {
            std::cerr << "async_read_some failed with " << ec << std::endl;
          }
          client.close();
          return;
        }
        std::cout.write(buffer.data(), bytes);
        read_print_stream(stream, client, buffer);
      });
}

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

  // resolve hostname
  const auto remote_endpoint = [&] {
      auto resolver = udp::resolver{ex};
      return resolver.resolve(hostname, portstr)->endpoint();
    }();

  auto global = nexus::quic::global::init_client();
  auto client = nexus::quic::http3::client{ex, udp::endpoint{}};
  auto conn = nexus::quic::http3::client_connection{client};
  conn.connect(remote_endpoint, hostname);
  auto stream = nexus::quic::http3::stream{conn};

  auto request = nexus::quic::http3::fields{};
  request.insert(":method", "GET");
  request.insert(":scheme", "https");
  request.insert(":path", path);
  request.insert(":authority", hostname);
  request.insert("user-agent", "h3cli/lsquic");
  auto response = nexus::quic::http3::fields{};
  auto buffer = body_buffer{};

  stream.async_connect([&] (error_code ec) {
    if (ec) {
      std::cerr << "async_connect failed with " << ec << std::endl;
      return;
    }
    stream.async_write_headers(request, [&] (error_code ec) {
      if (ec) {
        std::cerr << "async_write_headers failed with " << ec << std::endl;
        return;
      }
      stream.shutdown(1);
      stream.async_read_headers(response, [&] (error_code ec) {
        if (ec) {
          std::cerr << "async_read_headers failed with " << ec << std::endl;
          return;
        }
        for (const auto& f : response) {
          std::cout << f.c_str() << "\r\n";
        }
        std::cout << "\r\n";
        read_print_stream(stream, client, buffer);
      });
    });
  });

  ioc.run();
  return 0;
}
