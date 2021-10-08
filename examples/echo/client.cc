#include <iostream>
#include <fstream>
#include <boost/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>
#include <asio.hpp>
#include <nexus/global_init.hpp>
#include <nexus/quic/client.hpp>
#include <nexus/quic/connection.hpp>
#include <nexus/quic/stream.hpp>

// echo client takes one or more input files, writes each file in parallel
// to a different stream and reads back their echos for display to stdout.
// because the streams are multiplexed, the output from multiple files will be
// mixed together; however, running against a server with max-streams=1 will
// display their output in sequential order

namespace {

struct configuration {
  const char* hostname;
  const char* portstr;
  char** files_begin;
  char** files_end;
};

configuration parse_args(int argc, char** argv)
{
  if (argc < 4) {
    std::cerr << "Usage: " << argv[0] << " <hostname> <port> [filenames...]\n";
    ::exit(EXIT_FAILURE);
  }
  configuration config;
  config.hostname = argv[1];
  config.portstr = argv[2];
  config.files_begin = std::next(argv, 3);
  config.files_end = std::next(argv, argc);
  return config;
}

using asio::ip::udp;
using nexus::error_code;
using nexus::system_error;

using buffer_type = std::array<char, 256>;

template <typename T>
using ref_counter = boost::intrusive_ref_counter<T, boost::thread_unsafe_counter>;

struct echo_connection : ref_counter<echo_connection> {
  nexus::quic::client& client;
  nexus::quic::connection conn;

  echo_connection(nexus::quic::client& client,
                  const udp::endpoint& endpoint,
                  const char* hostname)
      : client(client), conn(client, endpoint, hostname)
  {}
  ~echo_connection() {
    client.close();
  }
};

using connection_ptr = boost::intrusive_ptr<echo_connection>;

struct echo_stream : ref_counter<echo_stream> {
  connection_ptr conn;
  nexus::quic::stream stream;
  std::ifstream input;
  std::ostream& output;
  buffer_type readbuf;
  buffer_type writebuf;

  echo_stream(connection_ptr conn, const char* filename, std::ostream& output)
      : conn(std::move(conn)), input(filename), output(output)
  {}
};
using stream_ptr = boost::intrusive_ptr<echo_stream>;

void write_file(stream_ptr stream)
{
  // read from input
  auto& data = stream->writebuf;
  stream->input.read(data.data(), data.size());
  const auto bytes = stream->input.gcount();
  // write to stream
  auto& s = stream->stream;
  asio::async_write(s, asio::buffer(data.data(), bytes),
    [stream=std::move(stream)] (error_code ec, size_t bytes) {
      if (ec) {
        std::cerr << "async_write failed with " << ec.message() << '\n';
      } else if (!stream->input) { // no more input, done writing
        stream->stream.shutdown(1);
      } else {
        write_file(std::move(stream));
      }
    });
}

void read_file(stream_ptr stream)
{
  // read back the echo
  auto& data = stream->readbuf;
  auto& s = stream->stream;
  s.async_read_some(asio::buffer(data),
    [stream=std::move(stream)] (error_code ec, size_t bytes) {
      if (ec) {
        if (ec != nexus::quic::stream_error::eof) {
          std::cerr << "async_read_some returned " << ec.message() << '\n';
        }
        return;
      }
      // write the output bytes then start reading more
      auto& data = stream->readbuf;
      stream->output.write(data.data(), bytes);
      read_file(std::move(stream));
    });
}

} // anonymous namespace

int main(int argc, char** argv)
{
  const auto cfg = parse_args(argc, argv);

  auto context = asio::io_context{};
  auto ex = context.get_executor();
  const auto endpoint = [&] {
      auto resolver = udp::resolver{ex};
      return resolver.resolve(cfg.hostname, cfg.portstr)->endpoint();
    }();

  auto ssl = asio::ssl::context{asio::ssl::context::tlsv13};
  ::SSL_CTX_set_min_proto_version(ssl.native_handle(), TLS1_3_VERSION);
  ::SSL_CTX_set_max_proto_version(ssl.native_handle(), TLS1_3_VERSION);
  const unsigned char alpn[] = {4,'e','c','h','o'};
  ::SSL_CTX_set_alpn_protos(ssl.native_handle(), alpn, sizeof(alpn));

  auto global = nexus::global::init_client();
  auto client = nexus::quic::client{ex, udp::endpoint{endpoint.protocol(), 0}, ssl};

  auto conn = connection_ptr{new echo_connection(client, endpoint, cfg.hostname)};

  // connect a stream for each input file
  for (auto f = cfg.files_begin; f != cfg.files_end; ++f) {
    auto stream = stream_ptr{new echo_stream(conn, *f, std::cout)};
    auto& c = conn->conn;
    auto& s = stream->stream;
    c.async_connect(s, [stream=std::move(stream)] (error_code ec) {
        if (ec) {
          std::cerr << "async_connect failed with " << ec.message() << '\n';
          return;
        }
        write_file(stream);
        read_file(std::move(stream));
      });
  }
  conn.reset(); // let the connection close once all streams are done

  context.run();
  return 0;
}
