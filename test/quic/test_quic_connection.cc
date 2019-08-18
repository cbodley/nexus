#include <nexus/quic/connection.hpp>
#include <gtest/gtest.h>

namespace nexus::quic {

TEST(quic, connection)
{
  boost::asio::io_context context;
  proto::resolver resolver(context);
  proto::endpoint remote = *resolver.resolve(proto::v4(), "localhost", "12345").begin();

  connection conn(context, remote);
  conn.send_initial();
}

} // namespace nexus::quic
