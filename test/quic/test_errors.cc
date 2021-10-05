#include <nexus/quic/error.hpp>
#include <gtest/gtest.h>

namespace nexus::quic {

TEST(errors, connection)
{
  // connection errors are distinguishable from stream errors
  EXPECT_NE(make_error_condition(stream_error::reset),
            make_error_code(connection_error::reset));
  EXPECT_NE(make_error_condition(stream_error::aborted),
            make_error_code(connection_error::aborted));
  // connection errors can be compared to generic error conditions
  EXPECT_EQ(make_error_condition(errc::connection_reset),
            make_error_code(connection_error::reset));
  EXPECT_EQ(make_error_condition(errc::connection_aborted),
            make_error_code(connection_error::aborted));
}

TEST(errors, stream)
{
  // stream errors are distinguishable from connection errors
  EXPECT_NE(make_error_condition(connection_error::reset),
            make_error_code(stream_error::reset));
  EXPECT_NE(make_error_condition(connection_error::aborted),
            make_error_code(stream_error::aborted));
  // stream errors can be compared to generic error conditions
  EXPECT_EQ(make_error_condition(errc::connection_reset),
            make_error_code(stream_error::reset));
  EXPECT_EQ(make_error_condition(errc::connection_aborted),
            make_error_code(stream_error::aborted));
  EXPECT_EQ(make_error_condition(errc::device_or_resource_busy),
            make_error_code(stream_error::busy));
}

} // namespace nexus::quic
