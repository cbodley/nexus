#include <nexus/quic/error.hpp>

namespace nexus::quic {

const error_category& quic_category()
{
  struct category : public error_category {
    const char* name() const noexcept override {
      return "nexus::quic";
    }

    std::string message(int ev) const override {
      switch (static_cast<error>(ev)) {
        case error::operation_aborted:
          return "operation aborted";
        case error::connection_aborted:
          return "connection aborted";
        case error::connection_handshake_failed:
          return "connection handshake failed";
        case error::connection_timed_out:
          return "connection timed out";
        case error::connection_reset:
          return "connection reset by peer";
        case error::connection_going_away:
          return "peer is going away";
        case error::end_of_stream:
          return "end of stream";
        case error::stream_reset:
          return "stream reset by peer";
        default:
          return "unknown";
      }
    }
  };
  static category instance;
  return instance;
}

} // namespace nexus::quic
