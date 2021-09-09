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
        case error::end_of_stream:
          return "end of stream";
        default:
          return "unknown";
      }
    }
  };
  static category instance;
  return instance;
}

} // namespace nexus::quic
