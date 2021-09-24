#pragma once

#include <nexus/error_code.hpp>

namespace nexus::quic {

enum class error {
  global_init_failed = 1,
  end_of_stream = 2,
};

/// quic error category
const error_category& quic_category();

inline error_code make_error_code(error e)
{
  return {static_cast<int>(e), quic_category()};
}

inline error_condition make_error_condition(error e)
{
  return {static_cast<int>(e), quic_category()};
}

} // namespace nexus::quic

namespace SYSTEM_ERROR_NAMESPACE {

/// enables implicit conversion to std::error_condition
template <>
struct is_error_condition_enum<nexus::quic::error> : public true_type {};

} // namespace SYSTEM_ERROR_NAMESPACE
