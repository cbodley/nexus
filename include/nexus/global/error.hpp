#pragma once

#include <nexus/error_code.hpp>

namespace nexus::global {

/// global error category
const error_category& global_category();

/// global error codes
enum class error {
  init_failed = 1, //< global initialization failed
};

inline error_code make_error_code(error e)
{
  return {static_cast<int>(e), global_category()};
}

inline error_condition make_error_condition(error e)
{
  return {static_cast<int>(e), global_category()};
}

} // namespace nexus::global
