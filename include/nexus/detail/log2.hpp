#pragma once

#include <limits>
#include <type_traits>

namespace nexus::detail {

// clz builtins are undefined for 0
inline int clz_nonzero(unsigned int x) { return __builtin_clz(x); }
inline int clz_nonzero(unsigned long x) { return __builtin_clzl(x); }
inline int clz_nonzero(unsigned long long x) { return __builtin_clzll(x); }

template <typename T>
auto log2_nonzero(T x) -> std::enable_if_t<std::is_unsigned_v<T>, unsigned int>
{
  return std::numeric_limits<T>::digits - 1 - clz_nonzero(x);
}

} // namespace nexus::detail
