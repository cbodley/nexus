#pragma once

namespace nexus::http::detail {

template <typename T, typename Executor>
struct shutdown_op {
  using value_type = T;
  value_type value;
  using executor_type = Executor;
  executor_type ex;

  explicit shutdown_op(value_type&& value, const Executor& ex)
    : value(std::move(value)), ex(ex) {}

  executor_type get_executor() const { return ex; }

  void operator()(boost::system::error_code) {}
};

} // namespace nexus::http::detail
