add_executable(test_connection_pool test_connection_pool.cc)
target_link_libraries(test_connection_pool nexus test_base OpenSSL::SSL OpenSSL::Crypto)
add_test(test_connection_pool test_connection_pool)

add_executable(test_connection_impl test_connection_impl.cc)
target_link_libraries(test_connection_impl nexus test_base OpenSSL::SSL OpenSSL::Crypto)
add_test(test_connection_impl test_connection_impl)
