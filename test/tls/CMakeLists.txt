add_executable(test_tls_alpn test_tls_alpn.cc)
target_link_libraries(test_tls_alpn nexus test_base OpenSSL::Crypto OpenSSL::SSL)
add_test(test_tls_alpn test_tls_alpn)
