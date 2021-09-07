add_executable(h3cli h3cli.cc)
target_link_libraries(h3cli nexus-quic address-sanitizer)
