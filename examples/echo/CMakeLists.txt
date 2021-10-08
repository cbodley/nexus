add_executable(nexus_echo_client client.cc)
target_link_libraries(nexus_echo_client nexus address-sanitizer)

add_executable(nexus_echo_server server.cc)
target_link_libraries(nexus_echo_server nexus address-sanitizer)
