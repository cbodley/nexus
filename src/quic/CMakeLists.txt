set(nexus-quic-srcs
	engine.cc
	client.cc)

add_library(nexus-quic ${nexus-quic-srcs})
target_link_libraries(nexus-quic PUBLIC nexus)
