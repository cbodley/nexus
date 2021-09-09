set(nexus-quic-srcs
	client.cc
	engine.cc
	error.cc
	global.cc
	stream.cc)

add_library(nexus-quic ${nexus-quic-srcs})
target_link_libraries(nexus-quic PUBLIC nexus lsquic)
