set(nexus-quic-srcs
	client.cc
	engine.cc
	error.cc
	global.cc
	server.cc
	socket.cc
	stream.cc)

add_library(nexus-quic ${nexus-quic-srcs})
target_link_libraries(nexus-quic PUBLIC nexus-headers lsquic)
install(TARGETS nexus-quic LIBRARY DESTINATION lib)
