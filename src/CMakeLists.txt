set(nexus-srcs
	client.cc
	connection.cc
	engine.cc
	error.cc
	global.cc
	server.cc
	settings.cc
	socket.cc
	stream.cc
	stream_state.cc)

add_library(nexus ${nexus-srcs})
target_link_libraries(nexus PUBLIC nexus-headers lsquic)
install(TARGETS nexus LIBRARY DESTINATION lib)
