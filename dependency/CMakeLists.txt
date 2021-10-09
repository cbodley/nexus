find_package(ZLIB REQUIRED)

add_subdirectory(boringssl)

set(BORINGSSL_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/boringssl/include)
set(BORINGSSL_LIB_ssl ssl)
set(BORINGSSL_LIB_crypto crypto)
set(BORINGSSL_LIB_decrepit decrepit)

add_subdirectory(lsquic)

cmake_policy(SET CMP0079 NEW)
target_include_directories(lsquic PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lsquic/include ${BORINGSSL_INCLUDE})
target_link_libraries(lsquic PUBLIC ssl crypto decrepit ZLIB::ZLIB)

add_library(asio INTERFACE)
target_include_directories(asio INTERFACE asio/asio/include)
target_compile_definitions(asio INTERFACE -DASIO_STANDALONE -DASIO_NO_TS_EXECUTORS)
