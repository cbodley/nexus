add_subdirectory(dependency)

add_library(sanitizers INTERFACE)
target_compile_options(sanitizers INTERFACE "-fsanitize=address")
target_link_libraries(sanitizers INTERFACE "-fsanitize=address")
