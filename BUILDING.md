# Building Nexus

## Dependencies

* LiteSpeed QUIC (lsquic)
* BoringSSL
* Boost
* zlib
* googletest for tests

BoringSSL and lsquic are included as git submodules, which must be initialized before building:

	~/nexus $ git submodule update --init --recursive

The boost, gtest and zlib dependencies must be installed manually. For example, on Fedora:

	~/nexus $ sudo dnf install boost-devel gtest-devel zlib-devel

## Building

Nexus uses the CMake build system. Start by creating a build directory:

	~/nexus $ mkdir build && cd build

Then invoke `cmake` to generate the build scripts:

	~/nexus/build $ cmake ..

Then build the library and its dependencies:

	~/nexus/build $ cmake --build .

You can run unit tests with `ctest`:

	~/nexus/build $ ctest

You can install nexus and its dependencies with:

	~/nexus/build $ cmake --build . --target install
