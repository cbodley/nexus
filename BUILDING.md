# Building Nexus

## Dependencies

* LiteSpeed QUIC (lsquic)
* BoringSSL
* asio
* zlib
* googletest for tests

BoringSSL, lsquic, asio and googletest are included as git submodules, which must be initialized before building:

	~/nexus $ git submodule update --init --recursive

The zlib dependency must be installed manually. For example, on Fedora:

	~/nexus $ sudo dnf install zlib-devel

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
