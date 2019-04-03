TODO
====

HPACK
-----

* huffman encode/decode for string literals
* stateful hpack decoder that reads one frame at a time and tolerates frame boundaries at any point
* beast Fields that preserve the 'never-indexed' property of literal header fields
* benchmarks

basic_connection
---------------

* handle HEADERS with CONTINUATION frames (depends on stateful hpack decoder)
* add an async process to read and handle request frames without blocking to write response frames
* add an async process that sends control frames and services the outgoing stream priority queue
* replace run() with an async_run() that reads/writes in parallel
* handle GOAWAY and RST_STREAM frames
* ssl::server_connection for server side of tls handshake

basic_stream
------------

* interfaces to manage priority relationships between streams. support streams with stream id 0 that haven't sent/received HEADERS yet
* interface to control max window size
* send WINDOW_UPDATE frames after reads are done with their buffers
* async read/write

stream_scheduler
----------------

* maintain a priority queue of streams with data to send and the stream window to send it
* enqueue sending streams once stream window becomes available

Error Handling
--------------
* distinguish between connection errors and stream errors
* send GOAWAY frame on connection errors
* send RST_STREAM frame on stream errors
* strategy for reconnects that can reuse existing settings and buffers
