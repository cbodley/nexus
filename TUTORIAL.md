# Tutorial

Nexus provides two sets of interfaces: one in namespace nexus::quic for generic QUIC clients and servers, and another in namespace nexus::h3 for HTTP/3 clients and servers.

## Global Initialization

The library must be initialized before use, and this is accomplished by creating a nexus::global::context with one of its factory functions:

	{
	  auto global = nexus::global::init_client();
	  ...
	} // global cleanup on destruction

## TLS

All QUIC connections are secure by default, so the use of TLS is not optional. TLS configuration is left to the application, which is expected to provide an initialized `asio::ssl::context` to the client and server interfaces.

### TLS v1.3

QUIC requires TLS version 1.3, so the ssl context should be initialized with a TLS 1.3 method, and its min/max protocol version should be set:

	auto ssl = asio::ssl::context{asio::ssl::context::tlsv13};
	SSL_CTX_set_min_proto_version(ssl.native_handle(), TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ssl.native_handle(), TLS1_3_VERSION);

### Certificate Verification

All QUIC clients ["MUST authenticate the identity of the server"](https://www.rfc-editor.org/rfc/rfc9001.html#name-peer-authentication), and the application is responsible for providing an SSL context that does this:

	ssl.set_verify_mode(asio::ssl::verify_peer);

## QUIC

### Application-Layer Protocol Negotiation

QUIC endpoints use a TLS extension called [Application-Layer Protocol Negotiation](https://en.wikipedia.org/wiki/ALPN) (ALPN) to negotiate the application protocol. The HTTP/3 client and server automatically negotiate the "h3" protocol, but the generic QUIC client and server are protocol-agnostic so must negotiate this manually.

The client provides its desired protocol names in a call to `SSL_CTX_set_alpn_protos()`.

The server implements this negotiation using `SSL_CTX_set_alpn_select_cb()` and `SSL_select_next_proto()`, either selecting the first supported protocol in the client's list, or rejecting the client's handshake.

The negotiated protocol can be queried on either side with `SSL_get0_alpn_selected()`.

### Settings

As part of the connection handshake, the client and server exchange their QUIC [Transport Parameters](https://www.rfc-editor.org/rfc/rfc9000.html#transport-parameter-definitions). Some of the transport parameters we send, such as flow control limits and timeouts, can be configured with class nexus::quic::settings.

Nexus also receives the peer's transport parameters, and will automatically respect the limits they impose. For example, once we've opened the maximum number of outgoing streams on the connection, requests to initiate a new outgoing stream will block until another stream closes. And once we reach a stream or connection flow control limit, requests to write more data will block until the peer reads some and adjusts the window.

The client and server constructors take an optional nexus::quic::settings argument and, once constructed, these settings cannot be changed.

### Client

The generic QUIC client (class nexus::quic::client) takes control of a bound `asio::ip::udp::socket` and `asio::ssl::context` to initiate secure connections (class nexus::quic::connection) to QUIC servers.

	auto client = nexus::quic::client{ex, udp::endpoint{}, ssl};

Initiating a client connection is instantaneous, and does not wait for the connection handshake to complete. This allows the application to start opening streams and staging data in the meantime. If the handshake does fail, the relevant error code will be delivered to any pending stream operations.

A client initiates a connection either by calling nexus::quic::client::connect():

	auto conn = nexus::quic::connection{client};
	client.connect(conn, endpoint, hostname);

Or by providing the remote endpoint and hostname arguments to the nexus::quic::connection constructor:

	auto conn = nexus::quic::connection{client, endpoint, hostname};

### Server

The generic QUIC server (class nexus::quic::server) listens on one or more UDP sockets (using class nexus::quic::acceptor) to accept secure connections from QUIC clients.

	auto server = nexus::quic::server{ex};
	auto acceptor = nexus::quic::acceptor{server, bind_endpoint, ssl};
	acceptor.listen(16);

	auto conn = nexus::quic::connection{acceptor};
	acceptor.accept(conn);

Unlike nexus::quic::client::connect() which returns immediately without waiting for the connection handshake, accept() only completes once the handshake is successful.

### Connection

Once a generic QUIC connection (class nexus::quic::connection) has been connected or accepted, it can be used both to initiate outgoing streams with connect():

	auto stream = nexus::quic:stream{};
	conn.connect(stream);

And to accept() incoming streams:

	auto stream = nexus::quic:stream{};
	conn.accept(stream);

When a connection closes, all related streams are closed and any pending operations are canceled with a connection error.

### Stream

Once a generic QUIC stream (class nexus::quic::stream) has been connected or accepted, it provides bidirectional, reliable ordered delivery of data.

For reads and writes, nexus::quic::stream models the asio concepts AsyncReadStream, AsyncWriteStream, SyncReadStream and SyncWriteStream, so can be used with the same read and write algorithms as `asio::ip::tcp::socket`:

	char request[16]; // read 16 bytes from the stream
	auto bytes = asio::read(stream, asio::buffer(data));

The stream can be closed in one or both directions with nexus::quic::stream::shutdown() and nexus::quic::stream::close().

Writes may be buffered by the stream due to a preference to send full packets. Buffered stream data can be flushed, either by calling nexus::quic::stream::flush() manually or by shutting down the stream for write.

## Synchronous and Asynchronous

For each potentially-blocking operation, both a synchronous or asynchronous version of the function are provided. The asynchronous function names all begin with `async_`, and attempt to meet all "Requirements on asynchronous operations" specified by asio.

However, QUIC requires that we regularly poll its sockets for incoming packets, respond with acknowledgements and other control messages, and resend unacknowledged packets. The Nexus client and server classes issue asynchronous operations for this background work, and expect their associated execution context to process those operations in a timely manner - for example, by calling `asio::io_context::run()`.

This is unlike the asio I/O objects you may be familiar with, which can be used exclusively in the synchronous blocking mode without requiring another thread to process asynchronous work.

## Exceptions

The library should be useable with or without exceptions, so both a throwing and non-throwing version of each function is provided. Their signatures are the same, except the non-throwing version takes a mutable reference to error_code as an additional parameter.

## Thread Safety

Global init/shutdown is not thread-safe with respect to other classes.

All engine operations can be considered thread-safe. The lsquic engine instance is not re-entrant, so an engine-wide mutex is used to serialize access to the engine and its related state. This mutex is held over all calls into the lsquic engine, including its calls to the callback functions we provide. No blocking system calls are made under this mutex, as lsquic does no i/o of its own.
