# TODO

## QUIC

* stream prioritization
	- lsquic_stream_set_priority/lsquic_stream_set_priority for quic
	- lsquic_stream_get_http_prio/lsquic_stream_set_http_prio for h3
* session resumption
* push promises
* connection migration

## connection

* expose lsquic_conn_n_avail_streams()?
* expose lsquic_conn_n_pending_streams/lsquic_conn_cancel_pending_streams?
* option to pre-allocate stream_impls based on negotiated limits?
* otherwise save closed streams and recycle them

## UDP

* send packets with IP_PKTINFO
* use sendmmsg()/recvmmsg() to reduce the number of system calls

## h3

* allocator support for fields

## Async

* maybe remove all synchronous interfaces and locking?
* template everything on Executor type? difficult because it requires a lot more of the implementation in header files, and lsquic dependency is hidden from headers

## Boost vs. Standalone Asio

* add #define to choose (along with std:: vs. boost::system::error_code)
* then go finish std::net so we can use that instead

## test coverage

* stream and connection is_open()
* connection errors from stream interfaces
* connection_impl lifetime vs handlers
* socket_impl lifetime vs handlers

## possibly-interesting stuff not supported by lsquic

* sending application errors via RESET_STREAM or CONNECTION_CLOSE
* receiving application errors from RESET_STREAM
* generic unidirectional streams
* getting a callback after shutdown(1) once all data is acked, so no async_shutdown(1). this only works for close via es_delay_onclose
