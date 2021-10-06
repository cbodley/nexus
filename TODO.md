# TODO

## QUIC

* stream prioritization
	- lsquic_stream_set_priority/lsquic_stream_set_priority for quic
	- lsquic_stream_get_http_prio/lsquic_stream_set_http_prio for h3
* session resumption
* push promises
* unidirectional streams?
* connection migration

## connection

* going_away() for h3 connections
* expose connection::close() vs. abort()? maybe just use abort() in destructor?
* expose lsquic_conn_n_avail_streams()?
* expose lsquic_conn_n_pending_streams/lsquic_conn_cancel_pending_streams?

## UDP

* send packets with IP_PKTINFO
* use sendmmsg()/recvmmsg() to reduce the number of system calls

## Async

* decide on object lifetime of stream/connection/engine state objects; is reference counting absolutely necessary?
* maybe remove all synchronous interfaces and locking?

## Boost vs. Standalone Asio

* add #define to choose (along with std:: vs. boost::system::error_code)
* then go finish std::net so we can use that instead
