# TODO

## QUIC

* stream prioritization
* session resumption
* push promises
* unidirectional streams?
* connection migration

## UDP

* send packets with IP_PKTINFO
* use sendmmsg()/recvmmsg() to reduce the number of system calls

## Async

* decide on object lifetime of stream/connection/engine state objects; is reference counting absolutely necessary?

## Boost vs. Standalone Asio

* add #define to choose (along with std:: vs. boost::system::error_code)
* then go finish std::net so we can use that instead
