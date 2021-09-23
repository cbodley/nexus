# TODO

## SSL

* client side verification

## Client

* connection::handshake() to wait for handshake to complete?

## QUIC

* add interfaces to interact with flow control, stream limits, etc
* stream prioritization
* push promises
* unidirectional streams?
* session resumption
* connection migration

## Async

* decide on object lifetime of stream/connection/engine state objects; is reference counting absolutely necessary?

## Boost vs. Standalone Asio

* add #define to choose (along with std:: vs. boost::system::error_code)
* then go finish std::net so we can use that instead
