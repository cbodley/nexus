# TODO

## Error Handling

* on connection error, fail pending stream operations too
* error_condition for connection errors so callers can tell whether an error is fatal to the connection

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
