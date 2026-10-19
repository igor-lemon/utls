# utls for tls-forge

A fork of [bogdanfinn/utls](https://github.com/bogdanfinn/utls)
v1.7.8-barnius (`2557d0b9370fb665343b86dcac1c0e44b48e715c`, the commit Go's
module proxy holds for the tag), on the branch `tls-forge`, for
[tls-forge](https://github.com/Sec-CH-Lemon/tls-forge).

- The module is `github.com/igor-lemon/utls`: every import of
  `github.com/bogdanfinn/utls` is renamed, so that tls-forge and its forks of
  fhttp, tls-client, quic-go-utls and websocket can require it without a
  `replace`, which `go install` refuses and a library's users never see. On
  another base:

      grep -rl github.com/bogdanfinn/utls --include='*.go' --include=go.mod . |
        xargs perl -pi -e 's#github\.com/bogdanfinn/utls#github.com/igor-lemon/utls#g'

  then `git diff --name-only -- '*.go' | xargs gofmt -w`, which puts the
  renamed imports back in order.

- At the base, upstream as here, `go vet ./...` is clean and `go test ./...`
  passes.

## Patches

- **A parrot's second flight in as few records as it fits in**
  (`handshake_client_tls13.go`, `Conn.writeHandshakeRecord`,
  `Conn.writeFlight` in `u_conn.go`): a TLS 1.3 client handshake driven by a
  `UConn` of any ClientHelloID but HelloGolang packs the messages of its
  second flight (its EncryptedExtensions of ALPS, Certificate,
  CertificateVerify, Finished) one after another and writes them together,
  under the handshake's keys, in records of as many bytes as a record
  carries, as BoringSSL and NSS write a flight; Go's own client and
  HelloGolang write a record each, as crypto/tls does. Chrome 155 sends its
  EncryptedExtensions and Finished in one record (tls-forge's bench, every
  `alps-*` scenario that negotiated ALPS, measured four times); utls wrote
  them in two. Over QUIC it changes nothing: `quicWriteCryptoData` already
  joins a level's writes. Tests in `u_flight_test.go` (a parrot with a
  certificate, with a chain past a record, without one; HelloGolang; Go's
  client; the keys the flight goes under); 8 mutants, all killed.
