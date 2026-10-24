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

- Under tls-forge's `go.work` (`go 1.26.9`) the test binary takes Go 1.26's
  GODEBUG defaults, `cryptocustomrand` among them: crypto/ecdh, crypto/ecdsa
  and crypto/rsa pass over a `Config.Rand` of the caller's, so the client's
  key share and the server's keys no longer come from `zeroSource` and the
  recorded handshakes in `testdata/` do not match (`write mismatch`). 64
  tests failed so, at the base `54318ca` as with this branch's tree, and
  none with `GOWORK=off`, which takes utls's own `go 1.24` (2026-10-24).
  `runMain` sets `GODEBUG=cryptocustomrand=1` before any test, as Go 1.26's
  crypto/tls does in its own; a toolchain before 1.26 passes over the
  setting; taken out, the 64 fail again. Nothing outside the tests changes:
  a Config's keys are drawn as crypto/tls 1.26 draws them. Both ways pass:

      GOWORK="$PWD/../../tls-forge/go.work" go test ./... -count=1
      GOWORK=off go test ./... -count=1

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

- **False Start, as Chrome's** (`Config.FalseStart`, `u_false_start.go`,
  `clientHandshakeState.readServerFlight` and `complete` in
  `handshake_client.go`, `falseStarted` in `Conn`'s and `UConn`'s
  `handshakeContext`, `Read` and `Write`): a client set to it whose TLS 1.2
  handshake allows it, on the connection's first handshake, a full one, with
  an ECDHE key exchange, an AEAD and a protocol ALPN negotiated
  (`falseStarts`, BoringSSL's `can_false_start`), returns from Handshake
  once its Finished is out and may write; the first Read reads the server's
  session ticket, ChangeCipherSpec and Finished (`finishFalseStart`, under
  the handshake's lock and `c.in`), checks the Finished, keeps the session,
  and only then reads application data. A Finished that does not check ends
  the connection, Handshake says so from then on, and nothing more is sent.
  Until it is read, ConnectionState says the handshake is not complete and
  keying material cannot be exported. Off by default: Go's client and a
  parrot not set to it wait as before. Chromium sets
  SSL_MODE_ENABLE_FALSE_START for every connection; Chrome 155.0.8059.85 was
  measured on 2026-10-19 sending its request before the server's Finished
  with ECDHE and AES-GCM or ChaCha20-Poly1305 over h2 and http/1.1, and
  waiting without ALPN, with a CBC suite and with an RSA key exchange. Tests
  in `u_false_start_test.go` (a Conn and a Chrome parrot each: where it false
  starts and where it waits, a Finished that does not check, reads and writes
  while it finishes, two handshakes at once, the session resumed, the rule
  by case); 27 mutants, 26 killed, and one equivalent (`finishFalseStart`'s
  first look at `falseStarted` before the lock, which saves taking it).
