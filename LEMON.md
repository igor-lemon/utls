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

- `Conn.Close` without close_notify when the policy says `"tls.close_notify":
  false` (`u_chrome_policy.go` `sendsCloseNotify`; `behavior` registers it with
  the `tcp.keepalive*`, `h1.idle_*`, `h2.idle_connection_timeout_ms` and
  `h2.close_on_goaway` fields the other forks read). Chromium's
  `SSLClientSocketImpl::Disconnect` calls no `SSL_shutdown`: Chrome 155 ended
  every connection with the TCP FIN alone, also after the server's
  close_notify (measured 2026-10-23). Absent, Close sends the alert as
  before; `CloseWrite` always does, being asked to. Test
  `TestCloseSendsCloseNotifyAsThePolicySays` (TLS 1.3 and 1.2, absent, true,
  false, CloseWrite), which fails with the check taken out (24 and 23 bytes
  written).

- **No record of a client after one whose write failed**
  (`Conn.writeRecordLocked` and `Conn.sendAlertLocked` in `conn.go`,
  `failedWrite` in `u_conn.go`): a record takes its sequence number, and with
  it its nonce, when it is encrypted, however few of its bytes the socket
  then takes, so the peer cannot read a record after it (RFC 8446 §5.3).
  `writeRecordLocked` keeps the error of a write that failed in
  `c.utls.failedWrite`, and a client writes no record of any type after it:
  no alert, close_notify included, no TLS 1.2 renegotiation's handshake, no
  answer to a KeyUpdate. `sendAlertLocked` refuses before it, so that an
  alert that never went out says the write's error and leaves no local error
  of its own in `c.out.err`; Close only closes the connection. Every
  client's, whatever its Config: a rule of the record layer, not a profile's
  choice; a server is crypto/tls's. It came with net-fp-server's TLS-039
  (2026-10-21): tls-forge's close_notify at an HTTPS proxy's teardown went
  out with sequence 10 where 9 was expected; which write failed there was
  not traced. A first, uncommitted version refused an alert whenever
  `c.out.err` was set, which an alert that went out sets too (the local
  error of a fatal one, and of the `no_renegotiation` warning):
  `TestWarningAlertFlood` hung, all but the first of its 33 warnings never
  sent, and `TestRenegotiationRejected` and `TestRenegotiateTwiceRejected`
  lacked the close_notify their recordings end with (2026-10-24). Tests:
  `TestOnlyAFailedWriteStopsTheAlertsAfterIt` (TLS 1.3 and 1.2: an
  application write that failed having sent nothing, and seven bytes, then
  Close; a warning and a fatal alert written, each followed by the
  close_notify; an alert whose own write failed; a close_notify whose write
  failed, then an alert refused with the write's error while `c.out.err` is
  empty; a server), `TestAClientWritesNoRecordAfterAFailedWrite` (a KeyUpdate
  answered, and after a failed write not, the keys staying and what came
  after it read all the same; a TLS 1.2 server's HelloRequest answered with
  a ClientHello, and after a failed write with the write's error at once);
  10 mutants, all killed (the first version's check among them, by the
  flood, the two recordings and the written alerts).

- `behavior` registers the `h2.preface_ping_*` fields fhttp reads for its
  connection's own PING (Chrome's SpdySession::MaybeSendPrefacePing and
  CheckPingStatus): `idle_ms` and `hung_ms` (at most 2^32-1), `first_id`
  (any uint64), `failed_goaway_code` (2^32-1), `failed_goaway_debug` (text of
  at most 1024 bytes) and `failed_retries` (at most 16). `first_id` and
  `hung_ms` need `idle_ms`; a nonzero `idle_ms` needs `first_id`; the code
  and the retries need `hung_ms`; the debug data the code. The cases are
  tls-forge's `TestPrefacePingPolicyIsTypedAndCoherent`.
- `behavior` registers `h2.priority_dependency` (`root` or `nearest-weight`),
  which fhttp reads for the stream a request's HEADERS depend on; held by
  tls-forge's `TestPriorityDependencyIsAChoiceOfTheEngines`.
- `behavior` registers how an answer a request goes on from unread is let go
  of, which tls-forge reads (its `unread.go`, over fhttp's `DrainBody` and
  `AwaitBody`): `h1.`/`h2.` `dropped_body`, `auth_body`, `restart_body` and
  `preflight_body`, each `read`, `close`, `drain`, `read-all` or
  `first-bytes`; `http.drain_bytes` (at most 1 GiB) and `http.drain_ms`
  (2^32-1), required with a `drain` and refused without one;
  `http.first_bytes_ms` (2^32-1), likewise with a `first-bytes`; and
  `h1.unread_grace_us`/`h2.unread_grace_us` (at most 10 s), refused for a
  protocol none of whose answers is let go of by `close`, `drain` or
  `first-bytes`. The cases are tls-forge's
  `TestUnreadAnswerPolicyIsTypedAndCoherent`.
