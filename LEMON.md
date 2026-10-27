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

- **Bounded content-coding policy for the unpublished engine 1**:
  `http.max_content_codings`, `http.content_coding_overflow` and
  `http.ignored_content_codings` are typed JSON choices. The decoder-chain
  safety ceiling is 64; it is not a browser default. Chromium's lower limit
  and identity handling are explicit migration additions measured on Chrome
  156, while generic compatibility data retains its explicit normalization.
  `legacy-chromium.json` and `legacy-generic.json` stay unchanged; new choices
  are in separately identified `engine1-*-additions.json`. Partial/null,
  out-of-range and unsupported policies are rejected. Tests in
  `behavior/content_codings_test.go`.

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
  (any uint64), `failed_goaway_code` (2^32-1) and `failed_goaway_debug`
  (text of at most 1024 bytes). `first_id` and `hung_ms` need `idle_ms`; a
  nonzero `idle_ms` needs `first_id`; the code needs `hung_ms`; the debug
  data the code. The cases are tls-forge's
  `TestPrefacePingPolicyIsTypedAndCoherent`. (`failed_retries` went on
  2026-10-24 for `h2.retries` with `ping-failed`, below.)
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
  `TestUnreadAnswerPolicyIsTypedAndCoherent`; 9 mutants, all killed.
- `behavior` registers when a request goes again, which fhttp reads (its
  `http2/resend.go` and `transport.go`): `h2.retries` (at most 16) with
  `h2.retry_errors` (each of `refused-stream`, `goaway-no-error`,
  `goaway-error`, `ping-failed` once, the last needing
  `h2.preface_ping_hung_ms`), `h2.retry_delay_ms` (at most 60000, needing
  `h2.retries`), `http.connection_error_retries` (at most 1000) with
  `http.connection_error_methods` (`any` or `idempotent`), which need
  `h2.retries`, and `h1.request_timeout_resend`. The cases are tls-forge's
  `TestRetryPolicyIsTypedAndCoherent`; 13 mutants, all killed.
- `behavior` registers what a request is given and what a browser sent,
  which tls-forge reads (its `typed.go`, `sent.go`, `browser.go`):
  `headers.without_context` (`as-given` or `typed-navigation`, the latter
  needing `headers.browser_context` and `@given`), `@given` in
  `headers.navigation_order`, `form_order`, `redirected_order` and
  `restarted_order` (in all four or none, once each), `headers.given_order`
  (`bytes` or `as-given`) and `headers.given_redirect_drops` (field names in
  lower case), each needing `@given`; `h2.urgency_weights` (eight weights of
  at most 255), `headers.sent_priority` (`destination=Priority`, each
  destination in lower case once, needing the weights) and
  `headers.renderer_origin_dests`. The cases are tls-forge's
  `TestGivenFieldsPolicyIsTypedAndCoherent`; 29 mutants, all killed.
- ECH with an inner hello of the profile's own (`u_ech_spec.go`, 2026-10-24,
  for tls-forge's ECH from DNS HTTPS records): a config whose policy says
  `tls.ech` offers ECH as Chrome 155's BoringSSL does, measured against a
  server that opened every inner hello: the outer the spec's to the config's
  public name, its ECH extension the real one, no `pre_shared_key`; the inner
  made of the outer's bytes (`innerOf`): the extensions `tls.ech_inner_own`
  names written for it in the outer's order, the rest of the outer's but
  `tls.ech_inner_omitted`'s and the padding by reference, a session's PSK
  last with binders over the inner, suites and versions of
  `tls.ech_inner_min_version` and up, the outer's session ID, its own
  random, padded as RFC 9849 says to `tls.ech_padding_block`; config and
  suite picked by the policy's KEMs, KDFs and AEADs as BoringSSL picks them,
  public names as BoringSSL takes them; after a HelloRetryRequest both again,
  the inner random kept, no enc (`helloRetrySpecECH`, a `specECH` branch of
  `processHelloRetryRequest` after its early-data step, whose sending is
  `sendHelloRetried` now; the cookie is `cookieForRetry` for both paths). A
  refusal is checked against the public name (`c.serverName`: it was the
  config's `ServerName`, the real one), and a server that answers a spec
  offer in TLS 1.2 refused it (`ECHRejectionError{}` after an ech_required
  alert): the outer offers TLS 1.2 as the spec does (`supportedVersions`).
  `behavior/ech.go` registers and validates the keys. Tests
  `u_ech_spec_test.go` (Chrome's 12 inner hellos made byte for byte from
  their outers, `testdata/chrome155-ech-hellos.json`; handshakes against
  crypto/tls's server) and `behavior/ech_test.go`; 101 mutants, all killed.
  `dns.resolver` (2026-10-25, `system` or `built-in`: who asks a direct
  connection's names, the machine's resolver or a client of tls-forge's own,
  as Chrome's built-in DNS client asks them) is registered with them;
  `dns.https_records` needs `built-in`, as a record asked apart from
  addresses a cache answers comes after the wait. 5 mutants, all killed.
- `behavior` registers `dns.https_h3` (2026-10-25), which sends a direct
  https request whose name's HTTPS record names h3 over HTTP/3 as Chrome's
  DNS ALPN job sends it, with `quic.tcp_wait_cold_ms`, `_broken_ms`,
  `_rtt_percent`, `_default_ms`, `_extra_ms` and `_max_ms` (how long TCP
  waits behind QUIC), `quic.tcp_waits_with_connection`, `quic.broken_ms`,
  `_doublings` and `_max_ms`, `quic.broken_recent_max`,
  `quic.server_rtts_max` and `http.unused_idle_connection_timeout_ms`,
  held together by `behavior/h3dns.go` (`dns.https_h3` needs
  `dns.https_records`, `quic.enabled` and every key, none is set without it,
  a first break no longer than the longest). tls-client's `dnsh3.go` and
  `quicstate.go` read them. Test `behavior/h3dns_test.go`; 14 mutants, all
  killed.
- `behavior` registers a QUIC client's handshake as Chrome 155's (2026-10-25):
  `quic.packet_numbers` (`shared`: one counter for the three spaces),
  `quic.first_packet_number`, `quic.packet_number_length` (`window`,
  quiche's `UpdatePacketNumberLength`), `quic.pto_skip`, `quic.pto_probes`,
  `quic.pto_*` of the probe timeout, `quic.alarm_slack_ms`,
  `quic.handshake_idle_timeout_ms`, `quic.handshake_timeout_ms`,
  `quic.handshake_ack_timer_ms`, `quic.idle_close` with its code, reasons and
  `quic.undecryptable_level_names` (kind `quic-reason`: `QUICReason` writes
  quiche's `QuicTime::Delta`), `quic.initial_layout` (`chaos`, with
  `quic.chaos_*`), `quic.padding_position`, `quic.connected_socket`, held
  together by `behavior/quic.go`. And ALPS for HTTP/3: `quic.alps_protocols`
  with 17613 or 17513 kept in `quic.preserve_extensions` (which refused both
  as "HTTP3 ALPS bootstrap API is unavailable"), `h3.alps_reader`,
  `h3.alps_origin_frames`, `h3.alps_close_*`, `h3.alps_errors`,
  `h3.peer_settings`, `h3.settings_*`, `quic.close_early_application`
  (`behavior/alps.go`: kinds `template` and `templates`, a set of templates by
  condition, read in one pass that refuses a key said twice; `Template`).
  quic-go-utls and tls-client read them. Tests `behavior/quic_test.go`,
  `behavior/alps_test.go`; 65 mutants, all killed.
- A server's side of ALPS (2026-10-25, `u_alps_server.go`), for uTLS's tests
  and tls-forge's bench of servers that give a client ALPS: a server with
  `Config.ApplicationSettings` for the protocol ALPN chose sends them in its
  EncryptedExtensions under the codepoint the client offered (the new one when
  it offered both), reads the client's own from the client's
  EncryptedExtensions before its Certificate and Finished, and only then
  works out the Finished it expects and sends its tickets (it precomputed
  them without the client's EncryptedExtensions, which failed every
  handshake of ALPS with decrypt_error). The client looked up its own
  settings by the ServerHello's ALPN, which TLS 1.3 leaves empty; it takes
  `clientProtocol` now. Tests `u_alps_server_test.go` (TCP and QUIC, the
  codepoints, resumption, a client certificate asked for).
- `quic.retry_over_tcp` (2026-10-25, `behavior/h3dns.go`), one of the keys
  `dns.https_h3` needs: a request its QUIC connection failed before its
  answer goes again over TCP (tls-client).
- `Conn.Peek` and `UConn.Peek` (2026-10-25, `u_peek.go`): BoringSSL's
  `SSL_peek`, which Chromium calls on each of its connections once its
  handshake is done, read or not (`SSLClientSocketImpl::DoPeek`): what the
  server sends after the handshake is read and its messages handled (every
  session ticket of a record cached as it comes) until there is application
  data, left for Read, or an error, the one a Read would meet; a false start
  is finished first. tls-client peeks at a TCP connection that waits unused
  for a request. Tests `u_peek_test.go`; 10 mutants, all killed.
- `behavior` registers following Alt-Svc as Chrome 155 does (2026-10-25,
  `behavior/altsvc.go`): `quic.alt_svc` with `quic.alt_svc_user_ports`
  (`enable_user_alternate_protocol_ports`), `quic.alt_svc_remote_hosts`
  (`allow_remote_alt_svc`) and `quic.alt_svc_tcp_waits_with_h2`
  (`delay_main_job_with_available_spdy_session`), all said with it and
  none without; it needs `dns.https_h3`, whose race an alternative's QUIC
  connection goes through. tls-client's `altsvc.go` and `dnsh3.go` read
  them. Test `behavior/altsvc_test.go`; 15 mutants, all killed.
- **The lock of the key logs let go of on every return**
  (`Config.writeKeyLog` in `common.go`, 2026-10-25): bogdanfinn's
  `SSLKEYLOGFILE` change (410eb0a, 2024) returned from a write to the
  Config's `KeyLogWriter` that failed, and from a file `SSLKEYLOGFILE` names
  that could not be opened, written or closed, with `writerMutex`, the one
  lock of every key log of the process, still held: the handshake failed
  with the error, as crypto/tls's does, and every later one that wrote its
  secrets, of any Config, waited for it for good, its context's deadline
  included (tls-forge's `go test -count=2 .` hung so in its key log tests).
  A `defer` lets go of it now. Tests `u_key_log_test.go`:
  `TestAKeyLogThatFailedHoldsUpNoLaterHandshake` (TLS 1.3 and 1.2: a writer
  that fails, then one that works; a file that cannot be opened, then one
  that can, which holds the lines of both ends; each handshake given ten
  seconds, so that the old code fails in seconds) and
  `TestKeyLogsAreWrittenOneAtATime` (a handshake whose write is held keeps
  another's from writing until it is let go of); 7 mutants, all killed, and
  one equivalent (the `defer` before the `Lock`).
- `behavior` registers a QUIC client after its handshake as Chrome 155's
  (2026-10-26): `quic.ecn` (`ect0`, quic-go's validated ECT(0), or `none`),
  `quic.mtu_probes` (`search`, quic-go's DPLPMTUD, or `none`),
  `quic.connection_id_change` (`after-handshake`, quic-go's, or
  `when-retired`), `h3.control_stream` (`after-handshake` or
  `with-finished`), `h3.peer_reset` (`frame-error`, quic-go's, or
  `read-side`); quic-go-utls reads them. Test `behavior/quic_test.go`; 16
  mutants, all killed.
- `behavior` registers how an HTTP/3 client puts its writes in packets as
  Chrome 155's (2026-10-26): `h3.request_writes` (`as-written`, quic-go's,
  or `one-flush`: a request's PRIORITY_UPDATE, QPACK encoder instructions
  and HEADERS under one flush) and `h3.qpack.decoder_writes` (`as-written`
  or `opportunistic`: the QPACK decoder's instructions only in packets sent
  for something else); quic-go-utls reads them. Test
  `behavior/bundling_test.go`; 10 mutants, all killed.
- `behavior` registers how a QUIC client acknowledges a long download as
  Chrome 155's (2026-10-26; quiche's `QuicReceivedPacketManager` and
  `QuicConnection` at Chrome 155's DEPS revision `0b2bc13f`):
  `quic.ack_decimation_after`, `quic.ack_decimation_packets`,
  `quic.ack_decimation_rtt_percent` and `quic.ack_decimation_min_ms` (all
  four or none: every tenth packet from the peer's first plus 100, a quarter
  of the least round trip, 1 ms at least), `quic.ack_gap_packets` (each of
  the packets after a gap at once, while the highest range holds no more),
  `quic.ack_sent_after` (`batch`, quic-go's, or `packet`), `quic.ack_only_max`
  and `quic.ack_only_frame` (`ping`, quic-go's, or `max-data`; both or
  neither), `quic.ack_alarm_slack_percent` (needs `quic.alarm_slack_ms`);
  quic-go-utls reads them. Test `behavior/acks_test.go`; 27 mutants, all
  killed.

- Unreleased engine1 cookie-prefix policy (2026-10-27): `cookie.prefixes`
  contains explicit ASCII prefixes, case matching, nameless-value rejection
  and required secure/http-only/host-only/root-path attributes. Strict nested
  validation rejects unknown, repeated, missing and invalid fields before I/O.
  Engine1 additions carry Chrome156/macOS observations; frozen legacy source
  JSON remains unchanged. A hard ceiling of 64 rules and 256 prefix bytes
  bounds the generic capability. Other browsers/builds are not newly measured.

- Unreleased engine1 PSK+HRR (S03, 2026-10-27): real PSK extensions receive
  the retried identities/ages and binders; the binder is recomputed after
  marshalling actual profile-shaped ClientHello2 over message_hash(CH1)||HRR.
  Reset the extension's cached length when a hash-incompatible PSK is removed.
  Unsupported opaque/fake PSK retry implementations fail explicitly. The
  separate real-ECH helloRetrySpecECH path is unchanged. Test
  u_psk_hrr_test.go uses a standard-library TLS1.3 server, P-256/P-384-only
  and X25519, six fresh connections with server-confirmed resumption. The
  owning product retains actual Chrome156/macOS cohorts, raw packets/secrets
  privately and an independent HMAC/HKDF binder oracle with negative controls.

- A3/S06 real-ECH False Start (2026-10-27): RFC9849 forbids TLS1.2 False
  Start after an actual ECH offer. Check the negotiated profile ECH context,
  not the presence of a GREASE ECH extension. The held-Finished regression
  proves rejection waits and authenticates the server Finished; a corrupted
  Finished cannot yield ECHRejectionError. Ordinary/GREASE False Start tests
  retain their measured behavior. Shares the existing unpublished engine1.

- A3/S06 compressed certificates (2026-10-27): enforce the existing engine
  Certificate-message ceiling before decoder creation/allocation. Read at most
  declared length+1 and require exact output length, rejecting both a short
  stream and a valid Certificate prefix with extra output using bad_certificate.
  Codec failures retain the profile's certificate_decode_alert (Chrome50).
  Zstd uses one worker and the same engine ceiling for its memory/window.
  This safety ceiling is not a browser default or a new profile value.
  Brotli/zlib/zstd length controls, a bounded allocation subprocess and actual
  encrypted UConn alert tests are in u_compressed_cert_security_test.go.

- A3/S06 CVE-2025-61730 / GO-2026-4340: Go1.26.10's read-key guard rejects
  buffered handshake bytes at every read secret change, including KeyUpdate;
  a server also rejects extra ClientHello bytes before HRR. Set write keys
  first when both levels change, so errors use the right alert protection.
  Old QUIC-only checks no longer stand in for the generic guard. Upstream
  trailing-message/duplicate-HRR regressions plus a profile-shaped UConn
  case live in u_read_keys_security_test.go. Valid flight/KeyUpdate/HRR and
  real-ECH replay tests retain their original bytes. No selectable browser
  behavior or JSON value changed; this is protocol integrity in engine1.

- A3/S06 CVE-2025-68121 / GO-2026-4337: revalidate cached chains against
  current time and roots before client or mTLS server resumption, in both
  TLS1.2 and TLS1.3, as Go1.26.10 does. Evict invalid client cache entries
  and perform a fresh handshake. Explicit existing insecure time/name options
  retain their original semantics; this is certificate integrity, not a JSON
  default. Ported expiry/RootCAs/GetConfigForClient+ClientCAs tests and a real
  profile UConn root-replacement control are retained. One positive ECH test
  now supplies its test CA to its second Config too; none of its outer/inner
  identity assertions was weakened. Full hello/record replay suite passes.

- A6: invalid H3 GREASE length diagnostics identify the behavior field, index,
  actual value/count and existing resource bound. The supported ranges and
  browser values are unchanged; no new policy primitive or default.
