# utls for tls-forge

A fork of [bogdanfinn/utls](https://github.com/bogdanfinn/utls) v1.7.8-barnius
(`2557d0b9370fb665343b86dcac1c0e44b48e715c`, the commit Go's module proxy
holds for the tag), its patches laid over v1.8.2-barnius since 2026-11-10
(below), on the branch `tls-forge`, for
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

## The branch: bogdanfinn's release, then the patches (2026-11-10)

`git log --first-parent v1.8.2-barnius..tls-forge` lists the branch as it is
laid out: bogdanfinn's v1.8.2-barnius (`40d542347353`), then "Rename the
module ...", the rename above, made by a script (the five forks' module paths
in every Go file and go.mod, imports sorted), then this fork's patches, one
commit a change, oldest first, as this file tells them. A merge on top, `-s
ours`, joins the branch's earlier head: the branch only ever moves forward,
every commit a published pin names stays in it, and the merge's tree is the
last patch's.

On 2026-11-10 the history to then (80 patches written over v1.7.8-barnius, and
the merge of v1.8.2-barnius of 2026-11-09) was laid over v1.8.2-barnius so:
each patch cherry-picked over the renamed release, a conflict resolved toward
the merge's tree, and what the merge itself had resolved put into the patch it
belongs to (the section on v1.8.2-barnius says what was decided). The last
patch's tree is the merge's, byte for byte, but for this section. Every commit
of the series builds and passes go vet (Go 1.27.3, GOWORK=off).

To take another release of bogdanfinn's, with tls-forge's
`scripts/fork_sync.py`, in a clone (this checkout is not touched):

    python3 scripts/fork_sync.py start ../forks/utls vX.Y.Z --work /tmp/utls-sync
    # a conflict stops it: resolve it, git add, then
    python3 scripts/fork_sync.py continue --work /tmp/utls-sync
    # what has to change for it to build, made in the clone, goes into the
    # patch whose lines it touches (or the one --to "SUBJECT=PATH" names)
    python3 scripts/fork_sync.py absorb --work /tmp/utls-sync
    python3 scripts/fork_sync.py check --work /tmp/utls-sync --with ...
    python3 scripts/fork_sync.py finish --work /tmp/utls-sync -m "Patches laid over vX.Y.Z"

then `git merge --ff-only` of the clone's head on this branch. A conflict that
only moves an import the rename changed settles itself; git rerere keeps the
others; go.mod is merged module by module (the higher version) and go.sum by
union. The forks go in tls-forge's order: utls, fhttp, websocket and
quic-go-utls, tls-client; `check --with` builds a fork against the new series
of the ones before it.

## Upstream v1.8.2-barnius merged (2026-11-09)

bogdanfinn's v1.8.2-barnius (`40d5423`, one squash of refraction-networking's
master and crypto/tls of Go 1.25 to 1.27; its history is
`rebase-upstream-master`, `4c28bd0`, the same tree) is merged into this
branch. The module now says `go 1.27`: it imports `crypto/mldsa` (Go 1.27) and
`crypto/hpke` (Go 1.26). Where both sides had made the same change, one is
kept; where they differ, as follows.

- **Same fix twice**: `anyValidVerifiedChain` (CVE-2025-68121) was this
  fork's back-port and upstream's, byte for byte: one copy left, and the
  second resumption check in `loadSession` with it. `setReadTrafficSecret`
  (CVE-2025-61730) takes upstream's `locked` argument (its CVE-2026-32283
  fix); `handleKeyUpdate` keeps this fork's order, the read keys first and then
  the answer, so `tls.defer_key_update`'s early return still updates them.
  The HRR binders stay this fork's (281f37f, over the profile-shaped
  ClientHello2); upstream's `UpdateOnHRR` call after it, which would bind
  them a second time, is taken out. The Go security tests this fork had
  ported (`u_read_keys_security_test.go`, `u_resumption_trust_security_test.go`)
  are upstream's own now; the parrot's case is kept as
  `TestAParrotRefusesAServerHellosTrailingMessage`.
- **HPKE**: upstream seals ECH with Go's `crypto/hpke`, which keeps the KEM's
  shared secret to itself. `newECHSender` (`u_ech_sender.go`) seals a
  DHKEM(X25519) offer, the KEM browsers offer, with `internal/hpke` (kept, with
  `internal/hkdf` for it), so the key log still writes `ECH_SECRET`; another
  KEM goes through `crypto/hpke` and writes no ECH lines. The profile's own
  offer (`u_ech_spec.go`) is as it was.
- **ALPN with ECH**: upstream leaves `Config.NextProtos` alone when ECH configs
  are given ("Hide ALPN in ECH"); an offer of the profile's own
  (`offersSpecECH`) sets them as before, as its inner hello carries the
  outer's ALPN (without it a TLS 1.2 server's ALPN was refused).
- **Certificate compression**: this fork's decoder stays (the engine's
  Certificate limit, `brotliWindowFor`, andybalholm/brotli 1.2.7, not
  upstream's go-brrr). Upstream's refusal of compressed bytes after the
  stream is taken for zlib and zstd; brotli refuses them itself. Upstream's
  tests' large certificates are cut to fit under the limit, and its brotli
  test compresses with andybalholm/brotli.
- **Key share reuse**: this fork's `ReuseWith` (74878a2, what tls-forge's
  descriptors say) and upstream's markers (`ReuseHybridAndClassicalKeyShares`)
  both work; MLKEM1024 shares come with upstream.
- **ApplyPreset** works on a deep copy of the spec (upstream 98f1bbc): the
  fork's tests read the UConn's extensions, not the spec's.
- **trust_anchors** (0xca34) is read into upstream's `TrustAnchorsExtension`
  (the fingerprinter, `ExtensionFromID`), not a `GenericExtension` of its
  bytes: tls-forge, which orders the IDs by its profile
  (`tls.trust_anchor_order`) in `profile.Spec`, has to take them from it when
  it requires this utls; tls-client's QUIC hello keeps it.
- A malformed handshake message (an empty ServerHello) is answered with
  decode_error (50), as BoringSSL answers it, where unexpected_message (10)
  was: Go's own change, not measured against Chrome.
- QUIC clamps the minimum version to TLS 1.3 instead of refusing a lower
  `MinVersion` at Start; key log write errors say `tls: KeyLogWriter:`;
  `GetGREASEVersion` draws a real reserved version (tls-forge's TP 17 comes
  from quic-go-utls). SSLKEYLOGFILE stays ignored (A4).
- The tests this fork wrote against crypto/tls's fixtures before Go 1.26
  regenerated them get them from `u_legacy_fixtures_test.go`. `behavior`'s
  JSON syntax cases hold the key, not encoding/json's words, which Go 1.27
  changed.

`GOWORK=off GOTOOLCHAIN=go1.27.3 go test ./...` passes, `-race` too.

## Patches

- **Two sessions a key, as Chromium's caches keep (review 2026-11-05, 1.5)**:
  `NewLRUClientSessionCacheOf(capacity, perKey)` keeps up to perKey sessions
  a key, as `SSLClientSessionCache::Entry` (net/ssl, 156) and quiche's
  `QuicClientSessionCache::Entry` keep two: a single-use (TLS 1.3) session
  put where another is moves that one behind it, a reusable one takes its
  place, and Take takes the newest. `NewLRUClientSessionCache` keeps one, as
  before. The registry has `tls.session_cache_sessions_per_entry` and
  `quic.session_cache_sessions_per_entry` (1..16) for tls-client to read.
  Before, a server's second ticket replaced its first, and a second
  connection at once went through a full handshake. `u_session_cache_test.go`;
  7 mutants killed.

- **TLS 1.3's ALPN alert the profile's (review 2026-11-05, 1.4)**: a
  protocol a server says it chose that the client did not offer is alerted
  with `tls.alpn_mismatch_alert` in TLS 1.3 as in TLS 1.2 (BoringSSL's
  ext_alpn_parse_serverhello: illegal_parameter of both), where crypto/tls
  sent no_application_protocol whatever the profile said. A QUIC server that
  chose none still gets no_application_protocol. `testingOnlyServerALPN`
  makes a TLS 1.3 server say a protocol (`u_alpn_alert_test.go`, over TCP:
  a pipe holds the server's flight); 3 mutants killed.

- **ServerHello extensions held to BoringSSL's (review 2026-11-05, 1.3)**:
  `tls.validate_server_hello_extensions` has `validateServerHello`
  (u_chrome_policy.go, from `readHandshake` before the message is read)
  refuse what BoringSSL 2ea3200c refuses: of TLS 1.3 all but
  supported_versions, a key_share where shares were sent and pre_shared_key
  where one was offered, each once; of a HelloRetryRequest all but cookie,
  key_share, supported_versions and ECH's confirmation; of TLS 1.2 what the
  client did not offer, GREASE and padding, and one twice (the malformed
  alert, as BoringSSL's decode_error). The alerts are the profile's
  unsolicited, duplicate and malformed ones. Go's reading passed over an
  extension it did not know. `u_server_hello_test.go`: the table, the
  alert on the wire, the registry's requirement; 20 mutants killed.

- **A session kept by the key its dialer gives (2026-11-06)**:
  `Config.SessionCacheKey`, when set, is the key `clientSessionCacheKey`
  keeps and looks sessions up by, in place of `ServerName`, and `Clone`
  keeps it. Chromium keys its TLS sessions by host and port
  (`SSLClientSessionCache::Key`, its `HostPortPair`, net/socket and net/ssl
  of 156.0.8078.80) and quiche its QUIC ones by `QuicServerId`, so a ticket a
  server gave on one port is offered on no other port of its name; Go keys
  them by the server name alone. The registry has `tls.session_cache_key` and
  `quic.session_cache_key` (`server-name` | `host-port`) for tls-client to
  give the key by. `u_session_cache_key_test.go` (its key, another key of the
  name, a clone, none).

- **A refused ServerHello in BoringSSL's order and record (2026-11-06)**:
  tls-forge's wire test of the check above found its alert in a record of
  TLS 1.0, where Chrome's is in one of TLS 1.2: BoringSSL refuses the
  extensions once the version is known (do_read_server_hello sets
  `s3->version` first, and `tls_record_version` freezes TLS 1.3's at TLS
  1.2). Only what parse_server_version reads before that, the list and
  supported_versions where the legacy version is TLS 1.2, is alerted in a
  record of TLS 1.0: a list that does not read, supported_versions of other
  than one version (decode_error; Go's unmarshal said unexpected_message),
  supported_versions twice (illegal_parameter, before any extension
  unknown). A version the client does not support is protocol_version
  there too, the legacy version the version unless it is TLS 1.2: crypto/tls
  took TLS 1.3 from supported_versions of a legacy TLS 1.0 hello. Of TLS 1.2
  a ServerHello may answer only what BoringSSL's kExtensions parse there
  (`tls12ServerHello`): key_share, supported_versions, signature_algorithms,
  psk_key_exchange_modes, cookie, ALPS, ECH, trust_anchors and pre_shared_key
  offered are unsupported_extension, compress_certificate a decode_error.
  Contents (a non-empty extended_master_secret, say) are not held to
  BoringSSL's, nor the order of a hello wrong twice over (BoringSSL checks
  its cipher suite and session ID before the extensions of TLS 1.3).
  `u_server_hello_record_test.go` (17 cases, the record of each alert); 13
  mutants killed.

  tls-forge's Chrome profiles, given the check, found two more. An ECH offer
  resumes its session in the inner hello alone, and BoringSSL reads a
  ServerHello's extensions as the inner's where the server accepted ECH
  (do_read_server_hello sets `extensions.sent` to `inner_extensions_sent`
  after check_ech_confirmation): the check read the outer's and refused
  every resumed accepted ECH. Now pre_shared_key is taken where the inner
  hello offered a session (`innerOffersPSK`), and where the server then
  turns out to have rejected ECH it is unsupported_extension, as BoringSSL's
  `pre_shared_key_allowed` says ("pre-shared keys are only offered in
  ClientHelloInner"), once the handshake knows (`rejectedECHResumed`, in a
  record of TLS 1.2); crypto/tls said illegal_parameter there. And a hello
  that signals secure renegotiation by its SCSV alone (Python's, catalogue
  ones) has a TLS 1.2 server answer renegotiation_info, as RFC 5746 (section
  3.4) has it: the SCSV counts as offering it. BoringSSL never sends the SCSV.
  `u_server_hello_ech_test.go`; 10 mutants killed.

- **Hardware cipher selection capability (A13, pending engine1)**:
  `AESGCMHardwareSupport` reports the crypto backend's CPU capability, including
  Go feature overrides. It selects no wire values: owner JSON supplies the cipher
  vectors and selection algorithm. Native/profile comparison retains both AES and
  no-AES process cohorts; this API alone establishes no browser verdict.


- **Explicit QUIC transport and layout policies (A13, pending engine1)**:
  separate initial/max receive windows, keepalive and bounded session capacities;
  explicit TCP-adapter versus independent QUIC TLS source; full supported TP slot
  order and bounded byte-modulo GREASE length selection. Unknown, incomplete,
  conflicting, sentinel-zero and unsupported choices fail validation. Initial ACK
  packet and new-gap thresholds and ACK algorithm selections are explicit too.
  No browser defaults are added.


- **Strict selected policy JSON (A13, pending engine1)**: SETTINGS objects
  require exact explicit non-null `id` and `value`; case-folded, missing,
  duplicate and trailing-value representations cannot invent zero choices.
  The shared policy boundary also rejects invalid UTF-8, nested nulls and
  repeated object keys instead of accepting replacement/empty/last values.
  Existing typed diagnostics are retained; explicit zero, empty text, empty
  SETTINGS and literal text "null" stay distinct and supported. Scalar checks
  avoid token allocation after typed validation. The same boundary serves
  every transport; it is not a root-only workaround. Original nine invalid
  acceptances and the existing duplicate-template rejection are retained by
  `behavior/structured_json_witness_test.go`; positive/negative controls are
  in `behavior/structured_json_test.go`. No browser default changes here.

- **Explicit fresh hybrid/X25519 key reuse (A13, pending engine1)**:
  `KeyShare.ReuseWith` names a fresh X25519MLKEM768 source for an X25519
  fallback. Zero retains independent generation and consumes no extra random
  input. The engine links both public values to the same live private key,
  handles either wire order, and rejects captured, missing, duplicate or
  recursive sources. The selector is data supplied by the owning profile,
  never a browser-name branch. No captured key or cross-connection key is
  replayed. The public extension JSON decoder preserves `reuse_with`.
  `u_keyshare_reuse_test.go` checks default independence, both orders, invalid
  inputs, RNG failure and real standard-library peer handshakes, resumption
  and P-256 HRR; `u_keyshare_reuse_witness_test.go` is the unchanged before/after
  relationship oracle. Native Go QUIC exports establish the need for this
  capability; this is not a new Chrome/platform fidelity verdict.

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
  that fails, then one that works; each handshake given ten seconds, so that
  the old code fails in seconds) and `TestKeyLogsAreWrittenOneAtATime` (a
  handshake whose write is held keeps another's from writing until it is let
  go of); 7 mutants, all killed, and one equivalent (the `defer` before the
  `Lock`). Since 18ad370 (2026-10-27, tls-forge's S08) `writeKeyLog` writes to
  the Config's `KeyLogWriter` alone and passes over `SSLKEYLOGFILE`, on a
  client and a server alike: an environment variable is no consent to give
  away a connection's secrets. The halves of these tests that wrote through
  a file `SSLKEYLOGFILE` named went with it; `u_key_log_consent_test.go`'s
  `TestKeyLogEnvironmentIsNotConsent` holds that a named file, there or not,
  is neither written nor made, and that an explicit writer still is.
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

- Review problem 6 (2026-10-28): the brotli decoder sized its ring buffer from
  the stream's window and a meta-block's claimed length before any data came,
  so four bytes (WBITS 24, a non-last 2^24-byte meta-block) allocated 16 MiB.
  `brotliWindowFor` cuts WBITS 18..24 to the least window whose reach,
  2^w - 16, covers the declared length (2^18, or 2^19 past 262128 bytes):
  only the three bits choosing among them change, and every distance of a
  stream decoding to that many bytes keeps its meaning (a back reference
  within the window, a dictionary word beyond). 326 KB and 590 KB measured
  for the four bytes. Tests: the bit rewrite table, decoding against the
  stream's own window (a copy from 262130 bytes back, which a 2^18 window
  would read as a dictionary word), a bounded allocation subprocess.

- andybalholm/brotli v1.0.6's Reader took a stream that ended short of its
  last meta-block for a whole one when its input ran out between meta-blocks:
  a stream flushed before it was closed, cut before the empty last
  meta-block, gave the whole Certificate with no error, which Chrome's
  decoder refuses (it needs more input). v1.2.3, which tls-forge already
  links, says io.ErrUnexpectedEOF there; utls now requires it, so a module
  built on utls alone refuses such a stream too
  (TestATruncatedBrotliCertificateIsRefused cuts every prefix).

- `http.zstd_window_bytes` has an engine ceiling, `MaxZstdWindowBytes`
  (128 MiB, sixteen times the 8 MiB RFC 9659 holds a zstd content coding to):
  the registry allowed 2147483647, so a profile could let one zstd layer keep
  a 2 GiB window. Every shipped, catalogue and frozen legacy value is
  8388608. `TestZstdWindowPolicy` holds the ceiling and one byte past it.

- Negative controls of the review of 2026-10-28 (`u_negative_controls_test.go`):
  each fails with its check taken away, and none of utls's tests did before.
  A server Finished, and a KeyUpdate, with another handshake message after it
  in its record (refused: it was sealed under the read keys that end there);
  a HelloRetryRequest whose suite hashes otherwise than the session's (the
  second hello offers no pre_shared_key, RFC 8446 4.1.4; a Go server picks
  the SHA-384 suite with AES hardware, and the test is skipped without); the
  second hello saying the ticket's age anew (a clock a second later at each
  reading).
- `quicSetReadSecret` refuses handshake bytes left in the buffer, as Go
  1.26.10's does (CVE-2025-61730): the generic guard of 54dd25b covered every
  read key but a QUIC server's 0-RTT one, set right after the ClientHello,
  so a message that came after the hello in its Initial CRYPTO data was read
  under the early keys. `TestAQUICServerRefusesWhatFollowsAHelloWithEarlyData`.
- A cookie a profile has no extension of its own for goes where BoringSSL's
  permutation puts it (`cookieForRetry`): among the extensions it permutes,
  after a GREASE extension that opens the hello and before those that close
  it (GREASE, padding, pre_shared_key), each place as likely. It went at
  `rand.IntN(len - 2)`: before the opening GREASE about once in 17 of
  Chrome's hellos, a shape Chrome's never has, and never just before the
  closing ones. `TestACookieGoesAmongTheExtensionsBoringSSLPermutes`.
- A HelloRetryRequest after a `FakePreSharedKeyExtension` (a PSK of the
  caller's bytes, set with `SetPskExtension`) is an error,
  `requires a recomputable pre_shared_key extension`, as for any PSK whose
  binder cannot be made again: crypto/tls's code read the suite of a session
  there is none of, and panicked. `TestAHelloRetryRequestAfterAFakePSKIsAnError`.

## A11 owned hostname verification

`TestVerifyHostname` uses an owned loopback TLS peer and explicit signing root.
TLS1.2/TLS1.3 each retain matching-name, post-handshake wrong-name and
InsecureSkipVerify rejection, and add a typed wrong-name handshake control.
No DNS/public endpoint or external-network skip remains. Production code and
profile policy are unchanged; original denied-network failure is retained.

## Explicit GREASE extension payloads (pending engine 1 / A13)

`UtlsGREASEExtension.BodySet` preserves profile-owned `Body` bytes in both
GREASE slots, including an explicitly empty second payload. The per-connection
GREASE ID draws and collision handling are unchanged. Callers without the
presence flag retain the legacy second-slot `00` payload. This generic
mechanism does not select browser data or establish browser equivalence.

## A13 legacy H3 settings capability

The existing `h3.settings` primitive accepts implemented extended CONNECT
booleans and the draft-08 datagram codepoint `0xffd277`. The HTTP/3 engine must
negotiate the common advertised datagram version and use its wire error code.
Historical WebTransport setting `0x2b603742` is accepted only at zero: enabling
its unavailable state machine is still rejected. Unknown APIs, duplicates,
invalid booleans and resource bounds remain strict. No browser defaults added.

Draft-08 enablement additionally requires the explicit
`h3.datagram_setting_error_reason` template (`{id}`, `{value}`, max1024bytes).
Unknown/malformed/null templates are rejected; frozen migration files retain
exact bytes. The owner catalogue supplies the new choice explicitly.

## A13 network-hint capability declaration

`headers.network_hints` declares `none`, `literal` or `weighted-observations`. The project owns the typed policy and execution. Earlier engine snapshots reject this unknown mandatory selector; frozen migration templates receive no hidden default. This registry addition does not claim browser acceptance.

## Pending engine1 release: ECH configs a profile cannot use

A record's ECHConfigList that reads but has no config the profile can use (a
KEM, KDF or AEAD the policy does not name, another ECHConfig version, a
mandatory extension, a public name that is no DNS name) failed the connection
before its ClientHello (`contains no config the profile can use`). Chrome sends
its hello as with no list, with GREASE ECH: BoringSSL's `ssl_select_ech_config`
picks none, and `ssl_encrypt_client_hello` then sends GREASE (revision
2ea3200c, Chrome 156's); Chromium's `ConfigureEch` sets
`reject_unusable_ech_config` only in strict mode. Measured on Chrome
156.0.8078.80 (tls-forge's ledger, TLS-014, baseline
`review-20261105-ech-unusable`).

- `MarshalClientHello`: `startSpecECH` says `errNoUsableECHConfig`, and
  `withoutECHConfigs` gives the connection a copy of its config with no list,
  so that the rest of the handshake is one of no list: TLS 1.2 offered, the
  certificate checked against the server's name with `VerifyConnection` and
  `VerifyPeerCertificate`, a session resumed in the hello itself, the GREASE
  the same after a HelloRetryRequest. The caller's config keeps its list.
- `specECHConfigs` reads a list as BoringSSL's `ssl_is_valid_ech_config_list`
  does and fails one that does not read, as Chrome's
  `ERR_INVALID_ECH_CONFIG_LIST`: Go's `parseECHConfigList` takes an empty list
  and configs with no key, cipher suite or public name, or with more in them
  than their fields, and refuses a list whose config of another version, or
  of a public name that is no DNS name, BoringSSL passes over unread.

Tests in `u_ech_spec_test.go`: `TestAListWithNoConfigTheProfileCanUseSendsGREASEAsChrome`,
`TestAHelloOfNoConfigTheProfileCanUseGoesOnAsOneOfNoList`,
`TestAListThatDoesNotReadSendsNothing` (15 mutants, all killed). No JSON value
or browser branch is added; this is the same unpublished engine1.

- **A cookie's identity (2026-11-06)**: the registry's `cookie.identity` is
  what makes two cookies one: `name-domain-path`, RFC 6265's (5.3, step 11),
  or `name-domain-host-only-path`, RFC 6265bis's (5.7, step 22), under which
  a cookie its host's alone and one of a Domain naming that host are two.
  Chrome 156.0.8078.80 keeps them so (measured at example.test and
  www.example.test, two launches each: both sent, each replaced and removed
  by its own kind). The jar that reads it is fhttp's (`Options.HostOnlyApart`)
  under tls-forge's wrapper; absent, it is RFC 6265's.

- **An ECH offer in the key log (2026-11-06)**: `logECHOffer` (common.go)
  writes `ECH_SECRET` (the HPKE shared secret, `hpke.context.SharedSecret`)
  and `ECH_CONFIG` (the config offered) by the outer hello's random, as NSS
  writes them (draft-ietf-tls-keylogfile), right after the outer hello is
  written, in Go's client and uTLS's alike; a failed write fails the
  handshake, as the others do. The handshake's secrets go by the inner
  hello's random when the server accepts, as BoringSSL writes them, and
  without these lines nothing a reader of the log had opened the inner hello:
  Wireshark (4.6.9, which reads both labels) showed the outer hello alone.
  Tests in `u_ech_keylog_test.go`: the secret is the one the server's key
  gives of the offer's encapsulated key, the handshake's lines the opened
  inner hello's, over uTLS's and Go's client; GREASE writes none; a line
  that cannot be written fails the handshake. 8 mutants, all killed.

- **What a browser's cache keeps (2026-11-06, review M8)**: the registry's
  `cache.store_any_status`, `cache.validated_statuses`,
  `cache.response_pragma_no_cache`, `cache.request_no_cache`
  (validate | bypass), `cache.heuristic_percent`, `cache.heuristic_statuses`,
  `cache.heuristic_with_must_revalidate` (the three together) and
  `cache.implicit_fresh_statuses`, statuses final and once each
  (`behavior/cache.go`, `validateCacheStatuses`). Chrome 156.0.8078.80 keeps
  as Chromium's GetFreshnessLifetimes, ConditionalizeRequest and
  kForceFetchHeaders say (tls-forge's testdata/chrome156-cache-rules.json,
  23 scenarios, two launches alike); tls-forge's cache reads them. Test:
  `behavior/cache_test.go`; 7 mutants, all killed.
