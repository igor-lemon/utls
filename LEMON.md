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
