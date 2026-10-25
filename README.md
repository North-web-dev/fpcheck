# fpcheck

[![CI](https://github.com/North-web-dev/fpcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/North-web-dev/fpcheck/actions/workflows/ci.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/North-web-dev/fpcheck)](https://goreportcard.com/report/github.com/North-web-dev/fpcheck) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Release](https://img.shields.io/github/v/release/North-web-dev/fpcheck?display_name=tag&sort=semver)](https://github.com/North-web-dev/fpcheck/releases)

> **Live demo:** [`fp.shshbshsnang.shop`](https://fp.shshbshsnang.shop/) — open it in a browser to see your own fingerprint, or `curl -s --http2 https://fp.shshbshsnang.shop/api/all` to see what the server reads from your client.


A self-hostable TLS/HTTP2 fingerprint tester and differ. It terminates TLS,
reads the raw ClientHello and HTTP/2 frames, and reports the client's **JA3**,
**JA4**, **JA4H**, and **Akamai HTTP/2** fingerprints — then diffs them against a
reference browser.

It exists because the usual way to debug a fingerprint is [tls.peet.ws](https://tls.peet.ws)
or scrapfly.io, both closed SaaS. `fpcheck` is the same idea you can run
yourself and script. Relevant now that JA4/JA4H shipped across Cloudflare, AWS
WAF and Akamai in 2025–2026 and JA3 alone no longer tells the whole story.

## What it measures

| Signal | One-liner | Source |
| --- | --- | --- |
| **JA3** | Legacy TLS hash; order-sensitive, so browser extension shuffling changes it between connections. | raw ClientHello: cipher suites, extensions, curves, EC point formats |
| **JA4** | Modern TLS fingerprint; sorts extensions, so it is stable where JA3 is not. | raw ClientHello, [FoxIO JA4 spec](https://github.com/FoxIO-LLC/ja4) (`t13d1516h2_..._...`) |
| **JA4H** | Fingerprint of the HTTP request itself. | method, version, cookie presence, header count and order |
| **Akamai HTTP/2** | Fingerprint of the HTTP/2 layer. | raw H2 frames: SETTINGS, WINDOW_UPDATE, PRIORITY, pseudo-header order |
| header order | The header names exactly as sent on the wire. | request frames |

The ClientHello is parsed off the wire rather than through
`crypto/tls.ClientHelloInfo`, so extension order, EC point formats and GREASE
are preserved — the details a fingerprint depends on.

## Quickstart

Build and run with Docker, then ask the server for your own fingerprint:

```
git clone https://github.com/North-web-dev/fpcheck && cd fpcheck
docker build -t fpcheck . && docker run --rm -p 8443:8443 fpcheck
curl -sk --http2 https://127.0.0.1:8443/api/all
```

A prebuilt image is also published to `ghcr.io/north-web-dev/fpcheck` for each
release (`docker run --rm -p 8443:8443 ghcr.io/north-web-dev/fpcheck:latest`).

Or without Docker:

```
go install github.com/North-web-dev/fpcheck@latest
fpcheck serve --addr :8443
```

(build from source: `git clone https://github.com/North-web-dev/fpcheck && cd fpcheck && go build -o fpcheck .`)

`https://host:8443/api/all` returns JSON; any other path (e.g. `/`) returns the
same data as an HTML page — that page is the public demo.

### Real sample — `curl --http2`

```jsonc
// curl -sk --http2 https://127.0.0.1:8443/api/all   (curl 7.81, OpenSSL)
{
  "ja3": "771,4866-4867-4865-49196-49200-159-52393-52392-52394-...,11-10-13172-16-22-23-49-13-43-45-51-21,29-23-30-25-24-256-257-258-259-260,0-1-2",
  "ja3_hash": "4314c4ae07ee10b792caeaf57790fa7b",
  "ja4": "t13i3112h2_e8f1e7e78f70_ce5650b735ce",
  "tls": { "version": "TLS 1.3", "cipher_suites": ["0x1302", "..."], "extensions": ["0x000b", "..."], "alpn": ["h2", "http/1.1"] },
  "ja4h": "ge20nn020000_5594a17e7e7e_000000000000_000000000000",
  "akamai_h2": "3:100;4:33554432;2:0|33488897|0|m,p,s,a",
  "header_order": [":method", ":path", ":scheme", ":authority", "user-agent", "accept"],
  "user_agent": "curl/7.81.0"
}
```

### Real sample — Chrome (headless, Chrome 151)

A real browser against the same endpoint. Note the GREASE values
(`0x2a2a`, `0x5a5a`, `0x4a4a`) preserved in the ClientHello, and that this JA4
b-segment `8daaf6152771` matches the bundled `chrome131`/`chrome142` reference:

```jsonc
{
  "ja3_hash": "7bf320e323966bc676b52de076424af0",
  "ja4": "t13i1515h2_8daaf6152771_806a8c22fdea",
  "tls": { "version": "TLS 1.3", "cipher_suites": ["0x2a2a", "0x1301", "..."], "extensions": ["0x5a5a", "0x0017", "..."] },
  "ja4h": "ge20nn13enus_0c2c1d640f3e_000000000000_000000000000",
  "akamai_h2": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
  "header_order": [":method", ":authority", ":scheme", ":path", "sec-ch-ua", "...", "user-agent", "accept", "..."],
  "user_agent": "Mozilla/5.0 (X11; Linux x86_64) ... HeadlessChrome/151.0.0.0 Safari/537.36"
}
```

Re-run that request and the `ja3`/`ja3_hash` change (Chrome shuffles its
extension order every connection) while `ja4` stays identical — the reason JA4
replaced JA3. (The a-segment is `t13i...` rather than `t13d...` here only
because the request targeted an IP with no SNI; over a domain it is `t13d...`.)

## CLI

`report` prints the fingerprint the server saw, as a table:

```
$ fpcheck report --url https://127.0.0.1:8443/api/all
  JA3         4314c4ae07ee10b792caeaf57790fa7b
  JA4         t13i3112h2_e8f1e7e78f70_ce5650b735ce
  JA4H        ge20nn020000_5594a17e7e7e_000000000000_000000000000
  Akamai H2   3:100;4:33554432;2:0|33488897|0|m,p,s,a
  TLS         TLS 1.3
```

`run` fingerprints an arbitrary client that targets the server, and prints what
the server saw:

```
$ fpcheck run -- curl -sk --http2 https://127.0.0.1:8443/api/all
```

## Diff against a reference browser

`diff` fetches your fingerprint and compares it, field by field, against a
bundled reference profile. The comparison is segment-aware: a reference that
only pins the human-readable JA4 a-segment still produces a useful diff.

```
$ fpcheck diff --target chrome131 --url https://127.0.0.1:8443/api/all
diff vs chrome131 (Chrome 120-131 desktop (Windows/macOS/Linux))
  verified: ja4 a+b stable across Chrome 120-131; c matches ~Chrome 124-131

  ja4_a          got t13i1411h2  want t13d1516h2
  ja4_b          got cbb2034c60b8  want 8daaf6152771
  ja4_c          got e5728521abd4  want b0da82dd1658
  akamai_h2      got 2:0;...      want 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
```

Exit code is `0` on a match (no differences on the reference fields) and `1`
otherwise, so it drops into a script or CI check.

Bundled targets: `chrome131`, `chrome142`, `firefox`, `safari`. JA4 a-segments
and Akamai HTTP/2 strings are stable and well documented; JA4 b/c hashes drift
between browser builds, so some entries are marked *approximate* in
[`internal/profiles/profiles.json`](internal/profiles/profiles.json). To add or
pin a profile, capture the real value with `fpcheck report` against the target
browser and add an entry there.

## Self-host

`fpcheck` **terminates TLS itself** — that is the whole point, because it needs
the raw ClientHello and raw HTTP/2 frames. This constrains how you put it behind
a domain:

- **Do not** place it behind a TLS-terminating HTTP reverse proxy (nginx
  `proxy_pass`, a Caddy site block, a cloud load balancer in HTTP mode). The
  proxy would complete the TLS handshake and you would fingerprint the *proxy*,
  not the visitor.
- **Do** expose it directly, or front it with a **TCP / SNI passthrough** proxy
  that forwards the raw bytes.

### Option A — direct, with a real certificate

```
fpcheck serve --addr :443 --cert /etc/letsencrypt/live/fp.example.com/fullchain.pem \
                          --key  /etc/letsencrypt/live/fp.example.com/privkey.pem
```

Obtain the certificate out of band (e.g. `certbot certonly --standalone` on a
port that is free, or DNS-01) and point `--cert`/`--key` at it. Without the
flags `fpcheck` serves a self-signed certificate, fine for local use but it
warns in browsers.

With Docker, mount the certs and pass the same flags — see the commented block
in [`docker-compose.yml`](docker-compose.yml). Then `docker compose up -d`.

### Option B — nginx TCP/SNI passthrough

Keep an existing nginx for your other sites and route one hostname straight
through at the TCP layer (the `stream` module ships with mainline nginx):

```nginx
stream {
    map $ssl_preread_server_name $backend {
        fp.example.com  127.0.0.1:8443;   # fpcheck, self-signed or real cert
    }
    server {
        listen 443;
        ssl_preread on;          # read SNI without terminating TLS
        proxy_pass $backend;
    }
}
```

TLS is still terminated by `fpcheck` (so give it a real cert via `--cert`), and
nginx only reads the SNI to pick the backend. Caddy's `layer4` plugin does the
same with a `tls` matcher.

## Limitations

- JA4H header order reflects what the client sends over the wire; HTTP/2
  lowercases header names, as the protocol requires.
- A ClientHello split across multiple TLS records is not reassembled (rare in
  practice; browsers send it in one record).
- JA4 a-segment uses `d` only when SNI is present; a request to a bare IP
  reports `i`.

## Disclaimer

For educational and research purposes. Provided **as is, without warranty of
any kind**. You are responsible for how you use it and for complying with
applicable laws and the terms of any service you test against. The authors
accept no liability.

## Support

If this project saves you time, you can support development:

⭐ Star the repo if it helped.

| Coin | Address |
|---|---|
| **BTC** | `bc1q0sfghv7yfl594gjurhyhlhdgm0dtwh4dkjha36` |
| **ETH / USDT-ERC20 / BNB-BEP20** | `0xB827b5a8B6c5111946c5D872933b2C23484E87dE` |
| **SOL** | `3ch5aHrPp3CierhiNXmqmtFH2dMHh6Gfv7a97KtLMMCh` |
| **USDT-TRC20 / TRX** | `TUAyz7TjgJdFVD2oFHWUUTNrzzAnBRgySG` |
| **TON** | `UQAJmYVuR3hh02etjaPKJF-h6jcpdSnq9ZIFvI64NEskS6tx` |

## License

MIT — see [LICENSE](LICENSE).
