# fpcheck

A self-hostable TLS/HTTP2 fingerprint tester and differ. It terminates TLS,
reads the raw ClientHello and HTTP/2 frames, and reports the client's **JA3**,
**JA4**, **JA4H**, and **Akamai HTTP/2** fingerprints — then diffs them against a
reference browser.

It exists because the usual way to debug a fingerprint is [tls.peet.ws](https://tls.peet.ws)
or scrapfly.io, both closed SaaS. `fpcheck` is the same idea you can run
yourself and script. Relevant now that JA4/JA4H shipped across Cloudflare, AWS
WAF and Akamai in 2025–2026 and JA3 alone no longer tells the whole story.

## What it captures

| Signal | Source |
| --- | --- |
| JA3 + MD5 | raw ClientHello (cipher suites, extensions, curves, EC point formats) |
| JA4 | raw ClientHello, FoxIO spec (`t13d1516h2_..._...`) |
| JA4H | HTTP request (method, version, cookies, header order) |
| Akamai HTTP/2 | raw H2 frames (SETTINGS, WINDOW_UPDATE, PRIORITY, pseudo-header order) |
| header order | as sent on the wire |

The ClientHello is parsed off the wire rather than through
`crypto/tls.ClientHelloInfo`, so extension order, EC point formats and GREASE
are preserved — the details a fingerprint depends on.

## Install

```
go install github.com/North-web-dev/fpcheck@latest
```

or build from source:

```
git clone https://github.com/North-web-dev/fpcheck && cd fpcheck
go build -o fpcheck .
```

## Usage

Run the server (self-signed cert, advertises both h2 and http/1.1):

```
fpcheck serve --addr :8443
```

Point any client at `https://host:8443/api/all` and it gets back its own
fingerprint as JSON. `/` returns the same data as an HTML page.

```
$ curl -sk --http2 https://127.0.0.1:8443/api/all
{
  "ja3": "771,4865-4866-...",
  "ja3_hash": "4314c4ae07ee10b792caeaf57790fa7b",
  "ja4": "t13i3112h2_e8f1e7e78f70_ce5650b735ce",
  "ja4h": "ge20nn020000_5594a17e7e7e_000000000000_000000000000",
  "akamai_h2": "3:100;4:33554432;2:0|33488897|0|m,p,s,a",
  "header_order": [":method", ":path", ":scheme", ":authority", "user-agent", "accept"],
  "tls": { "version": "TLS 1.3", "cipher_suites": [...], "extensions": [...] }
}
```

`report` prints your fingerprint as a table:

```
$ fpcheck report --url https://127.0.0.1:8443/api/all
  JA4         t13i140900_cbb2034c60b8_e7c285222651
  JA4H        ge11nn030000_cd680697de12_000000000000_000000000000
  TLS         TLS 1.3
```

`run` fingerprints an arbitrary client that targets the server:

```
$ fpcheck run -- curl -sk --http2 https://127.0.0.1:8443/api/all
```

`diff` compares your client against a bundled reference browser:

```
$ fpcheck diff --target chrome131 --url https://127.0.0.1:8443/api/all
diff vs chrome131 (Chrome 120-131 desktop)
  ja4_a       got t13i140900  want t13d1516h2
  ja4_b       got cbb2034c60b8  want 8daaf6152771
  akamai_h2   got (none)      want 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
```

## Reference profiles

Bundled targets: `chrome131`, `chrome142`, `firefox`, `safari`. JA4 a-segments
and Akamai HTTP/2 strings are stable and well documented; JA4 b/c hashes drift
between browser builds, so some entries are marked *approximate* in
[`internal/profiles/profiles.json`](internal/profiles/profiles.json). The
diff is segment-aware: a reference that only pins the human-readable a-segment
still yields a useful diff.

To add or pin a profile, capture the real value with `fpcheck report` against
the target browser and add an entry to `profiles.json`.

## Limitations

- Header order for JA4H reflects what the client sends over the wire; HTTP/2
  lowercases header names, as the protocol requires.
- A ClientHello split across multiple TLS records is not reassembled (rare in
  practice; browsers send it in one record).

## Disclaimer

For educational and research purposes. Provided **as is, without warranty of
any kind**. You are responsible for how you use it and for complying with
applicable laws and the terms of any service you test against. The authors
accept no liability.

## License

MIT — see [LICENSE](LICENSE).
