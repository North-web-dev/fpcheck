// Package ja4 computes the JA4 suite of fingerprints (FoxIO spec): JA4 for the
// TLS ClientHello and JA4H for an HTTP request.
package ja4

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/North-web-dev/fpcheck/internal/tlsparse"
)

const emptyHash = "000000000000"

// FromClientHello returns the JA4 fingerprint for a TLS-over-TCP ClientHello,
// e.g. t13d1516h2_8daaf6152771_e5627efa2ab1.
func FromClientHello(ch *tlsparse.ClientHello) string {
	a := ja4a(ch)
	b := ja4b(ch)
	c := ja4c(ch)
	return a + "_" + b + "_" + c
}

func ja4a(ch *tlsparse.ClientHello) string {
	sni := "i"
	if ch.HasSNI {
		sni = "d"
	}
	nc := count(ch.CipherSuites)
	ne := count(ch.Extensions) // includes SNI and ALPN per spec
	return fmt.Sprintf("t%s%s%s%s%s", versionCode(ch), sni, twoDigit(nc), twoDigit(ne), alpnCode(ch.ALPN))
}

func ja4b(ch *tlsparse.ClientHello) string {
	hexes := hexList(ch.CipherSuites, nil)
	if len(hexes) == 0 {
		return emptyHash
	}
	sort.Strings(hexes)
	return trunc(strings.Join(hexes, ","))
}

func ja4c(ch *tlsparse.ClientHello) string {
	// Extensions sorted, excluding GREASE, SNI (0x0000) and ALPN (0x0010).
	exts := hexList(ch.Extensions, map[uint16]bool{0x0000: true, 0x0010: true})
	sort.Strings(exts)
	sigs := hexList(ch.SignatureAlgorithms, nil) // original order
	if len(exts) == 0 && len(sigs) == 0 {
		return emptyHash
	}
	return trunc(strings.Join(exts, ",") + "_" + strings.Join(sigs, ","))
}

// versionCode maps the negotiated TLS version to its two-char JA4 code,
// preferring the supported_versions extension over the legacy field.
func versionCode(ch *tlsparse.ClientHello) string {
	best := uint16(0)
	for _, v := range ch.SupportedVersions {
		if tlsparse.IsGREASE(v) {
			continue
		}
		if v > best {
			best = v
		}
	}
	if best == 0 {
		best = ch.LegacyVersion
	}
	switch best {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	default:
		return "00"
	}
}

// alpnCode is the first and last alphanumeric character of the first ALPN
// value, or "00" if there is no ALPN.
func alpnCode(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	v := alpn[0]
	f, l := v[0], v[len(v)-1]
	if isAlnum(f) && isAlnum(l) {
		return string(f) + string(l)
	}
	// Non-alphanumeric: use first and last nibble of the hex encoding.
	h := hex.EncodeToString([]byte(v))
	return string(h[0]) + string(h[len(h)-1])
}

func hexList(xs []uint16, exclude map[uint16]bool) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if tlsparse.IsGREASE(x) || exclude[x] {
			continue
		}
		out = append(out, fmt.Sprintf("%04x", x))
	}
	return out
}

func count(xs []uint16) int {
	n := 0
	for _, x := range xs {
		if !tlsparse.IsGREASE(x) {
			n++
		}
	}
	return n
}

func twoDigit(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

func trunc(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
