// Package ja3 computes the JA3 TLS client fingerprint (Salesforce spec) from a
// parsed ClientHello.
package ja3

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/North-web-dev/fpcheck/internal/tlsparse"
)

// FromClientHello returns the JA3 string and its MD5 hash. The string is
// SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats with each list
// hyphen-joined in decimal and GREASE values removed.
func FromClientHello(ch *tlsparse.ClientHello) (string, string) {
	var b strings.Builder
	b.WriteString(strconv.Itoa(int(ch.LegacyVersion)))
	b.WriteByte(',')
	writeU16(&b, ch.CipherSuites)
	b.WriteByte(',')
	writeU16(&b, ch.Extensions)
	b.WriteByte(',')
	writeU16(&b, ch.SupportedGroups)
	b.WriteByte(',')
	writeU8(&b, ch.ECPointFormats)

	s := b.String()
	sum := md5.Sum([]byte(s))
	return s, hex.EncodeToString(sum[:])
}

func writeU16(b *strings.Builder, xs []uint16) {
	first := true
	for _, x := range xs {
		if tlsparse.IsGREASE(x) {
			continue
		}
		if !first {
			b.WriteByte('-')
		}
		b.WriteString(strconv.Itoa(int(x)))
		first = false
	}
}

func writeU8(b *strings.Builder, xs []uint8) {
	for i, x := range xs {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(strconv.Itoa(int(x)))
	}
}
