package ja4

import (
	"testing"

	"github.com/North-web-dev/fpcheck/internal/tlsparse"
)

func TestJA4FromClientHello(t *testing.T) {
	ch := &tlsparse.ClientHello{
		LegacyVersion:       0x0303,
		SupportedVersions:   []uint16{0x0a0a, 0x0304, 0x0303}, // GREASE + 1.3 + 1.2
		HasSNI:              true,
		CipherSuites:        []uint16{0x0a0a, 0x1301, 0x1302, 0x1303}, // GREASE + 3
		Extensions:          []uint16{0x0a0a, 0x0000, 0x0010, 0x000d, 0x002b},
		SignatureAlgorithms: []uint16{0x0403, 0x0804},
		ALPN:                []string{"h2", "http/1.1"},
	}
	// a = t | 13 | d | 03 ciphers | 04 exts (incl SNI+ALPN) | h2
	want := "t13d0304h2_55b375c5d22e_ef5f37ab036a"
	if got := FromClientHello(ch); got != want {
		t.Errorf("JA4:\n got %s\nwant %s", got, want)
	}
}

func TestJA4NoALPNNoSNI(t *testing.T) {
	ch := &tlsparse.ClientHello{
		LegacyVersion: 0x0303,
		CipherSuites:  []uint16{0x1301},
		Extensions:    []uint16{0x000d},
	}
	got := FromClientHello(ch)
	// t | 12 (legacy 1.2) | i (no SNI) | 01 | 01 | 00 (no ALPN)
	if got[:10] != "t12i010100" {
		t.Errorf("prefix: got %s want t12i010100...", got[:10])
	}
}

func TestJA4HKnown(t *testing.T) {
	req := Request{
		Method: "GET",
		Proto:  "HTTP/1.1",
		Headers: []Header{
			{"Host", "example.com"},
			{"User-Agent", "curl/8"},
			{"Accept", "*/*"},
			{"Accept-Language", "en-US,en;q=0.9"},
			{"Cookie", "b=2; a=1"},
			{"Referer", "https://x"},
		},
	}
	got := JA4H(req)
	// a: ge 11 c r  hdrcount=3 (Host,User-Agent,Accept; Accept-Language counts too
	// =4? Accept-Language is a normal header) -> Host,UA,Accept,Accept-Language = 4
	// cookie present, referer present, lang enus
	if got[:12] != "ge11cr04enus" {
		t.Errorf("JA4H_a: got %s want ge11cr04enus...", got[:12])
	}
	// cookie hashes must be non-empty (cookies present)
	parts := got
	if len(parts) != len("ge11cr04enus")+1+12+1+12+1+12 {
		t.Errorf("JA4H length unexpected: %s", got)
	}
}
