// Package model defines the fingerprint record shared by the server, the
// reference profile database, and the diff logic.
package model

import (
	"fmt"
	"strings"
)

// Fingerprint is the full set of signals captured for one client connection.
// TLS fields are always present; HTTP fields are set only when an application
// request was read.
type Fingerprint struct {
	// TLS layer.
	JA3       string `json:"ja3"`
	JA3Hash   string `json:"ja3_hash"`
	JA4       string `json:"ja4"`
	TLSDetail TLS    `json:"tls"`

	// HTTP layer (optional).
	JA4H        string   `json:"ja4h,omitempty"`
	AkamaiH2    string   `json:"akamai_h2,omitempty"`
	HeaderOrder []string `json:"header_order,omitempty"`
	UserAgent   string   `json:"user_agent,omitempty"`
}

// TLS holds the decoded ClientHello detail, GREASE included as sent.
type TLS struct {
	Version             string   `json:"version"`
	SNI                 string   `json:"sni,omitempty"`
	CipherSuites        []string `json:"cipher_suites"`
	Extensions          []string `json:"extensions"`
	SupportedGroups     []string `json:"supported_groups"`
	SignatureAlgorithms []string `json:"signature_algorithms"`
	ALPN                []string `json:"alpn,omitempty"`
}

// Delta is one field-level difference between two fingerprints.
type Delta struct {
	Field string
	Got   string
	Want  string
}

func (d Delta) String() string {
	return fmt.Sprintf("%-14s got %s  want %s", d.Field, orNone(d.Got), orNone(d.Want))
}

// Diff compares got against a reference want and returns the mismatching
// fields. Only the primary fingerprints are compared; equal fields are omitted.
func Diff(got, want *Fingerprint) []Delta {
	var out []Delta
	add := func(field, g, w string) {
		if g != w {
			out = append(out, Delta{field, g, w})
		}
	}
	if want.JA3Hash != "" {
		add("ja3_hash", got.JA3Hash, want.JA3Hash)
	}
	// JA4 is compared segment by segment (a_b_c) so a reference that only pins
	// the human-readable a-segment still yields a meaningful diff.
	g, w := strings.Split(got.JA4, "_"), strings.Split(want.JA4, "_")
	for i, name := range []string{"ja4_a", "ja4_b", "ja4_c"} {
		if i >= len(w) || w[i] == "" {
			continue
		}
		gv := ""
		if i < len(g) {
			gv = g[i]
		}
		add(name, gv, w[i])
	}
	if want.JA4H != "" {
		add("ja4h", got.JA4H, want.JA4H)
	}
	if want.AkamaiH2 != "" {
		add("akamai_h2", got.AkamaiH2, want.AkamaiH2)
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
