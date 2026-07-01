// Package tlsparse decodes a raw TLS ClientHello into the fields needed for
// fingerprinting. It deliberately parses the wire bytes itself rather than
// using crypto/tls.ClientHelloInfo, which does not preserve extension order,
// EC point formats, or GREASE values.
package tlsparse

import (
	"encoding/binary"
	"errors"
)

// ClientHello holds the fingerprint-relevant fields of a TLS ClientHello, with
// list order preserved as sent on the wire. GREASE values are retained here;
// callers filter them per the fingerprint spec they implement.
type ClientHello struct {
	// LegacyVersion is the client_version field (e.g. 0x0303 for TLS 1.2).
	LegacyVersion uint16
	// CipherSuites in wire order.
	CipherSuites []uint16
	// Extensions is the list of extension types in wire order.
	Extensions []uint16
	// SupportedGroups (extension 0x000a), a.k.a. elliptic curves.
	SupportedGroups []uint16
	// ECPointFormats (extension 0x000b).
	ECPointFormats []uint8
	// SignatureAlgorithms (extension 0x000d) in wire order.
	SignatureAlgorithms []uint16
	// SupportedVersions (extension 0x002b) in wire order.
	SupportedVersions []uint16
	// ALPN protocols (extension 0x0010) in wire order.
	ALPN []string
	// ServerName is the SNI host (extension 0x0000), empty if absent.
	ServerName string
	// HasSNI reports whether the SNI extension was present.
	HasSNI bool
}

var errShort = errors.New("tlsparse: truncated ClientHello")

// IsGREASE reports whether v is a GREASE value (RFC 8701): both bytes equal and
// of the form 0x?a, i.e. 0x0a0a, 0x1a1a, ... 0xfafa.
func IsGREASE(v uint16) bool {
	return byte(v>>8) == byte(v) && v&0x000f == 0x000a
}

// ParseRecord extracts the ClientHello from a full TLS plaintext record,
// including the 5-byte record header. It returns an error if the record is not
// a handshake record carrying a ClientHello.
func ParseRecord(record []byte) (*ClientHello, error) {
	if len(record) < 5 {
		return nil, errShort
	}
	if record[0] != 0x16 { // handshake content type
		return nil, errors.New("tlsparse: not a handshake record")
	}
	return ParseHandshake(record[5:])
}

// ParseHandshake parses a handshake message whose first byte is the handshake
// type. Only ClientHello (type 0x01) is accepted.
func ParseHandshake(b []byte) (*ClientHello, error) {
	if len(b) < 4 {
		return nil, errShort
	}
	if b[0] != 0x01 {
		return nil, errors.New("tlsparse: not a ClientHello")
	}
	length := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	body := b[4:]
	if len(body) < length {
		return nil, errShort
	}
	return parseBody(body[:length])
}

func parseBody(b []byte) (*ClientHello, error) {
	ch := &ClientHello{}
	r := reader{b: b}

	ch.LegacyVersion = r.u16()
	r.skip(32)                           // random
	r.skip(int(r.u8()))                  // session_id
	for cl := r.u16len(); cl > 0; cl-- { // cipher_suites
		ch.CipherSuites = append(ch.CipherSuites, r.u16())
	}
	r.skip(int(r.u8())) // compression_methods

	if r.err || r.left() == 0 {
		return ch, r.finalErr()
	}
	extTotal := int(r.u16())
	extEnd := r.pos + extTotal
	for r.pos < extEnd && !r.err {
		etype := r.u16()
		elen := int(r.u16())
		data := r.take(elen)
		if r.err {
			break
		}
		ch.Extensions = append(ch.Extensions, etype)
		parseExtension(ch, etype, data)
	}
	return ch, r.finalErr()
}

func parseExtension(ch *ClientHello, etype uint16, data []byte) {
	e := reader{b: data}
	switch etype {
	case 0x0000: // server_name
		ch.HasSNI = true
		if len(data) >= 5 {
			// list len(2) + name type(1) + name len(2) + name
			e.skip(2)
			e.skip(1)
			n := int(e.u16())
			ch.ServerName = string(e.take(n))
		}
	case 0x000a: // supported_groups
		for l := e.u16len(); l > 0; l-- {
			ch.SupportedGroups = append(ch.SupportedGroups, e.u16())
		}
	case 0x000b: // ec_point_formats
		for l := int(e.u8()); l > 0; l-- {
			ch.ECPointFormats = append(ch.ECPointFormats, e.u8())
		}
	case 0x000d: // signature_algorithms
		for l := e.u16len(); l > 0; l-- {
			ch.SignatureAlgorithms = append(ch.SignatureAlgorithms, e.u16())
		}
	case 0x0010: // ALPN
		e.skip(2) // protocol name list length
		for e.left() > 0 && !e.err {
			n := int(e.u8())
			ch.ALPN = append(ch.ALPN, string(e.take(n)))
		}
	case 0x002b: // supported_versions
		for l := int(e.u8()); l > 0; l-- {
			ch.SupportedVersions = append(ch.SupportedVersions, e.u16())
		}
	}
}

// reader is a minimal bounds-checked cursor over a byte slice. Once any read
// runs past the end it latches err and returns zero values.
type reader struct {
	b   []byte
	pos int
	err bool
}

func (r *reader) left() int { return len(r.b) - r.pos }

func (r *reader) u8() uint8 {
	if r.pos+1 > len(r.b) {
		r.err = true
		return 0
	}
	v := r.b[r.pos]
	r.pos++
	return v
}

func (r *reader) u16() uint16 {
	if r.pos+2 > len(r.b) {
		r.err = true
		return 0
	}
	v := binary.BigEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v
}

// u16len reads a 2-byte length and returns it as the number of uint16 elements.
func (r *reader) u16len() int { return int(r.u16()) / 2 }

func (r *reader) skip(n int) {
	if n < 0 || r.pos+n > len(r.b) {
		r.err = true
		return
	}
	r.pos += n
}

func (r *reader) take(n int) []byte {
	if n < 0 || r.pos+n > len(r.b) {
		r.err = true
		return nil
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v
}

func (r *reader) finalErr() error {
	if r.err {
		return errShort
	}
	return nil
}
