// Package server terminates TLS, captures the raw ClientHello and the HTTP/2
// or HTTP/1.1 request, and serves the resulting fingerprint as JSON (/api/all)
// or a small HTML page (any other path).
package server

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/North-web-dev/fpcheck/internal/h2fp"
	"github.com/North-web-dev/fpcheck/internal/ja3"
	"github.com/North-web-dev/fpcheck/internal/ja4"
	"github.com/North-web-dev/fpcheck/internal/model"
	"github.com/North-web-dev/fpcheck/internal/tlsparse"
)

// Server captures client fingerprints over TLS.
type Server struct {
	addr string
	cfg  *tls.Config
}

// New builds a Server listening on addr with a freshly generated self-signed
// certificate and both h2 and http/1.1 advertised via ALPN.
func New(addr string) (*Server, error) {
	cert, err := selfSignedCert()
	if err != nil {
		return nil, err
	}
	return &Server{
		addr: addr,
		cfg: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
			MinVersion:   tls.VersionTLS12,
		},
	}, nil
}

// ListenAndServe accepts connections until the listener fails.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		raw, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(raw)
	}
}

func (s *Server) handle(raw net.Conn) {
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))

	record, err := readRecord(raw)
	if err != nil {
		return
	}
	ch, err := tlsparse.ParseRecord(record)
	if err != nil {
		return
	}

	tlsConn := tls.Server(&peekConn{Conn: raw, prefix: record}, s.cfg)
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	fp := fromClientHello(ch)
	proto := tlsConn.ConnectionState().NegotiatedProtocol

	if proto == "h2" {
		info, err := h2fp.ReadRequest(tlsConn)
		if err != nil {
			return
		}
		applyHTTP(&fp, info.Request, info.HeaderOrder)
		fp.AkamaiH2 = info.Akamai
		h2fp.WriteJSON(tlsConn, info.StreamID, render(&fp, info.Path))
		return
	}

	req, order, rpath, err := readHTTP1(tlsConn)
	if err != nil {
		return
	}
	applyHTTP(&fp, req, order)
	writeHTTP1(tlsConn, render(&fp, rpath))
}

// render returns the response body and is chosen by path: JSON for /api/all,
// otherwise an HTML page wrapping the same JSON.
func render(fp *model.Fingerprint, path string) []byte {
	pretty, _ := json.MarshalIndent(fp, "", "  ")
	if path == "/api/all" {
		return pretty
	}
	page := "<!doctype html><meta charset=utf-8><title>fpcheck</title>" +
		"<style>body{background:#0d1117;color:#c9d1d9;font:14px monospace;padding:24px}</style>" +
		"<h2>fpcheck</h2><pre>" + string(pretty) + "</pre>"
	return []byte(page)
}

func applyHTTP(fp *model.Fingerprint, req ja4.Request, order []string) {
	fp.JA4H = ja4.JA4H(req)
	fp.HeaderOrder = order
	for _, h := range req.Headers {
		if strings.EqualFold(h.Name, "user-agent") {
			fp.UserAgent = h.Value
		}
	}
}

func fromClientHello(ch *tlsparse.ClientHello) model.Fingerprint {
	str, hash := ja3.FromClientHello(ch)
	return model.Fingerprint{
		JA3:     str,
		JA3Hash: hash,
		JA4:     ja4.FromClientHello(ch),
		TLSDetail: model.TLS{
			Version:             tlsVersionName(ch),
			SNI:                 ch.ServerName,
			CipherSuites:        hexU16(ch.CipherSuites),
			Extensions:          hexU16(ch.Extensions),
			SupportedGroups:     hexU16(ch.SupportedGroups),
			SignatureAlgorithms: hexU16(ch.SignatureAlgorithms),
			ALPN:                ch.ALPN,
		},
	}
}

func tlsVersionName(ch *tlsparse.ClientHello) string {
	best := uint16(0)
	for _, v := range ch.SupportedVersions {
		if !tlsparse.IsGREASE(v) && v > best {
			best = v
		}
	}
	if best == 0 {
		best = ch.LegacyVersion
	}
	switch best {
	case 0x0304:
		return "TLS 1.3"
	case 0x0303:
		return "TLS 1.2"
	case 0x0302:
		return "TLS 1.1"
	case 0x0301:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", best)
	}
}

func hexU16(xs []uint16) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = fmt.Sprintf("0x%04x", x)
	}
	return out
}

// readRecord reads one complete TLS plaintext record (5-byte header + payload).
func readRecord(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	length := int(hdr[3])<<8 | int(hdr[4])
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

func readHTTP1(conn io.Reader) (ja4.Request, []string, string, error) {
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return ja4.Request{}, nil, "", err
	}
	parts := strings.Fields(strings.TrimSpace(line))
	req := ja4.Request{Proto: "HTTP/1.1"}
	path := "/"
	if len(parts) >= 3 {
		req.Method, path, req.Proto = parts[0], parts[1], parts[2]
	}
	var order []string
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return ja4.Request{}, nil, "", err
		}
		h = strings.TrimRight(h, "\r\n")
		if h == "" {
			break
		}
		i := strings.Index(h, ":")
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(h[:i])
		val := strings.TrimSpace(h[i+1:])
		order = append(order, name)
		req.Headers = append(req.Headers, ja4.Header{Name: name, Value: val})
	}
	return req, order, path, nil
}

func writeHTTP1(w io.Writer, body []byte) {
	ct := "application/json"
	if len(body) > 0 && body[0] == '<' {
		ct = "text/html; charset=utf-8"
	}
	fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", ct, len(body))
	w.Write(body)
}

// peekConn replays a prefix (the sniffed ClientHello record) before reading
// further from the underlying connection.
type peekConn struct {
	net.Conn
	prefix []byte
}

func (c *peekConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fpcheck"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
