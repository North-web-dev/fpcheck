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
	"html"
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

// New builds a Server listening on addr with both h2 and http/1.1 advertised
// via ALPN. If certFile and keyFile are both non-empty, that PEM keypair is
// loaded (use a real certificate to host a public demo on a domain); otherwise
// a self-signed certificate is generated for local use.
func New(addr, certFile, keyFile string) (*Server, error) {
	var (
		cert tls.Certificate
		err  error
	)
	if certFile != "" && keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	} else {
		cert, err = selfSignedCert()
	}
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
	return []byte(buildPage(fp, pretty))
}

// buildPage renders the branded HTML view served on any non-API path. Values
// that originate from the client (user-agent, SNI) are HTML-escaped; the JSON
// block is produced by encoding/json, which escapes <, >, & by default.
func buildPage(fp *model.Fingerprint, pretty []byte) string {
	esc := html.EscapeString
	card := func(label, val string) string {
		if val == "" {
			val = "—"
		}
		return fmt.Sprintf(`<div class=card><div class=lbl>%s</div><div class=val>%s</div></div>`, label, esc(val))
	}
	cards := card("JA4", fp.JA4) + card("JA3 hash", fp.JA3Hash) +
		card("JA4H", fp.JA4H) + card("Akamai HTTP/2", fp.AkamaiH2)
	ua := esc(fp.UserAgent)
	if ua == "" {
		ua = "—"
	}
	return `<!doctype html><html lang=en><head><meta charset=utf-8>` +
		`<meta name=viewport content="width=device-width,initial-scale=1">` +
		`<title>fpcheck — your TLS fingerprint</title><style>` +
		`:root{--bg:#0a1726;--panel:#0d2338;--foam:#f4ead2;--foamc:#eef5fb;--mute:#9fb8cc;--shu:#e34234;--kin:#d9a441;--wavel:#7fa8c9;--mono:ui-monospace,"JetBrains Mono","DejaVu Sans Mono",monospace}` +
		`*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--foamc);font-family:var(--mono);line-height:1.55;background-image:repeating-radial-gradient(circle at 50% 120%,#1b3a5b22 0 2px,transparent 2px 30px)}` +
		`.wrap{max-width:900px;margin:0 auto;padding:28px 20px 60px}` +
		`.hd{display:flex;align-items:center;gap:14px}` +
		`.seal{width:48px;height:48px;border-radius:9px;background:var(--shu);color:#fbe9df;display:flex;align-items:center;justify-content:center;font-size:26px;font-weight:700;box-shadow:inset 0 0 0 2px #fbe9df55}` +
		`h1{font-size:26px;margin:0;color:var(--foam);letter-spacing:1px}` +
		`.tag{color:var(--mute);font-size:13px;margin:6px 0 22px}` +
		`.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px}` +
		`@media(max-width:620px){.grid{grid-template-columns:1fr}}` +
		`.card{background:var(--panel);border:1px solid #d9a44133;border-left:3px solid var(--shu);border-radius:10px;padding:12px 14px}` +
		`.lbl{color:var(--kin);font-size:11px;letter-spacing:2px;text-transform:uppercase;margin-bottom:5px}` +
		`.val{color:var(--foam);font-size:14px;word-break:break-all;user-select:all}` +
		`.ua{color:var(--mute);font-size:12px;margin:0 0 16px;word-break:break-all}` +
		`.rule{height:1px;background:linear-gradient(90deg,transparent,#d9a44155 20%,#d9a44155 80%,transparent);margin:16px 0}` +
		`pre{background:#07111d;border:1px solid #1b3a5b;border-radius:10px;padding:16px;overflow:auto;font-size:12.5px;color:var(--foamc);max-height:460px}` +
		`a{color:var(--wavel)}a:hover{color:var(--foam)}.ft{color:var(--mute);font-size:12px;margin-top:18px}` +
		`</style></head><body><div class=wrap>` +
		`<div class=hd><span class=seal>北</span><h1>fpcheck</h1></div>` +
		`<div class=tag>your TLS / HTTP2 fingerprint, exactly as the server reads it off the wire</div>` +
		`<div class=grid>` + cards + `</div>` +
		`<div class=ua>UA&nbsp;·&nbsp;` + ua + `</div>` +
		`<div class=rule></div><pre>` + string(pretty) + `</pre>` +
		`<div class=ft>raw JSON: <a href="/api/all">/api/all</a> &nbsp;·&nbsp; <a href="https://github.com/North-web-dev/fpcheck">github.com/North-web-dev/fpcheck</a></div>` +
		`</div></body></html>`
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
