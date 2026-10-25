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

	"github.com/North-web-dev/fpcheck/internal/profiles"

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
		ct := "text/html; charset=utf-8"
		if info.Path == "/api/all" {
			ct = "application/json"
		}
		h2fp.WriteResponse(tlsConn, info.StreamID, render(&fp, info.Path), ct)
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

// ja4ASeg returns the JA4 "a" segment (before the first '_'), which is stable
// across browser builds while the b/c hash segments drift.
func ja4ASeg(ja4 string) string {
	if i := strings.IndexByte(ja4, '_'); i > 0 {
		return ja4[:i]
	}
	return ja4
}

// classify compares the observed fingerprint against the bundled reference
// profiles and returns a human verdict plus a level (good/warn/bad).
func classify(fp *model.Fingerprint) (string, string) {
	best := ""
	bestScore := 0
	for _, n := range profiles.Names() {
		_, p, err := profiles.Get(n)
		if err != nil || p == nil {
			continue
		}
		score := 0
		switch {
		case p.JA4 != "" && p.JA4 == fp.JA4:
			score = 4
		case p.JA4 != "" && fp.JA4 != "" && ja4ASeg(p.JA4) == ja4ASeg(fp.JA4):
			score = 2
		}
		if p.AkamaiH2 != "" && p.AkamaiH2 == fp.AkamaiH2 {
			score++
		}
		if score > bestScore {
			bestScore, best = score, p.Name
		}
	}
	switch {
	case bestScore >= 4:
		return "matches " + best, "good"
	case bestScore >= 2:
		return "looks like " + best + " — TLS shape matches (JA4 b/c drift between builds is normal)", "good"
	case bestScore == 1:
		return "partial match: " + best + " (HTTP/2 only)", "warn"
	default:
		return "no known browser match — likely a non-browser client (curl, a library, or a bot)", "bad"
	}
}

// buildPage renders the branded HTML view served on any non-API path. Values
// that originate from the client (user-agent, SNI, ALPN) are HTML-escaped; the
// JSON block is produced by encoding/json, which escapes <, >, & by default.
func buildPage(fp *model.Fingerprint, pretty []byte) string {
	esc := html.EscapeString
	card := func(label, val string) string {
		if val == "" {
			val = "—"
		}
		return fmt.Sprintf(`<div class=card><div class=lbl>%s</div><div class=val>%s</div></div>`, label, esc(val))
	}
	chips := func(items []string) string {
		if len(items) == 0 {
			return `<span class=mut>—</span>`
		}
		var b strings.Builder
		for _, it := range items {
			b.WriteString(`<span class=chip>` + esc(it) + `</span>`)
		}
		return b.String()
	}
	section := func(title, body string) string {
		return `<div class=sec><div class=sh>` + esc(title) + `</div>` + body + `</div>`
	}

	verdict, level := classify(fp)
	vicon := map[string]string{"good": "✓", "warn": "!", "bad": "✕"}[level]
	ja4hero := `<div class=hero-card><div class=lbl>JA4 · the stable fingerprint</div><div class=ja4>` + esc(fp.JA4) + `</div></div>`
	small := card("JA3 hash", fp.JA3Hash) + card("JA4H", fp.JA4H) + card("Akamai HTTP/2", fp.AkamaiH2)
	ua := esc(fp.UserAgent)
	if ua == "" {
		ua = "—"
	}
	t := &fp.TLSDetail
	tlsMeta := `<div class=kv><span>version</span><b>` + esc(t.Version) + `</b></div>` +
		`<div class=kv><span>SNI</span><b>` + esc(t.SNI) + `</b></div>` +
		`<div class=kv><span>ALPN</span><b>` + esc(strings.Join(t.ALPN, ", ")) + `</b></div>`
	tlsBody := tlsMeta +
		`<div class=cl>cipher suites</div><div class=chips>` + chips(t.CipherSuites) + `</div>` +
		`<div class=cl>extensions</div><div class=chips>` + chips(t.Extensions) + `</div>` +
		`<div class=cl>supported groups</div><div class=chips>` + chips(t.SupportedGroups) + `</div>` +
		`<div class=cl>signature algorithms</div><div class=chips>` + chips(t.SignatureAlgorithms) + `</div>`

	httpBody := `<div class=kv><span>Akamai h2</span><b>` + esc(fp.AkamaiH2) + `</b></div>`
	if len(fp.HeaderOrder) > 0 {
		httpBody += `<div class=cl>header order</div><div class=chips>` + chips(fp.HeaderOrder) + `</div>`
	}

	return `<!doctype html><html lang=en><head><meta charset=utf-8>` +
		`<meta name=viewport content="width=device-width,initial-scale=1">` +
		`<title>fpcheck — your TLS fingerprint</title>` +
		`<link rel=preconnect href="https://fonts.googleapis.com"><link rel=preconnect href="https://fonts.gstatic.com" crossorigin>` +
		`<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=JetBrains+Mono:wght@400;600&display=swap" rel=stylesheet>` +
		`<style>` +
		`:root{--bg:#0a1726;--panel:#0d2338;--p2:#102a44;--foam:#f4ead2;--foamc:#eef5fb;--mute:#9fb8cc;--shu:#e34234;--kin:#d9a441;--wavel:#7fa8c9;--disp:"Space Grotesk",system-ui,sans-serif;--mono:"JetBrains Mono",ui-monospace,"DejaVu Sans Mono",monospace}` +
		`*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--foamc);font-family:var(--mono);line-height:1.55}` +
		`.hero{position:relative;overflow:hidden;background:linear-gradient(180deg,#071320,#0d2338 70%,#13314c);border-bottom:1px solid #d9a44133}` +
		`.hero::before{content:"";position:absolute;inset:0;background-image:radial-gradient(circle at 50% 118%,#2e5f8633 0 3px,transparent 3px 26px);opacity:.55}` +
		`.hero-in{position:relative;max-width:900px;margin:0 auto;padding:42px 20px 36px;display:flex;align-items:center;gap:18px}` +
		`.seal{width:62px;height:62px;border-radius:12px;background:var(--shu);color:#fbe9df;display:flex;align-items:center;justify-content:center;font-size:34px;font-weight:700;box-shadow:inset 0 0 0 2px #fbe9df55,0 6px 20px #e3423433;flex:none}` +
		`.brand h1{font-family:var(--disp);font-size:34px;font-weight:700;margin:0;color:var(--foam);letter-spacing:.5px}` +
		`.brand .tag{color:var(--wavel);font-size:13px;margin-top:4px}` +
		`.wrap{max-width:900px;margin:0 auto;padding:26px 20px 72px}` +
		`.verdict{display:flex;align-items:center;gap:12px;border-radius:12px;padding:16px 18px;margin-bottom:22px;font-size:15px;border:1px solid}` +
		`.verdict .ic{width:30px;height:30px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;flex:none}` +
		`.verdict.good{background:#12314c;border-color:#4d86b5aa;color:#dce9f4}.verdict.good .ic{background:#4d86b5;color:#06131f}` +
		`.verdict.warn{background:#352c12;border-color:#d9a441aa;color:#f1e3bd}.verdict.warn .ic{background:#d9a441;color:#2a2008}` +
		`.verdict.bad{background:#371512;border-color:#e3423488;color:#f6d0cb}.verdict.bad .ic{background:#e34234;color:#fff}` +
		`.hero-card{background:linear-gradient(180deg,#102a44,#0d2338);border:1px solid #d9a44155;border-radius:14px;padding:16px 20px;margin-bottom:12px}` +
		`.hero-card .ja4{font-weight:600;font-size:clamp(17px,3.6vw,25px);color:var(--foam);word-break:break-all;user-select:all;margin-top:6px}` +
		`.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px}@media(max-width:680px){.grid{grid-template-columns:1fr}}` +
		`.card{background:var(--panel);border:1px solid #d9a44122;border-left:3px solid var(--shu);border-radius:10px;padding:12px 14px}` +
		`.lbl{color:var(--kin);font-size:11px;letter-spacing:2px;text-transform:uppercase;margin-bottom:5px}.val{color:var(--foamc);font-size:13.5px;word-break:break-all;user-select:all}` +
		`.ua{color:var(--mute);font-size:12px;margin:0 0 20px;word-break:break-all}` +
		`.sec{background:var(--panel);border:1px solid #1b3a5b;border-radius:12px;padding:16px 18px;margin-bottom:14px}` +
		`.sh{font-family:var(--disp);color:var(--foam);font-size:15px;font-weight:700;margin-bottom:12px;display:flex;align-items:center;gap:8px}.sh::before{content:"";width:8px;height:8px;border-radius:2px;background:var(--shu)}` +
		`.kv{display:flex;justify-content:space-between;gap:12px;padding:5px 0;font-size:13px;color:var(--mute);border-bottom:1px solid #ffffff08}.kv b{color:var(--foamc);font-weight:600;word-break:break-all;text-align:right}` +
		`.cl{color:var(--kin);font-size:10.5px;letter-spacing:1.5px;text-transform:uppercase;margin:14px 0 7px}` +
		`.chips{display:flex;flex-wrap:wrap;gap:6px}.chip{background:var(--p2);border:1px solid #2e5f8655;border-radius:7px;padding:3px 9px;font-size:12px;color:var(--foamc);user-select:all}.mut{color:var(--mute)}` +
		`details{margin-top:6px}summary{color:var(--wavel);cursor:pointer;font-size:13px;padding:6px 0}` +
		`pre{background:#07111d;border:1px solid #1b3a5b;border-radius:12px;padding:16px;overflow:auto;font-size:12.5px;color:var(--foamc);max-height:460px;margin-top:10px}` +
		`a{color:var(--wavel);text-decoration:none}a:hover{color:var(--foam)}.ft{color:var(--mute);font-size:12px;margin-top:22px;border-top:1px solid #ffffff10;padding-top:16px}` +
		`</style></head><body>` +
		`<div class=hero><div class=hero-in><span class=seal>北</span><div class=brand><h1>fpcheck</h1>` +
		`<div class=tag>your TLS / HTTP2 fingerprint, exactly as the server reads it off the wire</div></div></div></div>` +
		`<div class=wrap>` +
		`<div class="verdict ` + level + `"><span class=ic>` + vicon + `</span><div>` + esc(verdict) + `</div></div>` +
		ja4hero +
		`<div class=grid>` + small + `</div>` +
		`<div class=ua>UA&nbsp;·&nbsp;` + ua + `</div>` +
		section("TLS ClientHello", tlsBody) +
		section("HTTP/2", httpBody) +
		`<details><summary>raw JSON</summary><pre>` + string(pretty) + `</pre></details>` +
		`<div class=ft><a href="/api/all">/api/all</a> &nbsp;·&nbsp; <a href="https://github.com/North-web-dev/fpcheck">github.com/North-web-dev/fpcheck</a></div>` +
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
