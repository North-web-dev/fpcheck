package ja4

import (
	"sort"
	"strings"
)

// Header is a single request header with order preserved.
type Header struct {
	Name  string
	Value string
}

// Request carries the HTTP request fields JA4H needs, with header order as
// received on the wire.
type Request struct {
	Method  string
	Proto   string // e.g. "HTTP/1.1", "HTTP/2.0"
	Headers []Header
}

// JA4H computes the JA4H HTTP request fingerprint, e.g.
// ge11cn020000_000000000000_000000000000_000000000000.
func JA4H(req Request) string {
	var cookieHeader string
	var acceptLang string
	hdrCount := 0
	var names []string

	for _, h := range req.Headers {
		l := strings.ToLower(h.Name)
		switch l {
		case "cookie":
			cookieHeader = h.Value
			continue
		case "referer":
			continue
		case "accept-language":
			if acceptLang == "" {
				acceptLang = h.Value
			}
		}
		hdrCount++
		names = append(names, h.Name)
	}

	cookieFlag := "n"
	if cookieHeader != "" {
		cookieFlag = "c"
	}
	refererFlag := "n"
	for _, h := range req.Headers {
		if strings.EqualFold(h.Name, "referer") {
			refererFlag = "r"
			break
		}
	}

	a := methodCode(req.Method) + httpVersionCode(req.Proto) + cookieFlag + refererFlag +
		twoDigit(hdrCount) + langCode(acceptLang)

	b := emptyHash
	if len(names) > 0 {
		b = trunc(strings.Join(names, ","))
	}

	cNames, cPairs := cookies(cookieHeader)
	c, d := emptyHash, emptyHash
	if len(cNames) > 0 {
		sort.Strings(cNames)
		sort.Strings(cPairs)
		c = trunc(strings.Join(cNames, ","))
		d = trunc(strings.Join(cPairs, ","))
	}
	return a + "_" + b + "_" + c + "_" + d
}

func methodCode(m string) string {
	m = strings.ToLower(m)
	if len(m) >= 2 {
		return m[:2]
	}
	return "xx"
}

func httpVersionCode(proto string) string {
	switch {
	case strings.HasPrefix(proto, "HTTP/1.1"):
		return "11"
	case strings.HasPrefix(proto, "HTTP/1.0"):
		return "10"
	case strings.HasPrefix(proto, "HTTP/2"):
		return "20"
	case strings.HasPrefix(proto, "HTTP/3"):
		return "30"
	case strings.HasPrefix(proto, "HTTP/0.9"):
		return "09"
	default:
		return "00"
	}
}

// langCode is the first four characters of the primary Accept-Language value,
// lowercased with hyphens removed, or "0000" if absent.
func langCode(al string) string {
	if al == "" {
		return "0000"
	}
	primary := al
	for _, sep := range []string{",", ";"} {
		if i := strings.Index(primary, sep); i >= 0 {
			primary = primary[:i]
		}
	}
	primary = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(primary), "-", ""))
	if len(primary) >= 4 {
		return primary[:4]
	}
	return primary + strings.Repeat("0", 4-len(primary))
}

func cookies(header string) (names, pairs []string) {
	if header == "" {
		return nil, nil
	}
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name := part
		if i := strings.Index(part, "="); i >= 0 {
			name = part[:i]
		}
		names = append(names, name)
		pairs = append(pairs, part)
	}
	return names, pairs
}
