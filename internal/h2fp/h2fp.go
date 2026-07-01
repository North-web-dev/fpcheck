// Package h2fp reads a raw HTTP/2 connection (after TLS termination) and derives
// the Akamai HTTP/2 fingerprint together with the request needed for JA4H.
//
// The Akamai fingerprint has four sections joined by "|":
//
//	SETTINGS | WINDOW_UPDATE | PRIORITY | pseudo-header order
//
// e.g. 1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p
package h2fp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/http2/hpack"

	"github.com/North-web-dev/fpcheck/internal/ja4"
)

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// Frame types.
const (
	frameData         = 0x0
	frameHeaders      = 0x1
	framePriority     = 0x2
	frameSettings     = 0x4
	frameWindowUpdate = 0x8
)

// HEADERS flags.
const (
	flagEndStream  = 0x1
	flagEndHeaders = 0x4
	flagPadded     = 0x8
	flagPriority   = 0x20
	flagAck        = 0x1
)

// Info is the result of reading one HTTP/2 request.
type Info struct {
	StreamID    uint32
	Akamai      string
	HeaderOrder []string
	Path        string
	Request     ja4.Request
}

// ReadRequest reads the client preface and frames up to the first request
// HEADERS, sends the server SETTINGS and a SETTINGS ACK, and returns the
// captured fingerprint data.
func ReadRequest(conn io.ReadWriter) (*Info, error) {
	buf := make([]byte, len(preface))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	if string(buf) != preface {
		return nil, errors.New("h2fp: bad connection preface")
	}
	// Server SETTINGS must be the first frame we send.
	if err := writeFrame(conn, frameSettings, 0, 0, nil); err != nil {
		return nil, err
	}

	var settings, priorities []string
	windowUpdate := "0"
	dec := hpack.NewDecoder(4096, nil)

	for {
		ftype, flags, sid, payload, err := readFrame(conn)
		if err != nil {
			return nil, err
		}
		switch ftype {
		case frameSettings:
			if flags&flagAck == 0 {
				settings = parseSettings(payload)
				_ = writeFrame(conn, frameSettings, flagAck, 0, nil)
			}
		case frameWindowUpdate:
			if sid == 0 && len(payload) == 4 {
				windowUpdate = fmt.Sprintf("%d", binary.BigEndian.Uint32(payload)&0x7fffffff)
			}
		case framePriority:
			if p := parsePriority(sid, payload); p != "" {
				priorities = append(priorities, p)
			}
		case frameHeaders:
			order, req, path, err := parseHeaders(dec, flags, payload)
			if err != nil {
				return nil, err
			}
			return &Info{
				StreamID:    sid,
				Akamai:      strings.Join(settings, ";") + "|" + windowUpdate + "|" + prioOrZero(priorities) + "|" + pseudoOrder(order),
				HeaderOrder: order,
				Path:        path,
				Request:     req,
			}, nil
		}
	}
}

func parseSettings(p []byte) []string {
	var out []string
	for i := 0; i+6 <= len(p); i += 6 {
		id := binary.BigEndian.Uint16(p[i:])
		val := binary.BigEndian.Uint32(p[i+2:])
		out = append(out, fmt.Sprintf("%d:%d", id, val))
	}
	return out
}

func parsePriority(sid uint32, p []byte) string {
	if len(p) < 5 {
		return ""
	}
	dep := binary.BigEndian.Uint32(p[0:4])
	excl := 0
	if dep&0x80000000 != 0 {
		excl = 1
	}
	weight := int(p[4]) + 1
	return fmt.Sprintf("%d:%d:%d:%d", sid, excl, dep&0x7fffffff, weight)
}

// parseHeaders decodes the HPACK block (accounting for padding/priority) and
// returns the header name order plus the JA4H request.
func parseHeaders(dec *hpack.Decoder, flags byte, payload []byte) ([]string, ja4.Request, string, error) {
	block := payload
	if flags&flagPadded != 0 {
		if len(block) == 0 {
			return nil, ja4.Request{}, "", errors.New("h2fp: bad padded HEADERS")
		}
		pad := int(block[0])
		block = block[1:]
		if pad > len(block) {
			return nil, ja4.Request{}, "", errors.New("h2fp: pad exceeds frame")
		}
		block = block[:len(block)-pad]
	}
	if flags&flagPriority != 0 {
		if len(block) < 5 {
			return nil, ja4.Request{}, "", errors.New("h2fp: bad HEADERS priority")
		}
		block = block[5:]
	}

	var order []string
	var path string
	req := ja4.Request{Proto: "HTTP/2.0"}
	fields, err := dec.DecodeFull(block)
	if err != nil {
		return nil, ja4.Request{}, "", err
	}
	for _, hf := range fields {
		if strings.HasPrefix(hf.Name, ":") {
			order = append(order, hf.Name)
			switch hf.Name {
			case ":method":
				req.Method = hf.Value
			case ":path":
				path = hf.Value
			}
			continue
		}
		order = append(order, hf.Name)
		req.Headers = append(req.Headers, ja4.Header{Name: hf.Name, Value: hf.Value})
	}
	return order, req, path, nil
}

// pseudoOrder maps the pseudo-header order to the Akamai m,a,s,p shorthand.
func pseudoOrder(order []string) string {
	var out []string
	for _, name := range order {
		switch name {
		case ":method":
			out = append(out, "m")
		case ":authority":
			out = append(out, "a")
		case ":scheme":
			out = append(out, "s")
		case ":path":
			out = append(out, "p")
		}
	}
	return strings.Join(out, ",")
}

func prioOrZero(p []string) string {
	if len(p) == 0 {
		return "0"
	}
	return strings.Join(p, ",")
}

// WriteJSON sends a minimal HTTP/2 response (200 with a JSON body) on streamID.
func WriteJSON(w io.Writer, streamID uint32, body []byte) error {
	var hb strings.Builder
	enc := hpack.NewEncoder(&hb)
	_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	_ = enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/json"})
	if err := writeFrame(w, frameHeaders, flagEndHeaders, streamID, []byte(hb.String())); err != nil {
		return err
	}
	return writeFrame(w, frameData, flagEndStream, streamID, body)
}

func readFrame(r io.Reader) (ftype, flags byte, streamID uint32, payload []byte, err error) {
	hdr := make([]byte, 9)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return
	}
	length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	ftype = hdr[3]
	flags = hdr[4]
	streamID = binary.BigEndian.Uint32(hdr[5:]) & 0x7fffffff
	payload = make([]byte, length)
	_, err = io.ReadFull(r, payload)
	return
}

func writeFrame(w io.Writer, ftype, flags byte, streamID uint32, payload []byte) error {
	hdr := make([]byte, 9)
	n := len(payload)
	hdr[0], hdr[1], hdr[2] = byte(n>>16), byte(n>>8), byte(n)
	hdr[3] = ftype
	hdr[4] = flags
	binary.BigEndian.PutUint32(hdr[5:], streamID)
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}
