package h2fp

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
)

// TestReadRequest drives ReadRequest with a hand-built HTTP/2 client: preface,
// a SETTINGS frame, then a HEADERS frame, and checks the derived Akamai
// fingerprint and request.
func TestReadRequest(t *testing.T) {
	client, srv := net.Pipe()
	defer client.Close()
	defer srv.Close()

	// Continuously drain the server's writes (its SETTINGS + ACK + response).
	go io.Copy(io.Discard, client)

	go func() {
		client.SetDeadline(time.Now().Add(2 * time.Second))
		io.WriteString(client, preface)

		// SETTINGS: HEADER_TABLE_SIZE=65536, INITIAL_WINDOW_SIZE=131072.
		settings := []byte{0, 1, 0, 1, 0, 0, 0, 4, 0, 2, 0, 0}
		writeFrame(client, frameSettings, 0, 0, settings)

		var hb strings.Builder
		enc := hpack.NewEncoder(&hb)
		enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
		enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/api/all"})
		enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
		enc.WriteField(hpack.HeaderField{Name: ":authority", Value: "x"})
		enc.WriteField(hpack.HeaderField{Name: "user-agent", Value: "probe"})
		writeFrame(client, frameHeaders, flagEndHeaders|flagEndStream, 1, []byte(hb.String()))
	}()

	srv.SetDeadline(time.Now().Add(2 * time.Second))
	info, err := ReadRequest(srv)
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}

	wantAkamai := "1:65536;4:131072|0|0|m,p,s,a"
	if info.Akamai != wantAkamai {
		t.Errorf("akamai:\n got %s\nwant %s", info.Akamai, wantAkamai)
	}
	if info.Request.Method != "GET" {
		t.Errorf("method: got %q want GET", info.Request.Method)
	}
	if info.Path != "/api/all" {
		t.Errorf("path: got %q want /api/all", info.Path)
	}
	if info.StreamID != 1 {
		t.Errorf("stream: got %d want 1", info.StreamID)
	}
}

// TestWriteJSONFramesClosedCleanly checks that a response ends with a GOAWAY
// frame. Without it, clients close the socket after the DATA frame see a
// truncated connection (curl exit 56) even though the body arrived intact.
func TestWriteJSONFramesClosedCleanly(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, 3, []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var types []byte
	var sawEndStream, sawGoAway bool
	r := bytes.NewReader(buf.Bytes())
	for r.Len() > 0 {
		ftype, flags, _, _, err := readFrame(r)
		if err != nil {
			t.Fatalf("readFrame: %v", err)
		}
		types = append(types, ftype)
		if ftype == frameData && flags&flagEndStream != 0 {
			sawEndStream = true
		}
		if ftype == frameGoAway {
			sawGoAway = true
		}
	}

	want := []byte{frameHeaders, frameData, frameGoAway}
	if !bytes.Equal(types, want) {
		t.Errorf("frame sequence: got %v want %v", types, want)
	}
	if !sawEndStream {
		t.Error("DATA frame missing END_STREAM flag")
	}
	if !sawGoAway {
		t.Error("response did not end with GOAWAY")
	}
}
