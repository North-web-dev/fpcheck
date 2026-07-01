package h2fp

import (
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
