package ja3

import (
	"testing"

	"github.com/North-web-dev/fpcheck/internal/tlsparse"
)

// Ground truth from the Salesforce JA3 reference.
func TestKnownVector(t *testing.T) {
	ch := &tlsparse.ClientHello{
		LegacyVersion:   769,
		CipherSuites:    []uint16{47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4},
		Extensions:      []uint16{0, 10, 11},
		SupportedGroups: []uint16{23, 24, 25},
		ECPointFormats:  []uint8{0},
	}
	wantStr := "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
	wantHash := "ada70206e40642a3e4461f35503241d5"

	gotStr, gotHash := FromClientHello(ch)
	if gotStr != wantStr {
		t.Errorf("string:\n got %q\nwant %q", gotStr, wantStr)
	}
	if gotHash != wantHash {
		t.Errorf("hash: got %s want %s", gotHash, wantHash)
	}
}

func TestGREASEFiltered(t *testing.T) {
	ch := &tlsparse.ClientHello{
		LegacyVersion:   771,
		CipherSuites:    []uint16{0x0a0a, 4865, 4866}, // 0x0a0a is GREASE
		Extensions:      []uint16{0x1a1a, 0, 10},      // 0x1a1a is GREASE
		SupportedGroups: []uint16{0x2a2a, 29},         // 0x2a2a is GREASE
	}
	str, _ := FromClientHello(ch)
	want := "771,4865-4866,0-10,29,"
	if str != want {
		t.Errorf("GREASE not filtered:\n got %q\nwant %q", str, want)
	}
}
