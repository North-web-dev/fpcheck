package model

import "testing"

func TestDiffSegmentAware(t *testing.T) {
	got := &Fingerprint{JA4: "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb"}

	// Full reference matching a and b but differing on c.
	full := &Fingerprint{JA4: "t13d1516h2_aaaaaaaaaaaa_cccccccccccc"}
	d := Diff(got, full)
	if len(d) != 1 || d[0].Field != "ja4_c" {
		t.Fatalf("expected only ja4_c to differ, got %v", d)
	}

	// Prefix-only reference: only the a-segment is compared, and it matches.
	prefix := &Fingerprint{JA4: "t13d1516h2"}
	if d := Diff(got, prefix); len(d) != 0 {
		t.Fatalf("prefix reference should match on a-segment, got %v", d)
	}

	// Prefix-only reference that differs on the a-segment.
	other := &Fingerprint{JA4: "t13i1516h2"}
	if d := Diff(got, other); len(d) != 1 || d[0].Field != "ja4_a" {
		t.Fatalf("expected ja4_a mismatch, got %v", d)
	}
}

func TestDiffSkipsEmptyReferenceFields(t *testing.T) {
	got := &Fingerprint{JA4: "t13d1516h2_x_y", JA4H: "abc", AkamaiH2: "1:2"}
	// Reference pins only JA4; JA4H/Akamai empty must not produce deltas.
	ref := &Fingerprint{JA4: "t13d1516h2_x_y"}
	if d := Diff(got, ref); len(d) != 0 {
		t.Fatalf("empty reference fields should be skipped, got %v", d)
	}
}
