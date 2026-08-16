// Copyright (c) 2026 dido GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

package footer_test

import (
	"bytes"
	"testing"

	"github.com/eclipse-pcs/pcs"
	"github.com/eclipse-pcs/pcs/footer"
)

func TestFooterMarshalParseRoundTrip(t *testing.T) {
	want := &footer.Footer{
		Version:    footer.Version,
		Kind:       pcs.EvenCypher,
		Length:     42,
		PayloadCRC: 0x12345678,
		CrossCRC:   0xabcdef01,
		WriteID:    0x7f3a9b2c1d4e5f60,
		Mtime:      1700000000000000000,
	}
	want.FingerprintShard[0] = 0xde
	want.FingerprintShard[15] = 0xef

	raw := want.Marshal()
	got, err := footer.Parse(raw[:])
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Kind != want.Kind || got.Length != want.Length ||
		got.PayloadCRC != want.PayloadCRC || got.CrossCRC != want.CrossCRC ||
		got.WriteID != want.WriteID || got.Mtime != want.Mtime {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}
	if got.FingerprintShard != want.FingerprintShard {
		t.Fatalf("fingerprint shard mismatch")
	}
}

func TestParseFooterValidation(t *testing.T) {
	valid := (&footer.Footer{Kind: pcs.EvenCypher, WriteID: 1, Length: 0}).Marshal()
	cases := []struct {
		name string
		data []byte
	}{
		{"short", valid[:32]},
		{"bad magic", append([]byte("BAD\x00"), valid[4:]...)},
		{"bad version", func() []byte { b := valid; b[5] = 2; c := b; return c[:] }()},
		{"bad kind", func() []byte { b := valid; b[6] = 9; return b[:] }()},
		{"bad flags", func() []byte { b := valid; b[7] = 1; return b[:] }()},
		{"zero wid", func() []byte {
			b := valid
			b[40], b[41], b[42], b[43], b[44], b[45], b[46], b[47] = 0, 0, 0, 0, 0, 0, 0, 0
			return b[:]
		}()},
		{"reserved", func() []byte { b := valid; b[56] = 1; return b[:] }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := footer.Parse(tc.data); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestPayloadLen(t *testing.T) {
	if _, err := footer.PayloadLen(32); err == nil {
		t.Fatal("expected error for size < 64")
	}
	got, err := footer.PayloadLen(100)
	if err != nil || got != 36 {
		t.Fatalf("PayloadLen(100) = %d, %v", got, err)
	}
}

func TestLogicalSizeDerivation(t *testing.T) {
	if n := footer.LogicalSizeFromPayloadSizes(6, 5); n != 11 {
		t.Fatalf("odd length: got %d want 11", n)
	}
	if n := footer.LogicalSizeFromPayloadSizes(6, 6); n != 12 {
		t.Fatalf("even length: got %d want 12", n)
	}
	odd, even := footer.LogicalSizeCandidates(6)
	if odd != 11 || even != 12 {
		t.Fatalf("candidates: odd=%d even=%d", odd, even)
	}
}

func TestNewWriteIDNonZero(t *testing.T) {
	id, err := footer.NewWriteID()
	if err != nil || id == 0 {
		t.Fatalf("NewWriteID: id=%x err=%v", id, err)
	}
}

func TestReadAt(t *testing.T) {
	f := &footer.Footer{Kind: pcs.OddNoise, WriteID: 99, Length: 7}
	raw := f.Marshal()
	data := append([]byte("payload-bytes"), raw[:]...)
	r := bytes.NewReader(data)
	got, err := footer.ReadAt(r, int64(len(data)))
	if err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if got.WriteID != 99 || got.Kind != pcs.OddNoise {
		t.Fatalf("got %+v", got)
	}
}

func TestVerifyCrossCRC(t *testing.T) {
	left := []byte("hello-left")
	right := []byte("hello-right")
	lc := pcs.CRC32IEEE(left)
	rc := pcs.CRC32IEEE(right)

	if v := footer.VerifyCrossCRC(left, rc, right, lc); v != footer.CrossOK {
		t.Fatalf("expected CrossOK, got %v", v)
	}
	if v := footer.VerifyCrossCRC([]byte("tampered"), rc, right, lc); v != footer.CrossLeftCorrupt {
		t.Fatalf("expected CrossLeftCorrupt, got %v", v)
	}
	if v := footer.VerifyCrossCRC(left, rc, []byte("tampered"), lc); v != footer.CrossRightCorrupt {
		t.Fatalf("expected CrossRightCorrupt, got %v", v)
	}
	if v := footer.VerifyCrossCRC([]byte("x"), rc, []byte("y"), lc); v != footer.CrossBothCorrupt {
		t.Fatalf("expected CrossBothCorrupt, got %v", v)
	}
}

func TestVerifyCrossCRCSums(t *testing.T) {
	left := []byte("hello-left")
	right := []byte("hello-right")
	lc := pcs.CRC32IEEE(left)
	rc := pcs.CRC32IEEE(right)

	if v := footer.VerifyCrossCRCSums(lc, rc, rc, lc); v != footer.CrossOK {
		t.Fatalf("expected CrossOK, got %v", v)
	}
	if v := footer.VerifyCrossCRCSums(lc^0xffffffff, rc, rc, lc); v != footer.CrossLeftCorrupt {
		t.Fatalf("expected CrossLeftCorrupt, got %v", v)
	}
	if v := footer.VerifyCrossCRCSums(lc, rc, rc^0xffffffff, lc); v != footer.CrossRightCorrupt {
		t.Fatalf("expected CrossRightCorrupt, got %v", v)
	}
	if v := footer.VerifyCrossCRCSums(0, rc, 0, lc); v != footer.CrossBothCorrupt {
		t.Fatalf("expected CrossBothCorrupt, got %v", v)
	}
}

func TestVerifyWriteIDs(t *testing.T) {
	f1 := &footer.Footer{WriteID: 0xabc}
	f2 := &footer.Footer{WriteID: 0xabc}
	if err := footer.VerifyWriteIDs(map[pcs.ParticleKind]*footer.Footer{
		pcs.EvenCypher: f1, pcs.OddCypher: f2,
	}); err != nil {
		t.Fatalf("agreeing IDs: %v", err)
	}
	f2.WriteID = 0xdef
	if err := footer.VerifyWriteIDs(map[pcs.ParticleKind]*footer.Footer{
		pcs.EvenCypher: f1, pcs.OddCypher: f2,
	}); err == nil {
		t.Fatal("expected WriteID mismatch error")
	}
}

func TestPartnerKindPairs(t *testing.T) {
	if footer.PartnerKind(pcs.EvenCypher) != pcs.OddCypher {
		t.Fatal("ec partner")
	}
	if footer.PartnerKind(pcs.OddNoise) != pcs.EvenNoise {
		t.Fatal("on partner")
	}
}
