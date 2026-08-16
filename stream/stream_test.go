// Copyright (c) 2026 dido GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

package stream_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/eclipse-pcs/pcs"
	"github.com/eclipse-pcs/pcs/footer"
	"github.com/eclipse-pcs/pcs/stream"
)

func TestChunkHelpers(t *testing.T) {
	chunk := []byte{0, 1, 2, 3, 4, 5}
	if got := stream.EverySecondByte(chunk, 0); !bytes.Equal(got, []byte{0, 2, 4}) {
		t.Fatalf("start 0: %v", got)
	}
	if got := stream.EverySecondByte(chunk, 1); !bytes.Equal(got, []byte{1, 3, 5}) {
		t.Fatalf("start 1: %v", got)
	}
	if e, o := stream.SplitStartIndices(0); e != 0 || o != 1 {
		t.Fatalf("indices 0: %d %d", e, o)
	}
	if stream.EvenCountForRange(1, 4) != 2 {
		t.Fatal("even count")
	}
}

func TestStreamingMatchesBufferEncode(t *testing.T) {
	for n := 0; n <= 64; n++ {
		secret := make([]byte, n)
		for i := range secret {
			secret[i] = byte(i*7 + n)
		}
		noise, err := pcs.RandomNoise(n)
		if err != nil {
			t.Fatalf("n=%d noise: %v", n, err)
		}
		want, err := pcs.EncodeWithNoise(secret, noise)
		if err != nil {
			t.Fatalf("n=%d buffer encode: %v", n, err)
		}
		for _, chunkSize := range []int{1, 3, 7, 16, 32} {
			got, meta, err := stream.EncodeCollect(secret, noise, chunkSize)
			if err != nil {
				t.Fatalf("n=%d chunk=%d stream: %v", n, chunkSize, err)
			}
			assertParticle(t, n, chunkSize, "EvenCypher", want.EvenCypher, payloadOnly(got[pcs.EvenCypher]))
			assertParticle(t, n, chunkSize, "OddCypher", want.OddCypher, payloadOnly(got[pcs.OddCypher]))
			assertParticle(t, n, chunkSize, "EvenNoise", want.EvenNoise, payloadOnly(got[pcs.EvenNoise]))
			assertParticle(t, n, chunkSize, "OddNoise", want.OddNoise, payloadOnly(got[pcs.OddNoise]))
			assertParticle(t, n, chunkSize, "CypherParity", want.CypherParity, payloadOnly(got[pcs.CypherParity]))
			assertParticle(t, n, chunkSize, "NoiseParity", want.NoiseParity, payloadOnly(got[pcs.NoiseParity]))
			if meta.BytesProcessed != int64(n) {
				t.Fatalf("bytes processed %d want %d", meta.BytesProcessed, n)
			}
			if meta.Footers[pcs.EvenCypher].Length != uint64(n) {
				t.Fatalf("footer length %d", meta.Footers[pcs.EvenCypher].Length)
			}
			checkFooterCRC(t, got[pcs.EvenCypher], meta.Footers[pcs.EvenCypher])
		}
	}
}

func payloadOnly(data []byte) []byte {
	if len(data) <= footer.Size {
		return nil
	}
	return data[:len(data)-footer.Size]
}

func assertParticle(t *testing.T, n, chunk int, name string, want, got []byte) {
	t.Helper()
	if !bytes.Equal(want, got) {
		t.Fatalf("n=%d chunk=%d %s:\nwant %v\ngot  %v", n, chunk, name, want, got)
	}
}

func checkFooterCRC(t *testing.T, data []byte, f *footer.Footer) {
	t.Helper()
	if len(data) < footer.Size {
		t.Fatal("missing footer")
	}
	payload := data[:len(data)-footer.Size]
	if pcs.CRC32IEEE(payload) != f.PayloadCRC {
		t.Fatalf("payload CRC mismatch")
	}
}

func TestDecodeRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 7, 13, 32<<10 + 1} {
		secret := make([]byte, n)
		for i := range secret {
			secret[i] = byte(i*11 + n)
		}
		noise, err := pcs.RandomNoise(n)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		for _, chunkSize := range []int{1, 7, 32 << 10} {
			particles, encMeta, err := stream.EncodeCollect(secret, noise, chunkSize)
			if err != nil {
				t.Fatalf("n=%d chunk=%d encode: %v", n, chunkSize, err)
			}
			got, decMeta, err := stream.DecodeCollect(particles)
			if err != nil {
				t.Fatalf("n=%d chunk=%d decode: %v", n, chunkSize, err)
			}
			if !bytes.Equal(secret, got) {
				t.Fatalf("n=%d chunk=%d secret mismatch", n, chunkSize)
			}
			if decMeta.SHA256 != encMeta.SHA256 {
				t.Fatalf("SHA-256 mismatch")
			}
		}
	}
}

func TestRecoveryMatrix(t *testing.T) {
	for _, n := range []int{0, 1, 6, 7, 100} {
		secret := make([]byte, n)
		for i := range secret {
			secret[i] = byte(i*3 + 1)
		}
		noise, _ := pcs.RandomNoise(n)
		particles, _, err := stream.EncodeCollect(secret, noise, 16)
		if err != nil {
			t.Fatalf("encode n=%d: %v", n, err)
		}
		for _, missing := range pcs.CoreParticleKinds {
			src := buildSources(particles, missing)
			var out bytes.Buffer
			_, err := stream.NewDecoder(16).Decode(src, &out, stream.DecodeOptions{})
			if err != nil {
				t.Fatalf("n=%d missing=%v: %v", n, missing, err)
			}
			if !bytes.Equal(out.Bytes(), secret) {
				t.Fatalf("n=%d missing=%v: secret mismatch", n, missing)
			}
		}
	}
}

func TestBothOddMissingStreaming(t *testing.T) {
	secret := []byte("both odd missing case!")
	noise, _ := pcs.RandomNoise(len(secret))
	particles, _, err := stream.EncodeCollect(secret, noise, 8)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	src := stream.Sources{
		EC: sourceFor(particles[pcs.EvenCypher]),
		EN: sourceFor(particles[pcs.EvenNoise]),
		CP: sourceFor(particles[pcs.CypherParity]),
		NP: sourceFor(particles[pcs.NoiseParity]),
	}
	var out bytes.Buffer
	if _, err := stream.NewDecoder(8).Decode(src, &out, stream.DecodeOptions{}); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(out.Bytes(), secret) {
		t.Fatalf("got %q want %q", out.Bytes(), secret)
	}
}

func buildSources(particles map[pcs.ParticleKind][]byte, missing pcs.ParticleKind) stream.Sources {
	s := stream.Sources{}
	for _, kind := range pcs.AllParticleKinds {
		var src stream.Source
		if kind != missing {
			src = sourceFor(particles[kind])
		} else {
			src = stream.Source{PayloadLen: -1}
		}
		switch kind {
		case pcs.EvenCypher:
			s.EC = src
		case pcs.OddCypher:
			s.OC = src
		case pcs.EvenNoise:
			s.EN = src
		case pcs.OddNoise:
			s.ON = src
		case pcs.CypherParity:
			s.CP = src
		case pcs.NoiseParity:
			s.NP = src
		}
	}
	return s
}

func sourceFor(data []byte) stream.Source {
	payloadLen := int64(len(data) - footer.Size)
	return stream.Source{R: bytes.NewReader(data), PayloadLen: payloadLen}
}

func TestCorruptionMatrix(t *testing.T) {
	secret := []byte("corruption test data")
	noise, _ := pcs.RandomNoise(len(secret))
	particles, _, err := stream.EncodeCollect(secret, noise, 32)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	t.Run("payload CRC", func(t *testing.T) {
		bad := append([]byte(nil), particles[pcs.EvenCypher]...)
		if len(bad) > footer.Size+1 {
			bad[0] ^= 0xff
		}
		src := stream.Sources{
			EC: sourceFor(bad),
			OC: sourceFor(particles[pcs.OddCypher]),
			EN: sourceFor(particles[pcs.EvenNoise]),
			ON: sourceFor(particles[pcs.OddNoise]),
			CP: sourceFor(particles[pcs.CypherParity]),
			NP: sourceFor(particles[pcs.NoiseParity]),
		}
		var out bytes.Buffer
		if _, err := stream.NewDecoder(32).Decode(src, &out, stream.DecodeOptions{}); err == nil {
			t.Fatal("expected integrity error")
		}
	})

	t.Run("WriteID mismatch", func(t *testing.T) {
		bad := append([]byte(nil), particles[pcs.OddCypher]...)
		footerStart := len(bad) - footer.Size
		bad[footerStart+40] ^= 0xff
		src := stream.Sources{
			EC: sourceFor(particles[pcs.EvenCypher]),
			OC: sourceFor(bad),
			EN: sourceFor(particles[pcs.EvenNoise]),
			ON: sourceFor(particles[pcs.OddNoise]),
			CP: sourceFor(particles[pcs.CypherParity]),
			NP: sourceFor(particles[pcs.NoiseParity]),
		}
		var out bytes.Buffer
		if _, err := stream.NewDecoder(32).Decode(src, &out, stream.DecodeOptions{}); err == nil {
			t.Fatal("expected WriteID error")
		}
	})

	t.Run("cross-CRC via partner", func(t *testing.T) {
		// Corrupt ec payload but patch ec's own PayloadCRC so only cross-CRC catches it.
		bad := append([]byte(nil), particles[pcs.EvenCypher]...)
		payloadEnd := len(bad) - footer.Size
		if payloadEnd < 1 {
			t.Fatal("need non-empty payload")
		}
		bad[0] ^= 0xff
		corruptPayload := bad[:payloadEnd]
		binary.LittleEndian.PutUint32(bad[payloadEnd+32:], pcs.CRC32IEEE(corruptPayload))
		src := stream.Sources{
			EC: sourceFor(bad),
			OC: sourceFor(particles[pcs.OddCypher]),
			EN: sourceFor(particles[pcs.EvenNoise]),
			ON: sourceFor(particles[pcs.OddNoise]),
			CP: sourceFor(particles[pcs.CypherParity]),
			NP: sourceFor(particles[pcs.NoiseParity]),
		}
		var out bytes.Buffer
		_, err := stream.NewDecoder(32).Decode(src, &out, stream.DecodeOptions{})
		if err == nil {
			t.Fatal("expected cross-CRC integrity error")
		}
		if !strings.Contains(err.Error(), "cross-CRC") {
			t.Fatalf("expected cross-CRC error, got: %v", err)
		}
	})
}

func TestGoldenFooterBytes(t *testing.T) {
	secret := []byte{0x01, 0x02, 0x03}
	noise := []byte{0xaa, 0xbb, 0xcc}
	particles, meta, err := stream.EncodeCollect(secret, noise, 32)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for kind, data := range particles {
		if len(data) < footer.Size {
			t.Fatalf("%s too short", kind)
		}
		raw := data[len(data)-footer.Size:]
		f, err := footer.Parse(raw)
		if err != nil {
			t.Fatalf("%s footer parse: %v", kind, err)
		}
		if f.WriteID != meta.Footers[kind].WriteID {
			t.Fatalf("WriteID mismatch on %s", kind)
		}
		if f.Length != 3 {
			t.Fatalf("length on %s: %d", kind, f.Length)
		}
	}
	sum := sha256.Sum256(secret)
	if meta.SHA256 != sum {
		t.Fatal("encoder SHA-256 mismatch")
	}
}

func TestReconstructCollect(t *testing.T) {
	even := []byte{1, 2, 3}
	odd := []byte{4, 5}
	parity := pcs.ParityPadded(even, odd)
	got, err := stream.ReconstructCollect(even, parity, stream.RecoverOdd, true)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(got, odd) {
		t.Fatalf("got %v want %v", got, odd)
	}
}

func TestPropertyRoundTrip(t *testing.T) {
	chunkSize := 17
	for seed := 0; seed < 40; seed++ {
		n := seed % (4*chunkSize + 4)
		secret := make([]byte, n)
		for i := range secret {
			secret[i] = byte(i*13 + seed)
		}
		noise, _ := pcs.RandomNoise(n)
		particles, _, err := stream.EncodeCollect(secret, noise, chunkSize)
		if err != nil {
			t.Fatalf("seed=%d encode: %v", seed, err)
		}
		if seed%3 == 0 {
			got, _, err := stream.DecodeCollect(particles)
			if err != nil || !bytes.Equal(got, secret) {
				t.Fatalf("seed=%d full decode: %v", seed, err)
			}
			continue
		}
		missing := pcs.CoreParticleKinds[seed%len(pcs.CoreParticleKinds)]
		src := buildSources(particles, missing)
		var out bytes.Buffer
		if _, err := stream.NewDecoder(chunkSize).Decode(src, &out, stream.DecodeOptions{}); err != nil {
			t.Fatalf("seed=%d missing=%v: %v", seed, missing, err)
		}
		if !bytes.Equal(out.Bytes(), secret) {
			t.Fatalf("seed=%d missing=%v", seed, missing)
		}
	}
}
