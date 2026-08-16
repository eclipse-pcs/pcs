// Copyright (c) 2026 dido GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

package stream

import (
	"bytes"
	"testing"

	"github.com/eclipse-pcs/pcs"
)

func TestReconstructCollectMatchesBufferRecovery(t *testing.T) {
	cases := []struct {
		name    string
		secret  []byte
		missing pcs.ParticleKind
	}{
		{"even_ec", bytes.Repeat([]byte("ab"), 16), pcs.EvenCypher},
		{"even_oc", bytes.Repeat([]byte("cd"), 16), pcs.OddCypher},
		{"odd_ec", []byte("odd-len-secret!!"), pcs.EvenCypher},
		{"odd_on", []byte("odd-len-secret!!"), pcs.OddNoise},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := pcs.Encode(tc.secret)
			if err != nil {
				t.Fatal(err)
			}
			wantData := map[pcs.ParticleKind][]byte{
				pcs.EvenCypher: result.EvenCypher, pcs.OddCypher: result.OddCypher,
				pcs.EvenNoise: result.EvenNoise, pcs.OddNoise: result.OddNoise,
				pcs.CypherParity: result.CypherParity, pcs.NoiseParity: result.NoiseParity,
			}
			delete(wantData, tc.missing)
			present := map[pcs.ParticleKind]bool{}
			for k, v := range wantData {
				present[k] = len(v) > 0
			}
			if err := pcs.RecoverCoreParticlesInto(pcs.NewParticleInventory(present), wantData, int64(len(tc.secret))); err != nil {
				t.Fatal(err)
			}
			want := wantData[tc.missing]
			var partner, parity []byte
			var role RecoverRole
			oddLength := len(tc.secret)%2 == 1
			switch tc.missing {
			case pcs.EvenCypher:
				partner, parity = result.OddCypher, result.CypherParity
				role = RecoverEven
			case pcs.OddCypher:
				partner, parity = result.EvenCypher, result.CypherParity
				role = RecoverOdd
			case pcs.EvenNoise:
				partner, parity = result.OddNoise, result.NoiseParity
				role = RecoverEven
			case pcs.OddNoise:
				partner, parity = result.EvenNoise, result.NoiseParity
				role = RecoverOdd
			default:
				t.Fatalf("unknown missing %s", tc.missing)
			}
			got, err := ReconstructCollect(partner, parity, role, oddLength)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(want, got) {
				t.Fatalf("missing %s:\nwant %v\ngot  %v", tc.missing, want, got)
			}
		})
	}
}

func TestMergeInterleaved(t *testing.T) {
	got := MergeInterleaved([]byte{10, 30}, []byte{20, 40}, 0, 4)
	want := []byte{10, 20, 30, 40}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestSkipCoreStreams(t *testing.T) {
	secret := []byte("skip offset test")
	noise, _ := pcs.RandomNoise(len(secret))
	particles, _, err := EncodeCollect(secret, noise, 8)
	if err != nil {
		t.Fatal(err)
	}
	src := Sources{
		EC: Source{R: bytes.NewReader(particles[pcs.EvenCypher]), PayloadLen: int64(len(particles[pcs.EvenCypher]) - 64)},
		OC: Source{R: bytes.NewReader(particles[pcs.OddCypher]), PayloadLen: int64(len(particles[pcs.OddCypher]) - 64)},
		EN: Source{R: bytes.NewReader(particles[pcs.EvenNoise]), PayloadLen: int64(len(particles[pcs.EvenNoise]) - 64)},
		ON: Source{R: bytes.NewReader(particles[pcs.OddNoise]), PayloadLen: int64(len(particles[pcs.OddNoise]) - 64)},
		CP: Source{R: bytes.NewReader(particles[pcs.CypherParity]), PayloadLen: int64(len(particles[pcs.CypherParity]) - 64)},
		NP: Source{R: bytes.NewReader(particles[pcs.NoiseParity]), PayloadLen: int64(len(particles[pcs.NoiseParity]) - 64)},
	}
	var out bytes.Buffer
	meta, err := NewDecoder(8).Decode(src, &out, DecodeOptions{StartOffset: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), secret[3:]) {
		t.Fatalf("got %q want %q", out.Bytes(), secret[3:])
	}
	if meta.BytesRead != int64(len(secret)) {
		t.Fatalf("bytes read %d", meta.BytesRead)
	}
}

func TestNewEncoderRandomNoise(t *testing.T) {
	var ec, oc, en, on, cp, np bytesCollector
	enc := NewEncoder(16)
	_, err := enc.Encode(bytes.NewReader([]byte("random noise")), Writers{EC: &ec, OC: &oc, EN: &en, ON: &on, CP: &cp, NP: &np}, EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
}
