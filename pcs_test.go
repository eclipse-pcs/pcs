// Copyright (c) 2026 dido GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

package pcs_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/eclipse-pcs/pcs"
)

var testPayloads = map[string][]byte{
	"empty":     {},
	"one byte":  {0x42},
	"two bytes": {0x01, 0x02},
	"odd len":   []byte("hello"),
	"even len":  []byte("abcdef"),
	"binary":    {0x00, 0xff, 0x10, 0x80, 0x7f, 0x01, 0xfe},
}

func TestSplitMergeRoundTrip(t *testing.T) {
	for name, payload := range testPayloads {
		t.Run(name, func(t *testing.T) {
			even, odd := pcs.Split(payload)
			if got, want := len(even), (len(payload)+1)/2; got != want {
				t.Fatalf("even length = %d, want %d", got, want)
			}
			if got, want := len(odd), len(payload)/2; got != want {
				t.Fatalf("odd length = %d, want %d", got, want)
			}
			merged := pcs.Merge(even, odd)
			if !bytes.Equal(merged, payload) {
				t.Fatalf("Merge(Split(x)) = %v, want %v", merged, payload)
			}
		})
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	for name, payload := range testPayloads {
		t.Run(name, func(t *testing.T) {
			noise, err := pcs.RandomNoise(len(payload))
			if err != nil {
				t.Fatalf("RandomNoise: %v", err)
			}
			cypher := pcs.Encrypt(payload, noise)
			secret, err := pcs.Decrypt(cypher, noise)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(secret, payload) {
				t.Fatalf("Decrypt(Encrypt(x)) = %v, want %v", secret, payload)
			}
		})
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	for name, payload := range testPayloads {
		t.Run(name, func(t *testing.T) {
			enc, err := pcs.Encode(payload)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			got, err := pcs.DecodeFromParticles(enc.EvenCypher, enc.OddCypher, enc.EvenNoise, enc.OddNoise)
			if err != nil {
				t.Fatalf("DecodeFromParticles: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("round trip = %v, want %v", got, payload)
			}
		})
	}
}

func TestRecoverMissingCoreParticle(t *testing.T) {
	for _, secret := range [][]byte{
		[]byte("Hello Freiburg"),
		[]byte("Hello"),
		[]byte("x"),
		{},
	} {
		result, err := pcs.Encode(secret)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		for _, missing := range pcs.CoreParticleKinds {
			particles := map[pcs.ParticleKind][]byte{
				pcs.EvenCypher:   result.EvenCypher,
				pcs.OddCypher:    result.OddCypher,
				pcs.EvenNoise:    result.EvenNoise,
				pcs.OddNoise:     result.OddNoise,
				pcs.CypherParity: result.CypherParity,
				pcs.NoiseParity:  result.NoiseParity,
			}
			present := map[pcs.ParticleKind]bool{}
			for k, v := range particles {
				present[k] = v != nil
			}
			delete(particles, missing)
			present[missing] = false

			inv, err := pcs.InventoryFromPresent(present)
			if err != nil {
				t.Fatalf("inventory: %v", err)
			}
			got, usedParity, err := pcs.DecodeWithRecovery(inv, particles, int64(len(secret)))
			if err != nil {
				t.Fatalf("secret=%q missing=%v: %v", secret, missing, err)
			}
			if !usedParity {
				t.Fatalf("expected parity recovery for missing %v", missing)
			}
			if !bytes.Equal(got, secret) {
				t.Fatalf("secret=%q missing=%v: got %q", secret, missing, got)
			}
		}
	}
}

func TestRecoverBothOddMissing(t *testing.T) {
	secret := []byte("odd length!")
	result, err := pcs.Encode(secret)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	particles := map[pcs.ParticleKind][]byte{
		pcs.EvenCypher:   result.EvenCypher,
		pcs.EvenNoise:    result.EvenNoise,
		pcs.CypherParity: result.CypherParity,
		pcs.NoiseParity:  result.NoiseParity,
	}
	present := map[pcs.ParticleKind]bool{
		pcs.EvenCypher: true, pcs.EvenNoise: true,
		pcs.CypherParity: true, pcs.NoiseParity: true,
	}
	inv, err := pcs.InventoryFromPresent(present)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	got, _, err := pcs.DecodeWithRecovery(inv, particles, int64(len(secret)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("got %q want %q", got, secret)
	}
}

func TestFingerprintRoundTrip(t *testing.T) {
	secret := []byte("fingerprint test payload")
	sum := sha256.Sum256(secret)
	fpEnc, err := pcs.EncodeFingerprint(sum)
	if err != nil {
		t.Fatalf("EncodeFingerprint: %v", err)
	}
	shards := map[pcs.ParticleKind][]byte{
		pcs.EvenCypher:   fpEnc.EvenCypher,
		pcs.OddCypher:    fpEnc.OddCypher,
		pcs.EvenNoise:    fpEnc.EvenNoise,
		pcs.OddNoise:     fpEnc.OddNoise,
		pcs.CypherParity: fpEnc.CypherParity,
		pcs.NoiseParity:  fpEnc.NoiseParity,
	}
	present := map[pcs.ParticleKind]bool{}
	for k := range shards {
		present[k] = true
	}
	got, err := pcs.DecodeFingerprint(present, shards)
	if err != nil {
		t.Fatalf("DecodeFingerprint: %v", err)
	}
	if got != sum {
		t.Fatalf("digest mismatch")
	}
}

func TestRecoverAllFingerprintShards(t *testing.T) {
	sum := sha256.Sum256([]byte("shard recovery"))
	fpEnc, err := pcs.EncodeFingerprint(sum)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	present := map[pcs.ParticleKind]bool{
		pcs.EvenCypher: true, pcs.OddCypher: true,
		pcs.EvenNoise: true, pcs.OddNoise: true,
	}
	shards := map[pcs.ParticleKind][]byte{
		pcs.EvenCypher: fpEnc.EvenCypher,
		pcs.OddCypher:  fpEnc.OddCypher,
		pcs.EvenNoise:  fpEnc.EvenNoise,
		pcs.OddNoise:   fpEnc.OddNoise,
	}
	got, err := pcs.RecoverAllFingerprintShards(present, shards)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if len(got[pcs.CypherParity]) == 0 || len(got[pcs.NoiseParity]) == 0 {
		t.Fatal("expected parity shards computed")
	}
	digest, err := pcs.DecodeFingerprint(map[pcs.ParticleKind]bool{
		pcs.EvenCypher: true, pcs.OddCypher: true,
		pcs.EvenNoise: true, pcs.OddNoise: true,
		pcs.CypherParity: true, pcs.NoiseParity: true,
	}, got)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if digest != sum {
		t.Fatal("digest mismatch after recovery")
	}
}

func TestLayout(t *testing.T) {
	keys := pcs.AllShardKeys("myfile.txt")
	if keys[pcs.EvenCypher] != "myfile.txt.ec" {
		t.Fatalf("EvenCypher key = %q", keys[pcs.EvenCypher])
	}
	if pcs.StorageForParticle(pcs.CypherParity) != pcs.StorageC {
		t.Fatalf("CypherParity storage = %q", pcs.StorageForParticle(pcs.CypherParity))
	}
	logical, kind, ok := pcs.LogicalKeyFromShard("myfile.txt.np")
	if !ok || logical != "myfile.txt" || kind != pcs.NoiseParity {
		t.Fatalf("LogicalKeyFromShard = %q %v %v", logical, kind, ok)
	}
}

func TestCRC32IEEE(t *testing.T) {
	data := []byte("crc test")
	if pcs.CRC32IEEE(data) == 0 {
		t.Fatal("expected non-zero CRC")
	}
}

func TestParticleKindString(t *testing.T) {
	if pcs.EvenCypher.String() != "evenCypher" {
		t.Fatal("string")
	}
	if pcs.ParticleKind(99).String() != "unknown" {
		t.Fatal("unknown kind")
	}
}

func TestEncodeResultShard(t *testing.T) {
	r, err := pcs.Encode([]byte("ab"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pcs.EncodeResultShard(r, pcs.EvenCypher), r.EvenCypher) {
		t.Fatal("shard")
	}
	if pcs.EncodeResultShard(r, pcs.ParticleKind(99)) != nil {
		t.Fatal("unknown shard")
	}
}

func TestParticleSuffixAndIsShard(t *testing.T) {
	if pcs.ParticleSuffix(pcs.OddCypher) != ".oc" {
		t.Fatal("suffix")
	}
	if !pcs.IsParticleShard("file.txt.ec") {
		t.Fatal("is shard")
	}
	if pcs.IsParticleShard("file.txt") {
		t.Fatal("not shard")
	}
	if pcs.StorageForParticle(pcs.ParticleKind(99)) != "" {
		t.Fatal("unknown storage")
	}
}

func TestInventoryFromPresentError(t *testing.T) {
	_, err := pcs.InventoryFromPresent(map[pcs.ParticleKind]bool{pcs.EvenCypher: true})
	if err == nil {
		t.Fatal("expected parity required error")
	}
}

func TestReconstructErrors(t *testing.T) {
	if _, err := pcs.ReconstructFromParityEven([]byte{1}, []byte{1, 2}); err == nil {
		t.Fatal("length mismatch")
	}
	if _, err := pcs.ReconstructOddFromParityOdd([]byte{1, 2}, []byte{1}); err == nil {
		t.Fatal("odd parity mismatch")
	}
	if _, err := pcs.ReconstructEvenFromParityOdd([]byte{1}, []byte{1}); err == nil {
		t.Fatal("even parity mismatch")
	}
}

func TestDecodeFingerprintErrors(t *testing.T) {
	present := map[pcs.ParticleKind]bool{pcs.EvenCypher: true}
	shards := map[pcs.ParticleKind][]byte{pcs.EvenCypher: {1}}
	if _, err := pcs.DecodeFingerprint(present, shards); err == nil {
		t.Fatal("expected recovery error")
	}
}

func TestDecryptLengthMismatch(t *testing.T) {
	if _, err := pcs.Decrypt([]byte{1, 2, 3}, []byte{1, 2}); err == nil {
		t.Fatal("expected error")
	}
}

func TestEncodeWithNoiseMismatch(t *testing.T) {
	if _, err := pcs.EncodeWithNoise([]byte{1}, []byte{1, 2}); err == nil {
		t.Fatal("expected error")
	}
}

func TestEncodeWithNoiseGolden(t *testing.T) {
	secret := []byte{0, 1, 2, 3, 4}
	noise := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	got, err := pcs.EncodeWithNoise(secret, noise)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	wantCypher := []byte{0xaa, 0xba, 0xce, 0xde, 0xea}
	evenC, oddC := pcs.Split(wantCypher)
	if !bytes.Equal(got.EvenCypher, evenC) || !bytes.Equal(got.OddCypher, oddC) {
		t.Fatalf("cypher split mismatch")
	}
}
