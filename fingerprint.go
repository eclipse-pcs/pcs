// Copyright (c) 2026 dido GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

package pcs

import "fmt"

const fingerprintPayloadSize int64 = 32

// EncodeFingerprint PCS-encodes a 32-byte SHA-256 digest.
func EncodeFingerprint(digest [32]byte) (*EncodeResult, error) {
	return Encode(digest[:])
}

// DecodeFingerprint reconstructs the digest from six fingerprint shard blobs.
func DecodeFingerprint(present map[ParticleKind]bool, shards map[ParticleKind][]byte) ([32]byte, error) {
	var zero [32]byte
	inv := NewParticleInventory(present)
	if err := RecoverCoreParticlesInto(inv, shards, fingerprintPayloadSize); err != nil {
		return zero, err
	}
	got, err := DecodeFromParticles(
		shards[EvenCypher],
		shards[OddCypher],
		shards[EvenNoise],
		shards[OddNoise],
	)
	if err != nil {
		return zero, err
	}
	if len(got) != 32 {
		return zero, fmt.Errorf("fingerprint length %d, want 32", len(got))
	}
	var out [32]byte
	copy(out[:], got)
	return out, nil
}

// RecoverAllFingerprintShards recovers missing fingerprint shards via parity math.
func RecoverAllFingerprintShards(present map[ParticleKind]bool, shards map[ParticleKind][]byte) (map[ParticleKind][]byte, error) {
	inv := NewParticleInventory(present)
	if err := RecoverCoreParticlesInto(inv, shards, fingerprintPayloadSize); err != nil {
		return nil, err
	}
	if len(shards[EvenCypher]) > 0 && len(shards[OddCypher]) > 0 && len(shards[CypherParity]) == 0 {
		shards[CypherParity] = ParityPadded(shards[EvenCypher], shards[OddCypher])
	}
	if len(shards[EvenNoise]) > 0 && len(shards[OddNoise]) > 0 && len(shards[NoiseParity]) == 0 {
		shards[NoiseParity] = ParityPadded(shards[EvenNoise], shards[OddNoise])
	}
	return shards, nil
}
