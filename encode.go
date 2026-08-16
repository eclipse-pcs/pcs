// Copyright (c) 2026 dido GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

package pcs

import "fmt"

// EncodeResult holds the six particle payloads from a PCS encode.
type EncodeResult struct {
	EvenCypher   []byte
	OddCypher    []byte
	EvenNoise    []byte
	OddNoise     []byte
	CypherParity []byte
	NoiseParity  []byte
}

// Encode generates random noise and PCS-encodes secret.
func Encode(secret []byte) (*EncodeResult, error) {
	noise, err := RandomNoise(len(secret))
	if err != nil {
		return nil, err
	}
	return EncodeWithNoise(secret, noise)
}

// EncodeWithNoise runs the PCS encode pipeline with caller-supplied noise.
func EncodeWithNoise(secret, noise []byte) (*EncodeResult, error) {
	if len(secret) != len(noise) {
		return nil, fmt.Errorf("secret and noise length mismatch: %d vs %d", len(secret), len(noise))
	}

	cypher := Encrypt(secret, noise)
	evenNoise, oddNoise := Split(noise)
	evenCypher, oddCypher := Split(cypher)

	return &EncodeResult{
		EvenCypher:   evenCypher,
		OddCypher:    oddCypher,
		EvenNoise:    evenNoise,
		OddNoise:     oddNoise,
		CypherParity: ParityPadded(evenCypher, oddCypher),
		NoiseParity:  ParityPadded(evenNoise, oddNoise),
	}, nil
}

// EncodeResultShard returns the particle bytes for kind from an encode result.
func EncodeResultShard(r *EncodeResult, kind ParticleKind) []byte {
	switch kind {
	case EvenCypher:
		return r.EvenCypher
	case OddCypher:
		return r.OddCypher
	case EvenNoise:
		return r.EvenNoise
	case OddNoise:
		return r.OddNoise
	case CypherParity:
		return r.CypherParity
	case NoiseParity:
		return r.NoiseParity
	default:
		return nil
	}
}
