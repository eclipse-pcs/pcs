// Copyright (c) 2026 dido GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

package pcs

// ParticleKind identifies one of the six particles in footer order.
type ParticleKind int

const (
	EvenCypher ParticleKind = iota
	OddCypher
	EvenNoise
	OddNoise
	CypherParity
	NoiseParity
)

var (
	// AllParticleKinds lists all six particle kinds in stable order.
	AllParticleKinds = []ParticleKind{
		EvenCypher, OddCypher, EvenNoise, OddNoise, CypherParity, NoiseParity,
	}
	// CoreParticleKinds are the four payload-determining particles.
	CoreParticleKinds = []ParticleKind{EvenCypher, OddCypher, EvenNoise, OddNoise}
)

func (k ParticleKind) String() string {
	switch k {
	case EvenCypher:
		return "evenCypher"
	case OddCypher:
		return "oddCypher"
	case EvenNoise:
		return "evenNoise"
	case OddNoise:
		return "oddNoise"
	case CypherParity:
		return "cypherParity"
	case NoiseParity:
		return "noiseParity"
	default:
		return "unknown"
	}
}
