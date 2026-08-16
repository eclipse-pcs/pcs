// Copyright (c) 2026 dido GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

package pcs

// DecodeFromParticles reconstructs the original secret from four core particles.
func DecodeFromParticles(evenCypher, oddCypher, evenNoise, oddNoise []byte) ([]byte, error) {
	cypher := Merge(evenCypher, oddCypher)
	noise := Merge(evenNoise, oddNoise)
	return Decrypt(cypher, noise)
}

// DecodeWithRecovery reconstructs the secret using parity when cores are missing.
func DecodeWithRecovery(inv *ParticleInventory, particles map[ParticleKind][]byte, logicalSize int64) ([]byte, bool, error) {
	usedParity := inv.NeedsParityRecovery()
	if err := RecoverCoreParticlesInto(inv, particles, logicalSize); err != nil {
		return nil, usedParity, err
	}
	secret, err := DecodeFromParticles(
		particles[EvenCypher],
		particles[OddCypher],
		particles[EvenNoise],
		particles[OddNoise],
	)
	return secret, usedParity, err
}
