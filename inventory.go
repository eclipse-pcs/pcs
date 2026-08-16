// Copyright (c) 2026 dido GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

package pcs

import "fmt"

// ParticleInventory tracks which particles are present for one logical object.
type ParticleInventory struct {
	Present map[ParticleKind]bool
}

// NewParticleInventory builds an inventory from a presence map.
func NewParticleInventory(present map[ParticleKind]bool) *ParticleInventory {
	cp := make(map[ParticleKind]bool, len(present))
	for k, v := range present {
		if v {
			cp[k] = true
		}
	}
	return &ParticleInventory{Present: cp}
}

// InventoryFromPresent builds an inventory from remote presence information.
func InventoryFromPresent(present map[ParticleKind]bool) (*ParticleInventory, error) {
	inv := NewParticleInventory(present)
	if inv.NeedsParityRecovery() {
		if !inv.Present[CypherParity] && !inv.Present[NoiseParity] {
			return nil, fmt.Errorf("parity particles required for recovery but not found")
		}
	}
	return inv, nil
}

func (inv *ParticleInventory) MissingCoreParticles() []ParticleKind {
	var missing []ParticleKind
	for _, kind := range CoreParticleKinds {
		if !inv.Present[kind] {
			missing = append(missing, kind)
		}
	}
	return missing
}

func (inv *ParticleInventory) NeedsParityRecovery() bool {
	return len(inv.MissingCoreParticles()) > 0
}
