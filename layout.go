// Copyright (c) 2026 dido GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

package pcs

import "strings"

var particleSuffix = map[ParticleKind]string{
	EvenCypher:   ".ec",
	OddCypher:    ".oc",
	EvenNoise:    ".en",
	OddNoise:     ".on",
	CypherParity: ".cp",
	NoiseParity:  ".np",
}

// ParticleSuffix returns the unified particle suffix for kind.
func ParticleSuffix(kind ParticleKind) string {
	return particleSuffix[kind]
}

// ShardKey returns the full shard key for a logical key and particle kind.
func ShardKey(logicalKey string, kind ParticleKind) string {
	return logicalKey + particleSuffix[kind]
}

// AllShardKeys returns all six shard keys for a logical object key.
func AllShardKeys(logicalKey string) map[ParticleKind]string {
	out := make(map[ParticleKind]string, len(AllParticleKinds))
	for _, kind := range AllParticleKinds {
		out[kind] = ShardKey(logicalKey, kind)
	}
	return out
}

// StorageForParticle returns the storage role that holds the given particle.
func StorageForParticle(kind ParticleKind) string {
	switch kind {
	case EvenCypher, OddNoise:
		return StorageA
	case OddCypher, EvenNoise:
		return StorageB
	case CypherParity, NoiseParity:
		return StorageC
	default:
		return ""
	}
}

// LogicalKeyFromShard strips a known particle suffix and returns the logical key.
func LogicalKeyFromShard(shardKey string) (logicalKey string, kind ParticleKind, ok bool) {
	for k, suf := range particleSuffix {
		if strings.HasSuffix(shardKey, suf) {
			return strings.TrimSuffix(shardKey, suf), k, true
		}
	}
	return "", 0, false
}

// IsParticleShard reports whether key ends with a known particle suffix.
func IsParticleShard(key string) bool {
	_, _, ok := LogicalKeyFromShard(key)
	return ok
}
