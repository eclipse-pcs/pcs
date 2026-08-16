// Copyright (c) 2026 dido GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

package pcs

import "fmt"

// ReconstructFromParityEven rebuilds the missing partner when both particles are equal length.
func ReconstructFromParityEven(have, parity []byte) ([]byte, error) {
	if len(have) != len(parity) {
		return nil, fmt.Errorf("particle and parity length mismatch: %d vs %d", len(have), len(parity))
	}
	out := make([]byte, len(have))
	for i := range have {
		out[i] = have[i] ^ parity[i]
	}
	return out, nil
}

// ReconstructOddFromParityOdd rebuilds the odd particle from even + parity (odd original length).
func ReconstructOddFromParityOdd(haveEven, parity []byte) ([]byte, error) {
	if len(parity) != len(haveEven) {
		return nil, fmt.Errorf("even particle and parity length mismatch: %d vs %d", len(haveEven), len(parity))
	}
	if len(haveEven) == 0 {
		return []byte{}, nil
	}
	oddLen := len(haveEven) - 1
	out := make([]byte, oddLen)
	for i := 0; i < oddLen; i++ {
		out[i] = haveEven[i] ^ parity[i]
	}
	return out, nil
}

// ReconstructEvenFromParityOdd rebuilds the even particle from odd + parity (odd original length).
func ReconstructEvenFromParityOdd(haveOdd, parity []byte) ([]byte, error) {
	if len(parity) != len(haveOdd)+1 {
		return nil, fmt.Errorf("odd particle and parity length mismatch: %d vs %d", len(haveOdd), len(parity))
	}
	even := make([]byte, len(parity))
	for i := range haveOdd {
		even[i] = haveOdd[i] ^ parity[i]
	}
	even[len(parity)-1] = parity[len(parity)-1]
	return even, nil
}

func recoverPairEven(inv *ParticleInventory, data map[ParticleKind][]byte, evenKind, oddKind, parityKind ParticleKind) (even, odd []byte, err error) {
	haveEven := inv.Present[evenKind]
	haveOdd := inv.Present[oddKind]

	switch {
	case haveEven && haveOdd:
		return data[evenKind], data[oddKind], nil
	case haveEven && !haveOdd:
		if !inv.Present[parityKind] {
			return nil, nil, fmt.Errorf("cannot recover %s without %s", oddKind, parityKind)
		}
		odd, err = ReconstructFromParityEven(data[evenKind], data[parityKind])
		return data[evenKind], odd, err
	case !haveEven && haveOdd:
		if !inv.Present[parityKind] {
			return nil, nil, fmt.Errorf("cannot recover %s without %s", evenKind, parityKind)
		}
		even, err = ReconstructFromParityEven(data[oddKind], data[parityKind])
		return even, data[oddKind], err
	default:
		return nil, nil, fmt.Errorf("cannot recover %s/%s pair from parity alone", evenKind, oddKind)
	}
}

func recoverPairOdd(inv *ParticleInventory, data map[ParticleKind][]byte, evenKind, oddKind, parityKind ParticleKind) (even, odd []byte, err error) {
	haveEven := inv.Present[evenKind]
	haveOdd := inv.Present[oddKind]

	switch {
	case haveEven && haveOdd:
		return data[evenKind], data[oddKind], nil
	case haveEven && !haveOdd:
		if !inv.Present[parityKind] {
			return nil, nil, fmt.Errorf("cannot recover %s without %s", oddKind, parityKind)
		}
		odd, err = ReconstructOddFromParityOdd(data[evenKind], data[parityKind])
		return data[evenKind], odd, err
	case !haveEven && haveOdd:
		if !inv.Present[parityKind] {
			return nil, nil, fmt.Errorf("cannot recover %s without %s", evenKind, parityKind)
		}
		even, err = ReconstructEvenFromParityOdd(data[oddKind], data[parityKind])
		return even, data[oddKind], err
	default:
		return nil, nil, fmt.Errorf("cannot recover %s/%s pair from parity alone", evenKind, oddKind)
	}
}

func recoverPair(inv *ParticleInventory, data map[ParticleKind][]byte, evenKind, oddKind, parityKind ParticleKind, oddLength bool) (even, odd []byte, err error) {
	if oddLength {
		return recoverPairOdd(inv, data, evenKind, oddKind, parityKind)
	}
	return recoverPairEven(inv, data, evenKind, oddKind, parityKind)
}

// RecoverCoreParticlesInto fills missing core particles using parity shards.
func RecoverCoreParticlesInto(inv *ParticleInventory, data map[ParticleKind][]byte, logicalSize int64) error {
	oddLength := logicalSize%2 == 1
	evenCypher, oddCypher, err := recoverPair(inv, data, EvenCypher, OddCypher, CypherParity, oddLength)
	if err != nil {
		return err
	}
	evenNoise, oddNoise, err := recoverPair(inv, data, EvenNoise, OddNoise, NoiseParity, oddLength)
	if err != nil {
		return err
	}
	data[EvenCypher] = evenCypher
	data[OddCypher] = oddCypher
	data[EvenNoise] = evenNoise
	data[OddNoise] = oddNoise
	inv.Present[EvenCypher] = true
	inv.Present[OddCypher] = true
	inv.Present[EvenNoise] = true
	inv.Present[OddNoise] = true
	return nil
}
