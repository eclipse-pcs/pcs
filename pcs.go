// Copyright (c) 2026 dido GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

package pcs

import (
	"crypto/rand"
	"fmt"
)

// Split separates text into even-indexed and odd-indexed bytes.
func Split(text []byte) ([]byte, []byte) {
	even := make([]byte, 0, (len(text)+1)/2)
	odd := make([]byte, 0, len(text)/2)
	for i, v := range text {
		if i%2 == 0 {
			even = append(even, v)
		} else {
			odd = append(odd, v)
		}
	}
	return even, odd
}

// Merge interleaves even and odd streams back into original byte order.
func Merge(even, odd []byte) []byte {
	n := len(even) + len(odd)
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			out[i] = even[i/2]
		} else {
			out[i] = odd[i/2]
		}
	}
	return out
}

// Encrypt XORs secret with noise of equal length.
func Encrypt(secret, noise []byte) []byte {
	l := len(secret)
	cypher := make([]byte, l)
	for i := 0; i < l; i++ {
		cypher[i] = secret[i] ^ noise[i]
	}
	return cypher
}

// Decrypt XORs cypher with noise to recover the secret.
func Decrypt(cypher, noise []byte) ([]byte, error) {
	if len(cypher) != len(noise) {
		return nil, fmt.Errorf("cypher and noise length mismatch: %d vs %d", len(cypher), len(noise))
	}
	secret := make([]byte, len(cypher))
	for i := 0; i < len(cypher); i++ {
		secret[i] = cypher[i] ^ noise[i]
	}
	return secret, nil
}

// ParityPadded computes XOR parity with odd-length tail handling.
func ParityPadded(even, odd []byte) []byte {
	parity := make([]byte, len(even))
	for i := 0; i < len(odd); i++ {
		parity[i] = even[i] ^ odd[i]
	}
	if len(odd) == len(even)-1 {
		parity[len(even)-1] = even[len(even)-1]
	}
	return parity
}

// RandomNoise returns n cryptographically secure random bytes.
func RandomNoise(n int) ([]byte, error) {
	if n == 0 {
		return []byte{}, nil
	}
	noise := make([]byte, n)
	if _, err := rand.Read(noise); err != nil {
		return nil, fmt.Errorf("generate random noise: %w", err)
	}
	return noise, nil
}
