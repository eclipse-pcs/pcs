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
	"io"
	"reflect"
	"runtime"
	"testing"

	"github.com/eclipse-pcs/pcs"
	"github.com/eclipse-pcs/pcs/footer"
)

func TestDecodeStateHasNoPayloadField(t *testing.T) {
	typ := reflect.TypeOf(decodeState{})
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Name == "payloads" {
			t.Fatal("decodeState must not accumulate whole particle payloads")
		}
	}
}

func TestDecodeLargeObjectBoundedMemory(t *testing.T) {
	const (
		secretLen = 4 << 20 // 4 MiB
		chunkSize = 8 << 10 // 8 KiB
	)
	secret := make([]byte, secretLen)
	for i := range secret {
		secret[i] = byte(i)
	}
	noise, err := pcs.RandomNoise(secretLen)
	if err != nil {
		t.Fatal(err)
	}
	particles, _, err := EncodeCollect(secret, noise, chunkSize)
	if err != nil {
		t.Fatal(err)
	}
	sources := Sources{}
	for _, kind := range pcs.AllParticleKinds {
		data := particles[kind]
		payloadLen := int64(len(data) - footer.Size)
		src := Source{R: bytes.NewReader(data), PayloadLen: payloadLen}
		switch kind {
		case pcs.EvenCypher:
			sources.EC = src
		case pcs.OddCypher:
			sources.OC = src
		case pcs.EvenNoise:
			sources.EN = src
		case pcs.OddNoise:
			sources.ON = src
		case pcs.CypherParity:
			sources.CP = src
		case pcs.NoiseParity:
			sources.NP = src
		}
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	dec := NewDecoder(chunkSize)
	if _, err := dec.Decode(sources, io.Discard, DecodeOptions{}); err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	// Buffering all six payloads would retain on the order of the object size.
	// Incremental CRC verification should stay far below that.
	const maxGrowth = 2 * chunkSize * 6
	var growth uint64
	if after.HeapAlloc >= before.HeapAlloc {
		growth = after.HeapAlloc - before.HeapAlloc
	}
	if growth > maxGrowth {
		t.Fatalf("heap growth %d exceeds bound %d (secret %d)", growth, maxGrowth, secretLen)
	}
}
