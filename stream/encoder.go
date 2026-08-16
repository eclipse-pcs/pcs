// Copyright (c) 2026 dido GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

package stream

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/eclipse-pcs/pcs"
	"github.com/eclipse-pcs/pcs/footer"
)

// Writers holds six particle output streams in protocol order.
type Writers struct {
	EC, OC, EN, ON, CP, NP io.Writer
}

// Encoder streams PCS encode from a document reader to six particle writers.
type Encoder struct {
	chunkSize         int
	noise             io.Reader
	cypherScratch     []byte
	evenCypherScratch []byte
	oddCypherScratch  []byte
	evenNoiseScratch  []byte
	oddNoiseScratch   []byte
}

// NewEncoder creates an encoder with cryptographically random noise.
func NewEncoder(chunkSize int) *Encoder {
	return &Encoder{chunkSize: chunkSize, noise: rand.Reader}
}

// NewEncoderWithNoise creates an encoder with deterministic noise (tests).
func NewEncoderWithNoise(chunkSize int, noise io.Reader) *Encoder {
	return &Encoder{chunkSize: chunkSize, noise: noise}
}

// Encode writes payloads and appends six v1 footers at EOF.
func (e *Encoder) Encode(secret io.Reader, outs Writers, opts EncodeOptions) (*EncodeMeta, error) {
	if e.chunkSize <= 0 {
		return nil, fmt.Errorf("chunk size must be > 0")
	}
	writeID := opts.WriteID
	if writeID == 0 {
		var err error
		writeID, err = footer.NewWriteID()
		if err != nil {
			return nil, err
		}
	}

	st := newEncodeState()
	buf := make([]byte, e.chunkSize)
	noiseBuf := make([]byte, e.chunkSize)

	for {
		n, err := secret.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if _, rerr := io.ReadFull(e.noise, noiseBuf[:n]); rerr != nil {
				return nil, fmt.Errorf("read noise: %w", rerr)
			}
			if err := e.processChunk(st, chunk, noiseBuf[:n], outs); err != nil {
				return nil, err
			}
			st.sha256.Write(chunk)
			st.globalByteIndex += n
			st.bytesProcessed += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read secret: %w", err)
		}
	}

	cypherTail, noiseTail := st.finishParity()
	if len(cypherTail) > 0 {
		if _, err := outs.CP.Write(cypherTail); err != nil {
			return nil, err
		}
		st.payloadCRC[pcs.CypherParity].Write(cypherTail)
	}
	if len(noiseTail) > 0 {
		if _, err := outs.NP.Write(noiseTail); err != nil {
			return nil, err
		}
		st.payloadCRC[pcs.NoiseParity].Write(noiseTail)
	}

	sum := secretSHA256(st.sha256)
	fpResult, err := fingerprintFromSHA256(sum)
	if err != nil {
		return nil, fmt.Errorf("encode fingerprint: %w", err)
	}

	footers := buildFooters(st, fpResult, writeID, opts.Mtime)
	if err := writeFooters(outs, footers); err != nil {
		return nil, err
	}

	return &EncodeMeta{
		SHA256:         sum,
		Fingerprint:    fpResult,
		Footers:        footers,
		BytesProcessed: st.bytesProcessed,
	}, nil
}

func writeFooters(outs Writers, footers map[pcs.ParticleKind]*footer.Footer) error {
	writes := []struct {
		kind pcs.ParticleKind
		w    io.Writer
	}{
		{pcs.EvenCypher, outs.EC},
		{pcs.OddCypher, outs.OC},
		{pcs.EvenNoise, outs.EN},
		{pcs.OddNoise, outs.ON},
		{pcs.CypherParity, outs.CP},
		{pcs.NoiseParity, outs.NP},
	}
	for _, item := range writes {
		f := footers[item.kind]
		if f == nil {
			return fmt.Errorf("missing footer for %s", item.kind)
		}
		raw := f.Marshal()
		if _, err := item.w.Write(raw[:]); err != nil {
			return fmt.Errorf("write footer %s: %w", item.kind, err)
		}
	}
	return nil
}

func (e *Encoder) processChunk(st *encodeState, secret, noise []byte, outs Writers) error {
	if cap(e.cypherScratch) < len(secret) {
		e.cypherScratch = make([]byte, len(secret))
	} else {
		e.cypherScratch = e.cypherScratch[:len(secret)]
	}
	cypher := e.cypherScratch
	for i := range secret {
		cypher[i] = secret[i] ^ noise[i]
	}
	startEven, startOdd := SplitStartIndices(st.globalByteIndex)

	evenCypher := everySecondByteInto(cypher, startEven, &e.evenCypherScratch)
	oddCypher := everySecondByteInto(cypher, startOdd, &e.oddCypherScratch)
	evenNoise := everySecondByteInto(noise, startEven, &e.evenNoiseScratch)
	oddNoise := everySecondByteInto(noise, startOdd, &e.oddNoiseScratch)

	writes := []struct {
		kind pcs.ParticleKind
		w    io.Writer
		data []byte
	}{
		{pcs.EvenCypher, outs.EC, evenCypher},
		{pcs.OddCypher, outs.OC, oddCypher},
		{pcs.EvenNoise, outs.EN, evenNoise},
		{pcs.OddNoise, outs.ON, oddNoise},
	}
	for _, item := range writes {
		if len(item.data) == 0 {
			continue
		}
		if _, err := item.w.Write(item.data); err != nil {
			return fmt.Errorf("write %s: %w", item.kind, err)
		}
		st.payloadCRC[item.kind].Write(item.data)
	}

	st.cypherParity.appendEven(evenCypher)
	st.cypherParity.appendOdd(oddCypher)
	st.noiseParity.appendEven(evenNoise)
	st.noiseParity.appendOdd(oddNoise)

	cypherParity := st.cypherParity.drain()
	if len(cypherParity) > 0 {
		if _, err := outs.CP.Write(cypherParity); err != nil {
			return err
		}
		st.payloadCRC[pcs.CypherParity].Write(cypherParity)
	}
	noiseParity := st.noiseParity.drain()
	if len(noiseParity) > 0 {
		if _, err := outs.NP.Write(noiseParity); err != nil {
			return err
		}
		st.payloadCRC[pcs.NoiseParity].Write(noiseParity)
	}
	return nil
}
