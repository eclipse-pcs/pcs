// Copyright (c) 2026 dido GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

package stream

import (
	"crypto/sha256"
	"hash"
	"hash/crc32"
	"time"

	"github.com/eclipse-pcs/pcs"
	"github.com/eclipse-pcs/pcs/footer"
)

type parityTracker struct {
	evenBuf   []byte
	oddBuf    []byte
	emitted   int
	oddLength bool
}

func (p *parityTracker) appendEven(data []byte) {
	p.evenBuf = append(p.evenBuf, data...)
}

func (p *parityTracker) appendOdd(data []byte) {
	p.oddBuf = append(p.oddBuf, data...)
}

func (p *parityTracker) drain() []byte {
	var out []byte
	for p.emitted < len(p.oddBuf) && p.emitted < len(p.evenBuf) {
		out = append(out, p.evenBuf[p.emitted]^p.oddBuf[p.emitted])
		p.emitted++
	}
	p.compact()
	return out
}

func (p *parityTracker) compact() {
	if p.emitted == 0 {
		return
	}
	p.evenBuf = p.evenBuf[p.emitted:]
	p.oddBuf = p.oddBuf[p.emitted:]
	p.emitted = 0
}

func (p *parityTracker) finishTail() []byte {
	out := p.drain()
	if p.oddLength && p.emitted < len(p.evenBuf) {
		out = append(out, p.evenBuf[p.emitted])
		p.emitted++
	}
	return out
}

type encodeState struct {
	globalByteIndex int
	sha256          hash.Hash
	payloadCRC      map[pcs.ParticleKind]hash.Hash32
	cypherParity    parityTracker
	noiseParity     parityTracker
	bytesProcessed  int64
}

func newEncodeState() *encodeState {
	newH := func() hash.Hash32 { return crc32.NewIEEE() }
	return &encodeState{
		sha256: sha256.New(),
		payloadCRC: map[pcs.ParticleKind]hash.Hash32{
			pcs.EvenCypher:   newH(),
			pcs.OddCypher:    newH(),
			pcs.EvenNoise:    newH(),
			pcs.OddNoise:     newH(),
			pcs.CypherParity: newH(),
			pcs.NoiseParity:  newH(),
		},
	}
}

func (s *encodeState) finishParity() (cypherTail, noiseTail []byte) {
	s.cypherParity.oddLength = true
	s.noiseParity.oddLength = true
	return s.cypherParity.finishTail(), s.noiseParity.finishTail()
}

func buildFooters(st *encodeState, fpResult *pcs.EncodeResult, writeID uint64, mtime time.Time) map[pcs.ParticleKind]*footer.Footer {
	out := make(map[pcs.ParticleKind]*footer.Footer, len(pcs.AllParticleKinds))
	for _, kind := range pcs.AllParticleKinds {
		partner := footer.PartnerKind(kind)
		var shard [16]byte
		footer.CopyFingerprintShard(&shard, pcs.EncodeResultShard(fpResult, kind))
		out[kind] = &footer.Footer{
			Version:          footer.Version,
			Kind:             kind,
			Length:           uint64(st.bytesProcessed),
			FingerprintShard: shard,
			PayloadCRC:       st.payloadCRC[kind].Sum32(),
			CrossCRC:         st.payloadCRC[partner].Sum32(),
			WriteID:          writeID,
			Mtime:            mtimeFromOptions(mtime),
		}
	}
	return out
}
