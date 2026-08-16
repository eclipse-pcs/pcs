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
	"crypto/sha256"
	"fmt"
	"hash"
	"hash/crc32"
	"io"

	"github.com/eclipse-pcs/pcs"
	"github.com/eclipse-pcs/pcs/footer"
)

const defaultStreamReadSize = 32 << 10

// Source is one particle input stream with a known payload length.
type Source struct {
	R          io.Reader
	PayloadLen int64 // -1 when missing/unknown
}

// Sources holds six particle sources.
type Sources struct {
	EC, OC, EN, ON, CP, NP Source
}

// Decoder reconstructs a document from six particle sources.
type Decoder struct {
	chunkSize int
}

// NewDecoder creates a decoder with the given chunk size.
func NewDecoder(chunkSize int) *Decoder {
	return &Decoder{chunkSize: chunkSize}
}

type decodeState struct {
	payloadCRC     map[pcs.ParticleKind]hash.Hash32
	sha256         hash.Hash
	bytesProcessed int64
	footers        map[pcs.ParticleKind]*footer.Footer
}

func newDecodeState() *decodeState {
	newH := func() hash.Hash32 { return crc32.NewIEEE() }
	return &decodeState{
		payloadCRC: map[pcs.ParticleKind]hash.Hash32{
			pcs.EvenCypher:   newH(),
			pcs.OddCypher:    newH(),
			pcs.EvenNoise:    newH(),
			pcs.OddNoise:     newH(),
			pcs.CypherParity: newH(),
			pcs.NoiseParity:  newH(),
		},
		sha256:  sha256.New(),
		footers: make(map[pcs.ParticleKind]*footer.Footer),
	}
}

type streamBuffer struct {
	r           io.Reader
	buf         []byte
	readScratch []byte
	eof         bool
}

func newStreamBuffer(r io.Reader) *streamBuffer {
	if r == nil {
		return &streamBuffer{eof: true}
	}
	return &streamBuffer{r: r}
}

func (s *streamBuffer) len() int { return len(s.buf) }

func (s *streamBuffer) fill() error {
	if s.eof {
		return nil
	}
	if cap(s.readScratch) < defaultStreamReadSize {
		s.readScratch = make([]byte, defaultStreamReadSize)
	}
	n, err := s.r.Read(s.readScratch)
	if n > 0 {
		s.buf = append(s.buf, s.readScratch[:n]...)
	}
	if err == io.EOF {
		s.eof = true
		return nil
	}
	return err
}

func (s *streamBuffer) take(n int) []byte {
	if n <= 0 {
		return nil
	}
	if n > len(s.buf) {
		n = len(s.buf)
	}
	out := s.buf[:n]
	s.buf = s.buf[n:]
	return out
}

func skipStreamBuffer(s *streamBuffer, n int) error {
	for n > 0 {
		if s.len() == 0 {
			if s.eof {
				return fmt.Errorf("stream ended during skip (%d bytes remaining)", n)
			}
			if err := s.fill(); err != nil {
				return err
			}
			if s.len() == 0 && s.eof {
				return fmt.Errorf("stream ended during skip (%d bytes remaining)", n)
			}
		}
		drop := n
		if drop > s.len() {
			drop = s.len()
		}
		s.take(drop)
		n -= drop
	}
	return nil
}

func skipCoreStreams(evenEC, oddOC, evenEN, oddON *streamBuffer, start int64) error {
	if start <= 0 {
		return nil
	}
	remaining := int(start)
	evenSkip := EvenCountForRange(0, remaining)
	oddSkip := remaining - evenSkip
	if err := skipStreamBuffer(evenEC, evenSkip); err != nil {
		return fmt.Errorf("skip even cypher: %w", err)
	}
	if err := skipStreamBuffer(oddOC, oddSkip); err != nil {
		return fmt.Errorf("skip odd cypher: %w", err)
	}
	if err := skipStreamBuffer(evenEN, evenSkip); err != nil {
		return fmt.Errorf("skip even noise: %w", err)
	}
	if err := skipStreamBuffer(oddON, oddSkip); err != nil {
		return fmt.Errorf("skip odd noise: %w", err)
	}
	return nil
}

func (s *streamBuffer) drainAll(st *decodeState, kind pcs.ParticleKind) error {
	for !s.eof || len(s.buf) > 0 {
		if len(s.buf) == 0 {
			if err := s.fill(); err != nil {
				return err
			}
			if len(s.buf) == 0 {
				return nil
			}
		}
		chunk := s.take(len(s.buf))
		st.payloadCRC[kind].Write(chunk)
	}
	return nil
}

// sharedStream allows multiple readers to consume the same source independently.
type sharedStream struct {
	src  io.Reader
	data []byte
}

type sharedCursor struct {
	stream *sharedStream
	off    int
}

func newSharedStream(r io.Reader) *sharedStream {
	if r == nil {
		return &sharedStream{}
	}
	return &sharedStream{src: r}
}

func (s *sharedStream) cursor() *sharedCursor {
	return &sharedCursor{stream: s}
}

func (c *sharedCursor) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err := c.stream.readFrom(c.off, p)
	c.off += n
	return n, err
}

func (s *sharedStream) readFrom(off int, p []byte) (int, error) {
	for off+len(p) > len(s.data) {
		if s.src == nil {
			break
		}
		chunk := make([]byte, 4096)
		n, err := s.src.Read(chunk)
		if n > 0 {
			s.data = append(s.data, chunk[:n]...)
		}
		if err == io.EOF {
			s.src = nil
			break
		}
		if err != nil {
			return 0, err
		}
	}
	if off >= len(s.data) {
		return 0, io.EOF
	}
	n := copy(p, s.data[off:])
	return n, nil
}

type particleReaders struct {
	EC, OC, EN, ON, CP, NP io.Reader
}

func openSources(sources Sources, oddLength bool) (particleReaders, error) {
	missing := map[pcs.ParticleKind]bool{
		pcs.EvenCypher: sources.EC.R == nil,
		pcs.OddCypher:  sources.OC.R == nil,
		pcs.EvenNoise:  sources.EN.R == nil,
		pcs.OddNoise:   sources.ON.R == nil,
	}

	ec, err := openPayloadReader(sources.EC)
	if err != nil {
		return particleReaders{}, fmt.Errorf("ec: %w", err)
	}
	oc, err := openPayloadReader(sources.OC)
	if err != nil {
		return particleReaders{}, fmt.Errorf("oc: %w", err)
	}
	en, err := openPayloadReader(sources.EN)
	if err != nil {
		return particleReaders{}, fmt.Errorf("en: %w", err)
	}
	on, err := openPayloadReader(sources.ON)
	if err != nil {
		return particleReaders{}, fmt.Errorf("on: %w", err)
	}
	cp, err := openPayloadReader(sources.CP)
	if err != nil {
		return particleReaders{}, fmt.Errorf("cp: %w", err)
	}
	np, err := openPayloadReader(sources.NP)
	if err != nil {
		return particleReaders{}, fmt.Errorf("np: %w", err)
	}

	ins := particleReaders{EC: ec, OC: oc, EN: en, ON: on, CP: cp, NP: np}
	applyRecoveryReaders(&ins, missing, oddLength)
	return ins, nil
}

func openPayloadReader(src Source) (io.Reader, error) {
	if src.R == nil {
		return nil, nil
	}
	if src.PayloadLen < 0 {
		return src.R, nil
	}
	return io.LimitReader(src.R, src.PayloadLen), nil
}

func applyRecoveryReaders(ins *particleReaders, missing map[pcs.ParticleKind]bool, oddLength bool) {
	orig := *ins
	if missing[pcs.EvenCypher] {
		oc := newSharedStream(orig.OC)
		cp := newSharedStream(orig.CP)
		ins.OC = oc.cursor()
		ins.CP = cp.cursor()
		ins.EC = newReconstructingReader(oc.cursor(), cp.cursor(), RecoverEven, oddLength)
	}
	if missing[pcs.OddCypher] {
		ec := newSharedStream(orig.EC)
		cp := newSharedStream(orig.CP)
		ins.EC = ec.cursor()
		ins.CP = cp.cursor()
		ins.OC = newReconstructingReader(ec.cursor(), cp.cursor(), RecoverOdd, oddLength)
	}
	if missing[pcs.EvenNoise] {
		on := newSharedStream(orig.ON)
		np := newSharedStream(orig.NP)
		ins.ON = on.cursor()
		ins.NP = np.cursor()
		ins.EN = newReconstructingReader(on.cursor(), np.cursor(), RecoverEven, oddLength)
	}
	if missing[pcs.OddNoise] {
		en := newSharedStream(orig.EN)
		np := newSharedStream(orig.NP)
		ins.EN = en.cursor()
		ins.NP = np.cursor()
		ins.ON = newReconstructingReader(en.cursor(), np.cursor(), RecoverOdd, oddLength)
	}
}

// Decode reconstructs secret from six sources, verifying footers at end.
func (d *Decoder) Decode(sources Sources, out io.Writer, opts DecodeOptions) (*DecodeMeta, error) {
	if d.chunkSize <= 0 {
		return nil, fmt.Errorf("chunk size must be > 0")
	}

	oddLength, err := deriveOddLength(sources)
	if err != nil {
		return nil, err
	}

	ins, err := openSources(sources, oddLength)
	if err != nil {
		return nil, err
	}

	st := newDecodeState()
	evenEC := newStreamBuffer(ins.EC)
	oddOC := newStreamBuffer(ins.OC)
	evenEN := newStreamBuffer(ins.EN)
	oddON := newStreamBuffer(ins.ON)
	cpBuf := newStreamBuffer(ins.CP)
	npBuf := newStreamBuffer(ins.NP)

	if err := skipCoreStreams(evenEC, oddOC, evenEN, oddON, opts.StartOffset); err != nil {
		return nil, err
	}
	st.bytesProcessed = opts.StartOffset

	validate := opts.StartOffset == 0
	plain := make([]byte, d.chunkSize)
	cypherScratch := make([]byte, d.chunkSize)
	noiseScratch := make([]byte, d.chunkSize)

	var heldBack byte
	hasHeldBack := false
	ambiguousBothOddMissing := sources.OC.R == nil && sources.ON.R == nil &&
		sources.EC.R != nil && sources.EN.R != nil

	for {
		startIdx := int(st.bytesProcessed)
		n := MaxReadable(evenEC.len(), oddOC.len(), startIdx, d.chunkSize)
		if n == 0 {
			if evenEC.eof && oddOC.eof {
				break
			}
			if err := evenEC.fill(); err != nil {
				return nil, fmt.Errorf("read even cypher: %w", err)
			}
			if err := oddOC.fill(); err != nil {
				return nil, fmt.Errorf("read odd cypher: %w", err)
			}
			if evenEC.eof && oddOC.eof {
				break
			}
			continue
		}
		for MaxReadable(evenEN.len(), oddON.len(), startIdx, n) < n {
			if evenEN.eof && oddON.eof {
				return nil, fmt.Errorf("noise shorter than cypher at byte %d", st.bytesProcessed)
			}
			if err := evenEN.fill(); err != nil {
				return nil, fmt.Errorf("read even noise: %w", err)
			}
			if err := oddON.fill(); err != nil {
				return nil, fmt.Errorf("read odd noise: %w", err)
			}
		}
		n = MaxReadable(evenEN.len(), oddON.len(), startIdx, n)
		if n == 0 {
			return nil, fmt.Errorf("noise shorter than cypher at byte %d", st.bytesProcessed)
		}

		evenNeed := EvenCountForRange(startIdx, n)
		oddNeed := n - evenNeed

		evenCypher := evenEC.take(evenNeed)
		oddCypher := oddOC.take(oddNeed)
		evenNoise := evenEN.take(evenNeed)
		oddNoise := oddON.take(oddNeed)

		if validate {
			st.payloadCRC[pcs.EvenCypher].Write(evenCypher)
			st.payloadCRC[pcs.OddCypher].Write(oddCypher)
			st.payloadCRC[pcs.EvenNoise].Write(evenNoise)
			st.payloadCRC[pcs.OddNoise].Write(oddNoise)
		}

		MergeInterleavedInto(evenCypher, oddCypher, startIdx, cypherScratch[:n])
		MergeInterleavedInto(evenNoise, oddNoise, startIdx, noiseScratch[:n])
		for i := 0; i < n; i++ {
			plain[i] = cypherScratch[i] ^ noiseScratch[i]
		}

		writePlain := plain[:n]
		if ambiguousBothOddMissing && !hasHeldBack && evenEC.eof && oddOC.eof && evenEN.eof && oddON.eof && n > 0 {
			heldBack = writePlain[n-1]
			hasHeldBack = true
			writePlain = writePlain[:n-1]
		}

		if len(writePlain) > 0 {
			if _, err := out.Write(writePlain); err != nil {
				return nil, fmt.Errorf("write secret: %w", err)
			}
			if validate {
				st.sha256.Write(writePlain)
			}
		}
		st.bytesProcessed += int64(n)
	}

	flushPayload := func(sb *streamBuffer, kind pcs.ParticleKind) error {
		for !sb.eof || sb.len() > 0 {
			if sb.len() == 0 {
				if err := sb.fill(); err != nil {
					return err
				}
				if sb.len() == 0 {
					continue
				}
			}
			chunk := sb.take(sb.len())
			if validate {
				st.payloadCRC[kind].Write(chunk)
			}
		}
		return nil
	}
	for _, item := range []struct {
		sb   *streamBuffer
		kind pcs.ParticleKind
	}{
		{evenEC, pcs.EvenCypher},
		{oddOC, pcs.OddCypher},
		{evenEN, pcs.EvenNoise},
		{oddON, pcs.OddNoise},
		{cpBuf, pcs.CypherParity},
		{npBuf, pcs.NoiseParity},
	} {
		if err := flushPayload(item.sb, item.kind); err != nil {
			return nil, fmt.Errorf("flush %s payload: %w", item.kind, err)
		}
	}

	footers, err := readFooters(sources)
	if err != nil {
		return nil, err
	}
	st.footers = footers

	if ambiguousBothOddMissing && hasHeldBack {
		if f := footers[pcs.CypherParity]; f != nil {
			oddLength = int64(f.Length)%2 == 1
		}
		if oddLength {
			if _, err := out.Write([]byte{heldBack}); err != nil {
				return nil, err
			}
			if validate {
				st.sha256.Write([]byte{heldBack})
			}
		}
	}

	if !validate {
		return &DecodeMeta{BytesRead: st.bytesProcessed}, nil
	}

	if err := verifyDecoded(st, footers); err != nil {
		return nil, err
	}

	sum := secretSHA256(st.sha256)
	return &DecodeMeta{
		SHA256:    sum,
		Footers:   footers,
		BytesRead: st.bytesProcessed,
	}, nil
}

func deriveOddLength(sources Sources) (bool, error) {
	type sized struct {
		src Source
		even bool
	}
	candidates := []sized{
		{sources.EC, true},
		{sources.EN, true},
		{sources.CP, true},
		{sources.NP, true},
		{sources.OC, false},
		{sources.ON, false},
	}
	var evenPayload, oddPayload int64 = -1, -1
	for _, c := range candidates {
		if c.src.R == nil || c.src.PayloadLen < 0 {
			continue
		}
		if c.even {
			evenPayload = c.src.PayloadLen
		} else {
			oddPayload = c.src.PayloadLen
		}
	}
	if evenPayload >= 0 && oddPayload >= 0 {
		n := footer.LogicalSizeFromPayloadSizes(evenPayload, oddPayload)
		return n%2 == 1, nil
	}
	if evenPayload >= 0 && sources.OC.R == nil && sources.ON.R == nil {
		oddCand, _ := footer.LogicalSizeCandidates(evenPayload)
		return oddCand%2 == 1, nil
	}
	if evenPayload >= 0 && oddPayload < 0 {
		oddCand, _ := footer.LogicalSizeCandidates(evenPayload)
		return oddCand%2 == 1, nil
	}
	return false, nil
}

func readFooters(sources Sources) (map[pcs.ParticleKind]*footer.Footer, error) {
	pairs := []struct {
		kind pcs.ParticleKind
		src  Source
	}{
		{pcs.EvenCypher, sources.EC},
		{pcs.OddCypher, sources.OC},
		{pcs.EvenNoise, sources.EN},
		{pcs.OddNoise, sources.ON},
		{pcs.CypherParity, sources.CP},
		{pcs.NoiseParity, sources.NP},
	}
	out := make(map[pcs.ParticleKind]*footer.Footer)
	for _, p := range pairs {
		if p.src.R == nil {
			continue
		}
		f, err := readFooterAfterPayload(p.src)
		if err != nil {
			return nil, fmt.Errorf("%s footer: %w", p.kind, err)
		}
		out[p.kind] = f
	}
	return out, nil
}

func readFooterAfterPayload(src Source) (*footer.Footer, error) {
	buf := make([]byte, footer.Size)
	if _, err := io.ReadFull(src.R, buf); err != nil {
		return nil, fmt.Errorf("read footer: %w", err)
	}
	return footer.Parse(buf)
}

func verifyDecoded(st *decodeState, footers map[pcs.ParticleKind]*footer.Footer) error {
	if err := footer.VerifyWriteIDs(footers); err != nil {
		return fmt.Errorf("WriteID: %w", err)
	}
	for _, pair := range footer.CrossCRCPairs() {
		left, right := pair[0], pair[1]
		lf, rf := footers[left], footers[right]
		if lf == nil || rf == nil {
			continue
		}
		v := footer.VerifyCrossCRCSums(
			st.payloadCRC[left].Sum32(), lf.CrossCRC,
			st.payloadCRC[right].Sum32(), rf.CrossCRC,
		)
		if v != footer.CrossOK {
			return fmt.Errorf("cross-CRC %s/%s: %s", left, right, v)
		}
	}
	for kind, f := range footers {
		if st.payloadCRC[kind].Sum32() != f.PayloadCRC {
			return fmt.Errorf("payload CRC mismatch on %s", kind)
		}
	}
	var logicalLen uint64
	for _, f := range footers {
		if f != nil {
			logicalLen = f.Length
			break
		}
	}
	sum := secretSHA256(st.sha256)
	shards := make(map[pcs.ParticleKind][]byte)
	present := make(map[pcs.ParticleKind]bool)
	for kind, f := range footers {
		if f == nil {
			continue
		}
		present[kind] = true
		shards[kind] = f.FingerprintShard[:]
	}
	gotDigest, err := pcs.DecodeFingerprint(present, shards)
	if err != nil {
		return fmt.Errorf("fingerprint: %w", err)
	}
	if gotDigest != sum {
		return fmt.Errorf("fingerprint mismatch")
	}
	if uint64(st.bytesProcessed) != logicalLen {
		return fmt.Errorf("decoded length %d, footer length %d", st.bytesProcessed, logicalLen)
	}
	return nil
}

// DecodeCollect is a test helper that decodes in-memory particle+footer blobs.
func DecodeCollect(particles map[pcs.ParticleKind][]byte) ([]byte, *DecodeMeta, error) {
	sources := Sources{}
	for _, kind := range pcs.AllParticleKinds {
		data := particles[kind]
		if data == nil {
			continue
		}
		if len(data) < footer.Size {
			return nil, nil, fmt.Errorf("%s: data shorter than footer", kind)
		}
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
	var out bytes.Buffer
	meta, err := NewDecoder(32 << 10).Decode(sources, &out, DecodeOptions{})
	if err != nil {
		return nil, nil, err
	}
	return out.Bytes(), meta, nil
}

// EncodeCollect runs streaming encode into memory buffers (tests).
func EncodeCollect(secret, noise []byte, chunkSize int) (map[pcs.ParticleKind][]byte, *EncodeMeta, error) {
	var ec, oc, en, on, cp, np bytesCollector
	enc := NewEncoderWithNoise(chunkSize, bytes.NewReader(noise))
	meta, err := enc.Encode(bytes.NewReader(secret), Writers{EC: &ec, OC: &oc, EN: &en, ON: &on, CP: &cp, NP: &np}, EncodeOptions{})
	if err != nil {
		return nil, nil, err
	}
	return map[pcs.ParticleKind][]byte{
		pcs.EvenCypher: ec.buf, pcs.OddCypher: oc.buf, pcs.EvenNoise: en.buf,
		pcs.OddNoise: on.buf, pcs.CypherParity: cp.buf, pcs.NoiseParity: np.buf,
	}, meta, nil
}

type bytesCollector struct{ buf []byte }

func (b *bytesCollector) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p...)
	return len(p), nil
}
