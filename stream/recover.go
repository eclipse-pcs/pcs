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
	"fmt"
	"io"
)

// RecoverRole selects which core stream is synthesized from partner + parity.
type RecoverRole int

const (
	RecoverEven RecoverRole = iota
	RecoverOdd
)

// recoverRole is the internal alias used by the decoder.
type recoverRole = RecoverRole

// reconstructingReader synthesizes a missing core stream incrementally.
type reconstructingReader struct {
	partner  io.Reader
	parity   io.Reader
	role     RecoverRole
	oddLength bool

	buf         []byte
	scratch     [4096]byte
	partnerDone bool
	parityDone  bool
	eof         bool

	partnerTotal int
	parityTotal  int
	lastPartner  byte
	lastParity   byte
	hasPartner   bool
	hasParity    bool
}

func newReconstructingReader(partner, parity io.Reader, role RecoverRole, oddLength bool) *reconstructingReader {
	if partner == nil {
		partner = emptyReader{}
	}
	if parity == nil {
		parity = emptyReader{}
	}
	return &reconstructingReader{partner: partner, parity: parity, role: role, oddLength: oddLength}
}

type emptyReader struct{}

func (emptyReader) Read([]byte) (int, error) { return 0, io.EOF }

func (r *reconstructingReader) Read(p []byte) (int, error) {
	if r.eof {
		return 0, io.EOF
	}
	if len(r.buf) == 0 {
		if err := r.fill(); err != nil {
			return 0, err
		}
		if len(r.buf) == 0 {
			r.eof = true
			return 0, io.EOF
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func (r *reconstructingReader) fill() error {
	for len(r.buf) < cap(r.scratch) {
		if !r.partnerDone {
			if err := r.xorPair(); err != nil {
				return err
			}
		}
		if r.partnerDone {
			if err := r.finishTail(); err != nil {
				return err
			}
			return nil
		}
	}
	return nil
}

func (r *reconstructingReader) xorPair() error {
	pn, perr := r.partner.Read(r.scratch[:])
	if pn == 0 && perr == io.EOF {
		r.partnerDone = true
		return nil
	}
	if perr != nil && perr != io.EOF {
		return fmt.Errorf("read recovery partner: %w", perr)
	}
	if pn == 0 {
		return nil
	}
	r.partnerTotal += pn
	r.lastPartner = r.scratch[pn-1]
	r.hasPartner = true

	pr := make([]byte, pn)
	qn, qerr := io.ReadFull(r.parity, pr)
	if qerr == io.EOF || qerr == io.ErrUnexpectedEOF {
		if qn == 0 {
			return fmt.Errorf("parity shorter than partner during recovery")
		}
	} else if qerr != nil {
		return fmt.Errorf("read recovery parity: %w", qerr)
	}
	r.parityTotal += qn
	r.lastParity = pr[qn-1]
	r.hasParity = true

	for i := 0; i < qn; i++ {
		r.buf = append(r.buf, r.scratch[i]^pr[i])
	}
	if perr == io.EOF {
		r.partnerDone = true
	}
	if qn < pn {
		r.parityDone = true
	}
	return nil
}

func (r *reconstructingReader) finishTail() error {
	if r.parityDone {
		return r.trimOddLengthOddTail()
	}
	switch r.role {
	case RecoverEven:
		var tail [1]byte
		n, err := r.parity.Read(tail[:])
		if n == 0 && err == io.EOF {
			r.parityDone = true
			return r.trimOddLengthOddTail()
		}
		if n != 1 {
			return fmt.Errorf("expected 1-byte odd-length parity tail, got %d", n)
		}
		r.parityTotal++
		r.lastParity = tail[0]
		r.hasParity = true
		r.buf = append(r.buf, tail[0])
		r.parityDone = true
		if err == io.EOF {
			return r.trimOddLengthOddTail()
		}
		return err
	case RecoverOdd:
		if r.parityTotal == r.partnerTotal {
			r.parityDone = true
			return r.trimOddLengthOddTail()
		}
		var discard [1]byte
		n, err := r.parity.Read(discard[:])
		if n == 0 && err == io.EOF {
			r.parityDone = true
			return r.trimOddLengthOddTail()
		}
		if n == 1 {
			r.parityDone = true
			return r.trimOddLengthOddTail()
		}
		return fmt.Errorf("unexpected parity tail read n=%d err=%v", n, err)
	default:
		r.parityDone = true
		return nil
	}
}

func (r *reconstructingReader) trimOddLengthOddTail() error {
	if r.role != RecoverOdd {
		return nil
	}
	if !r.hasPartner || !r.hasParity {
		return nil
	}
	if r.partnerTotal != r.parityTotal {
		return nil
	}
	if r.lastPartner != r.lastParity {
		return nil
	}
	if len(r.buf) > 0 {
		r.buf = r.buf[:len(r.buf)-1]
	}
	return nil
}

// ReconstructCollect reads partner+parity fully and returns synthesized core bytes (tests).
func ReconstructCollect(partner, parity []byte, role RecoverRole, oddLength bool) ([]byte, error) {
	r := newReconstructingReader(bytes.NewReader(partner), bytes.NewReader(parity), role, oddLength)
	var out bytes.Buffer
	if _, err := io.Copy(&out, r); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
