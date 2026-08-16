// Copyright (c) 2026 dido GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

package stream

import (
	"time"

	"github.com/eclipse-pcs/pcs"
	"github.com/eclipse-pcs/pcs/footer"
)

// EncodeMeta captures streaming encode metadata.
type EncodeMeta struct {
	SHA256      [32]byte
	Fingerprint *pcs.EncodeResult
	Footers     map[pcs.ParticleKind]*footer.Footer
	BytesProcessed int64
}

// DecodeMeta captures streaming decode metadata.
type DecodeMeta struct {
	SHA256    [32]byte
	Footers   map[pcs.ParticleKind]*footer.Footer
	BytesRead int64
}

// EncodeOptions controls footer fields stamped during streaming encode.
type EncodeOptions struct {
	WriteID uint64
	Mtime   time.Time
}

// DecodeOptions controls offset for streaming range reads.
type DecodeOptions struct {
	StartOffset int64
}

func secretSHA256(h interface{ Sum([]byte) []byte }) [32]byte {
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func fingerprintFromSHA256(sum [32]byte) (*pcs.EncodeResult, error) {
	return pcs.EncodeFingerprint(sum)
}

// mtimeFromOptions returns nanoseconds since epoch for footer mtime field.
func mtimeFromOptions(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}
