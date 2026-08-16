// Copyright (c) 2026 dido GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

// Package footer implements the PCS particle footer v1 codec.
package footer

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/eclipse-pcs/pcs"
)

const (
	// Size is the fixed footer length in bytes for version 1.
	Size = 64

	Version = 1

	magic0 = 'P'
	magic1 = 'C'
	magic2 = 'S'
	magic3 = 0x00
)

// Footer is the 64-byte particle footer (footer-v1).
type Footer struct {
	Version          uint16
	Kind             pcs.ParticleKind
	Length           uint64
	FingerprintShard [16]byte
	PayloadCRC       uint32
	CrossCRC         uint32
	WriteID          uint64
	Mtime            int64
}

// Marshal serializes the footer to a fixed 64-byte array.
func (f *Footer) Marshal() [Size]byte {
	var out [Size]byte
	out[0] = magic0
	out[1] = magic1
	out[2] = magic2
	out[3] = magic3
	binary.LittleEndian.PutUint16(out[4:], Version)
	out[6] = byte(f.Kind)
	out[7] = 0 // flags
	binary.LittleEndian.PutUint64(out[8:], f.Length)
	copy(out[16:32], f.FingerprintShard[:])
	binary.LittleEndian.PutUint32(out[32:], f.PayloadCRC)
	binary.LittleEndian.PutUint32(out[36:], f.CrossCRC)
	binary.LittleEndian.PutUint64(out[40:], f.WriteID)
	binary.LittleEndian.PutUint64(out[48:], uint64(f.Mtime))
	// reserved bytes 56-63 remain zero
	return out
}

// Parse validates and decodes a 64-byte footer.
func Parse(data []byte) (*Footer, error) {
	if len(data) != Size {
		return nil, fmt.Errorf("footer length %d, want %d", len(data), Size)
	}
	if data[0] != magic0 || data[1] != magic1 || data[2] != magic2 || data[3] != magic3 {
		return nil, fmt.Errorf("invalid footer magic")
	}
	version := binary.LittleEndian.Uint16(data[4:])
	if version != Version {
		return nil, fmt.Errorf("unsupported footer version %d", version)
	}
	kind := pcs.ParticleKind(data[6])
	if kind < pcs.EvenCypher || kind > pcs.NoiseParity {
		return nil, fmt.Errorf("invalid particle kind %d", kind)
	}
	if data[7] != 0 {
		return nil, fmt.Errorf("non-zero footer flags")
	}
	for i := 56; i < Size; i++ {
		if data[i] != 0 {
			return nil, fmt.Errorf("non-zero reserved byte at offset %d", i)
		}
	}
	var f Footer
	f.Version = version
	f.Kind = kind
	f.Length = binary.LittleEndian.Uint64(data[8:])
	copy(f.FingerprintShard[:], data[16:32])
	f.PayloadCRC = binary.LittleEndian.Uint32(data[32:])
	f.CrossCRC = binary.LittleEndian.Uint32(data[36:])
	f.WriteID = binary.LittleEndian.Uint64(data[40:])
	f.Mtime = int64(binary.LittleEndian.Uint64(data[48:]))
	if f.WriteID == 0 {
		return nil, fmt.Errorf("zero WriteID")
	}
	return &f, nil
}

// NewWriteID returns a random non-zero WriteID.
func NewWriteID() (uint64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("generate WriteID: %w", err)
	}
	id := binary.LittleEndian.Uint64(buf[:])
	if id == 0 {
		id = 1
	}
	return id, nil
}

// PayloadLen returns payload bytes from a reported object size.
func PayloadLen(reportedSize int64) (int64, error) {
	if reportedSize < Size {
		return 0, fmt.Errorf("object size %d smaller than footer (%d)", reportedSize, Size)
	}
	return reportedSize - Size, nil
}

// LogicalSizeFromPayloadSizes derives logical length from one even-type and one odd-type payload size.
func LogicalSizeFromPayloadSizes(evenType, oddType int64) int64 {
	return evenType + oddType
}

// LogicalSizeCandidates returns the two possible logical lengths when both odd cores are missing.
func LogicalSizeCandidates(evenType int64) (oddLen, evenLen int64) {
	return 2*evenType - 1, 2 * evenType
}

// ReadAt reads and parses the footer from the last 64 bytes of an object.
func ReadAt(r io.ReaderAt, objectSize int64) (*Footer, error) {
	if objectSize < Size {
		return nil, fmt.Errorf("object size %d smaller than footer (%d)", objectSize, Size)
	}
	buf := make([]byte, Size)
	if _, err := r.ReadAt(buf, objectSize-Size); err != nil {
		return nil, fmt.Errorf("read footer: %w", err)
	}
	return Parse(buf)
}

// PartnerKind returns the cross-CRC partner for kind.
func PartnerKind(kind pcs.ParticleKind) pcs.ParticleKind {
	switch kind {
	case pcs.EvenCypher:
		return pcs.OddCypher
	case pcs.OddCypher:
		return pcs.EvenCypher
	case pcs.OddNoise:
		return pcs.EvenNoise
	case pcs.EvenNoise:
		return pcs.OddNoise
	case pcs.CypherParity:
		return pcs.NoiseParity
	case pcs.NoiseParity:
		return pcs.CypherParity
	default:
		return kind
	}
}

// CrossCRCPairs returns the three partner pairs for cross-CRC verification.
func CrossCRCPairs() [][2]pcs.ParticleKind {
	return [][2]pcs.ParticleKind{
		{pcs.EvenCypher, pcs.OddCypher},
		{pcs.OddNoise, pcs.EvenNoise},
		{pcs.CypherParity, pcs.NoiseParity},
	}
}

// VerifyWriteIDs requires all present footers to share the same WriteID.
func VerifyWriteIDs(footers map[pcs.ParticleKind]*Footer) error {
	var want uint64
	var seen bool
	for _, kind := range pcs.AllParticleKinds {
		f := footers[kind]
		if f == nil {
			continue
		}
		if !seen {
			want = f.WriteID
			seen = true
			continue
		}
		if f.WriteID != want {
			return fmt.Errorf("WriteID mismatch on %s: got %016x want %016x", kind, f.WriteID, want)
		}
	}
	if !seen {
		return fmt.Errorf("no footers to verify")
	}
	return nil
}

// CopyFingerprintShard copies a variable-length shard into the fixed footer field.
func CopyFingerprintShard(dst *[16]byte, shard []byte) {
	clear(dst[:])
	copy(dst[:], shard)
}
