// Copyright (c) 2026 dido GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

package footer

import "github.com/eclipse-pcs/pcs"

// CrossCRCVerdict is the outcome of verifying a shard pair against cross-CRCs.
type CrossCRCVerdict int

const (
	CrossOK CrossCRCVerdict = iota
	CrossLeftCorrupt
	CrossRightCorrupt
	CrossBothCorrupt
)

func (v CrossCRCVerdict) String() string {
	switch v {
	case CrossOK:
		return "ok"
	case CrossLeftCorrupt:
		return "left-corrupt"
	case CrossRightCorrupt:
		return "right-corrupt"
	default:
		return "both-corrupt"
	}
}

// VerifyCrossCRC validates a shard pair using stored cross-CRCs.
func VerifyCrossCRC(leftPayload []byte, leftCrossCRC uint32, rightPayload []byte, rightCrossCRC uint32) CrossCRCVerdict {
	return VerifyCrossCRCSums(pcs.CRC32IEEE(leftPayload), leftCrossCRC, pcs.CRC32IEEE(rightPayload), rightCrossCRC)
}

// VerifyCrossCRCSums validates a shard pair using precomputed payload CRC sums.
func VerifyCrossCRCSums(leftSum, leftCrossCRC, rightSum, rightCrossCRC uint32) CrossCRCVerdict {
	leftOK := leftSum == rightCrossCRC
	rightOK := rightSum == leftCrossCRC
	switch {
	case leftOK && rightOK:
		return CrossOK
	case !leftOK && rightOK:
		return CrossLeftCorrupt
	case leftOK && !rightOK:
		return CrossRightCorrupt
	default:
		return CrossBothCorrupt
	}
}
