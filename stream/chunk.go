// Copyright (c) 2026 dido GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

package stream

// EverySecondByte returns every second byte of chunk starting at startIdx.
func EverySecondByte(chunk []byte, startIdx int) []byte {
	if startIdx >= len(chunk) {
		return nil
	}
	resultLen := (len(chunk) - startIdx + 1) / 2
	out := make([]byte, resultLen)
	for i := range out {
		out[i] = chunk[startIdx+2*i]
	}
	return out
}

func everySecondByteInto(chunk []byte, startIdx int, scratch *[]byte) []byte {
	if startIdx >= len(chunk) {
		return nil
	}
	resultLen := (len(chunk) - startIdx + 1) / 2
	if cap(*scratch) < resultLen {
		*scratch = make([]byte, resultLen)
	} else {
		*scratch = (*scratch)[:resultLen]
	}
	out := *scratch
	for i := range out {
		out[i] = chunk[startIdx+2*i]
	}
	return out
}

// MergeInterleaved reconstructs n plaintext bytes from even/odd particle chunks.
func MergeInterleaved(even, odd []byte, startIdx, n int) []byte {
	out := make([]byte, n)
	MergeInterleavedInto(even, odd, startIdx, out)
	return out
}

// MergeInterleavedInto writes reconstructed bytes into dst[:n].
func MergeInterleavedInto(even, odd []byte, startIdx int, dst []byte) {
	evenIdx, oddIdx := 0, 0
	for i := range dst {
		if (startIdx+i)%2 == 0 {
			dst[i] = even[evenIdx]
			evenIdx++
		} else {
			dst[i] = odd[oddIdx]
			oddIdx++
		}
	}
}

// EvenCountForRange returns even-stream bytes needed for n plaintext bytes at startIdx.
func EvenCountForRange(startIdx, n int) int {
	if n <= 0 {
		return 0
	}
	if startIdx%2 == 0 {
		return (n + 1) / 2
	}
	return n / 2
}

// MaxReadable returns the largest n <= want where even/odd streams have enough bytes.
func MaxReadable(evenAvail, oddAvail, startIdx, want int) int {
	lo, hi := 0, want
	for lo < hi {
		mid := (lo + hi + 1) / 2
		evenNeed := EvenCountForRange(startIdx, mid)
		if evenAvail >= evenNeed && oddAvail >= mid-evenNeed {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

// SplitStartIndices returns even/odd start indices for a chunk at globalByteIndex.
func SplitStartIndices(globalByteIndex int) (startEven, startOdd int) {
	if globalByteIndex%2 == 0 {
		return 0, 1
	}
	return 1, 0
}
