// Copyright (c) 2026 dido GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

package pcs

import "hash/crc32"

// CRC32IEEE returns the CRC-32 (IEEE) checksum of data.
func CRC32IEEE(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}
