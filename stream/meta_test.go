// Copyright (c) 2026 dido GmbH and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

package stream

import (
	"testing"
	"time"
)

func TestMtimeFromOptions(t *testing.T) {
	if mtimeFromOptions(time.Time{}) != 0 {
		t.Fatal("zero time")
	}
	ts := time.Unix(1, 2)
	if mtimeFromOptions(ts) != ts.UnixNano() {
		t.Fatal("mtime")
	}
}
