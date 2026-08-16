# Plan: the `github.com/eclipse-pcs/pcs` Go module

Goal: one shared Go module implementing the PCS core (math, footer v1 codec,
streaming encoder/decoder) consumed by pcs-demo, pcs-service,
pcs-files-gateway, pcs-s3-gateway, and later a PCS virtual remote for rclone.

Read first: [footer-v1.md](footer-v1.md) — the canonical format spec. This
plan does not restate it.

## Context for a fresh session

Four sibling repos under `~/go/src/` each carry their own copy of the PCS
core today:

- `pcs-demo/internal/pcs` — reference implementation (MD5 fingerprint,
  12-byte tail, `.e`/`.o` suffixes, `.cp_`/`.np_` odd-length convention)
- `pcs-service/internal/pcs` + `internal/stream` — adds streaming (O(chunk)
  memory) and merge planning
- `pcs-files-gateway/internal/pcs` + `internal/stream` — most evolved copy of
  both packages (streaming recovery, footer assembly, seek support)
- `pcs-s3-gateway/internal/pcs` — independent rewrite of the same math with a
  cleaner API (SHA-256 fingerprint, `IntegrityMeta` tag, cross-CRC verdicts,
  fingerprint healing)

The module supersedes all four copies. Seed sources: math and streaming from
**pcs-files-gateway** (most current demo lineage); API style, SHA-256
fingerprint handling, cross-CRC verdicts, and fingerprint-shard recovery from
**pcs-s3-gateway**.

## Module skeleton

- Path: `github.com/eclipse-pcs/pcs` (local folder `~/go/src/pcs`)
- Go version: 1.26.x. **No external dependencies** — stdlib only
  (`crypto/rand`, `crypto/sha256`, `hash/crc32`, `encoding/binary`, `io`).
- License: EPL-2.0. `LICENSE`, `NOTICE`, and per-file headers as in
  pcs-files-gateway (`Copyright (c) 2026 dido GmbH and others.` /
  `SPDX-License-Identifier: EPL-2.0`).
- Wire consumers locally until the GitHub org exists: create
  `~/go/src/go.work` with `use` entries for `pcs` and the four projects
  (do this in the first consumer migration, not here).

## Package `pcs` (repo root) — pure math

Exports (seeded from `pcs-files-gateway/internal/pcs` unless noted):

- `Split`, `Merge`, `Encrypt`, `Decrypt`, `ParityPadded`, `RandomNoise`
- `ReconstructFromParityEven`, `ReconstructOddFromParityOdd`,
  `ReconstructEvenFromParityOdd` (from `decode.go`)
- `ParticleKind` enum in footer order: `EvenCypher(0)`, `OddCypher(1)`,
  `EvenNoise(2)`, `OddNoise(3)`, `CypherParity(4)`, `NoiseParity(5)`;
  `AllParticleKinds`, `CoreParticleKinds`, `String()`
- Layout helpers (from pcs-s3-gateway `layout.go`): `ParticleSuffix` (unified
  set `.ec .oc .en .on .cp .np`), `StorageForParticle` (A: ec+on, B: oc+en,
  C: cp+np), `ShardKey`, `LogicalKeyFromShard`, `IsParticleShard`
- Buffered convenience path (style of pcs-s3-gateway `codec.go`):
  `Encode(secret) (*EncodeResult, error)` with named particle fields,
  `EncodeResultShard`, `DecodeFromParticles`, `DecodeWithRecovery`
- `ParticleInventory`: presence + recovery planning only. **Delete** the
  `EvenLength` / `OddLengthOnly` / `UseOddParity` fields — length parity now
  comes from the footer / size arithmetic (spec: "Size and parity
  derivation"). Recovery entry points take the logical length (or the parity
  bit derived from it) as an explicit parameter.
- Fingerprint (SHA-256 based, from pcs-s3-gateway):
  `EncodeFingerprint([32]byte) (*EncodeResult, error)`,
  `DecodeFingerprint`, `RecoverAllFingerprintShards`
- `CRC32IEEE(data []byte) uint32`

Explicitly **not** in the module: `PrintableNoise`, `ParityLegacy` (pcs-demo
GUI artifacts; they stay in pcs-demo), file-system storage helpers
(`SaveEncodedFile`, `ScanParticleInventory` on disk, …) — file/object I/O is
the consumer's job. Also out: healing orchestration, quorum/transactions,
tagging, network protocols.

## Package `footer`

Implements footer-v1.md exactly:

- `const Size = 64`, magic/version constants, `Kind` mapping to/from
  `pcs.ParticleKind`
- `type Footer struct { Version uint16; Kind pcs.ParticleKind; Length uint64;
  FingerprintShard [16]byte; PayloadCRC uint32; CrossCRC uint32;
  WriteID uint64; Mtime int64 }`
- `(f *Footer) Marshal() [Size]byte` and `Parse([]byte) (*Footer, error)`
  with strict validation (magic, version, kind range, zero flags/reserved)
- `NewWriteID() (uint64, error)` — crypto/rand, non-zero
- `PayloadLen(reportedSize int64) (int64, error)` (reject < 64)
- `LogicalSizeFromPayloadSizes(evenType, oddType int64) int64` and
  `LogicalSizeCandidates(evenType int64) (odd, even int64)` for the
  both-odd-missing ambiguity
- `ReadAt(r io.ReaderAt, objectSize int64) (*Footer, error)` — the fail-fast
  pre-read primitive for range-capable stores
- Cross-CRC verdicts (port from pcs-s3-gateway `integrity.go`):
  `VerifyCrossCRC(leftPayload, leftFooter, rightPayload, rightFooter)` →
  `CrossOK | CrossLeftCorrupt | CrossRightCorrupt | CrossBothCorrupt`
- `VerifyWriteIDs(map[pcs.ParticleKind]*Footer) error` — all present must
  agree

## Package `stream`

Seeded from `pcs-files-gateway/internal/stream`, adapted to the spec's
streaming contracts:

- `Encoder`: `NewEncoder(chunkSize)`, `NewEncoderWithNoise(chunkSize,
  io.Reader)` (deterministic tests). `Encode(secret io.Reader, outs Writers,
  opts EncodeOptions) (*EncodeMeta, error)` writes payloads and **appends the
  six v1 footers itself** at EOF. `EncodeOptions{WriteID uint64; Mtime
  time.Time}` (zero WriteID ⇒ generate). `EncodeMeta` returns the footers,
  SHA-256, byte count.
- `Decoder`: input changes from bare readers to
  `type Source struct { R io.Reader; PayloadLen int64 }` —
  `Decode(sources Sources, out io.Writer, opts DecodeOptions) (*DecodeMeta,
  error)`. Missing particle ⇒ nil reader with `PayloadLen = -1` (unknown).
  Behavior per spec: parse footer at each payload boundary; recovery readers
  for missing cores (port `recover.go`; replace the `useOddParity` flag with
  length-driven tail handling, deferring the last byte in the ambiguous case
  until the parity footer is parsed); verify own-CRC, cross-CRC, fingerprint,
  WriteID agreement at end; `DecodeOptions{StartOffset int64}` retained for
  seek/range support.
- Keep the chunk math helpers (`chunk.go`: `EverySecondByte`,
  `mergeInterleaved*`, `evenCountForRange`, `maxReadable`).

## Tests (the consolidated suite — projects keep only integration tests)

Port and unify from all four copies:

1. Golden vectors with `EncoderWithNoise` (deterministic): known secret +
   noise ⇒ exact particle payload bytes and exact 64-byte footers. Cover
   n = 0, 1, 2, odd, even, and n > several chunk sizes.
2. Recovery matrix (port from pcs-service/pcs-files-gateway test data
   concepts): every recoverable loss pattern × odd/even length, streaming and
   buffered paths, including **both-odd-missing** (the size-ambiguous case).
3. Corruption matrix: flip payload bytes ⇒ own-CRC and cross-CRC verdicts;
   mismatched WriteIDs ⇒ error; truncated/oversized footer ⇒ parse errors.
4. Fingerprint: verify after decode; shard recovery with partial shard sets.
5. Round-trip property test: random lengths 0..~4·chunkSize+3, random loss
   pattern, encode → decode == input.
6. Buffered ⇄ streaming equivalence: `pcs.Encode` output + footers ==
   `stream.Encoder` output for the same secret/noise.

## Acceptance

- `go test ./...` green; no external deps in `go.mod`
- `go vet ./...` clean
- Coverage of `pcs`, `footer`, `stream` ≥ 80% each (current per-project
  copies sit at 73–78%; the consolidated suite should exceed them)

## Non-goals (follow-ups tracked elsewhere)

- rclone PCS virtual remote (consumes this module later)
- healing/quorum abstractions (project-specific for now)
- compression variants (footer v2 / flag bits)
