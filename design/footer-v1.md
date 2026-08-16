# PCS Particle Footer v1 — Canonical Specification

Status: **agreed 2026-07-03** (design session across pcs-demo, pcs-service,
pcs-files-gateway, pcs-s3-gateway). This document is the single source of
truth for the on-disk / on-object particle format. Project migration plans
reference this file; do not fork or paraphrase it into other repos.

## Background

PCS distributes one logical object into six particle objects across three
storages. Each particle needs "warehousing" metadata for integrity
verification and reconstruction. Historically this was implemented three
different ways:

- pcs-demo / pcs-service / pcs-files-gateway: 12-byte tail
  (8-byte MD5 hash shard + 4-byte cross-CRC), odd/even object length signaled
  via parity filename suffixes `.cp_` / `.np_`
- pcs-s3-gateway: S3 object tag `pcs2`
  (`v=1:n=…:xcrc=…:fp=<base64 SHA-256 shard>:wid=…`)
- rclone `rs` backend (Reed-Solomon, not PCS): 104-byte binary footer —
  design reference only

These are replaced by **one identical footer for all PCS projects**. Existing
files/objects are discarded (pre-production; no read compatibility required).

## Decisions this format encodes

| Issue | Decision |
|---|---|
| A | Footer in the particle body replaces the S3 tag. The footer is set at particle creation and is immutable for the particle lifetime — a body suffix enforces this by construction; a tag cannot. |
| B | Logical object length lives in the footer; the `.cp_` / `.np_` filename convention is retired. One suffix set for all projects. |
| C | WriteID (from the rclone `rs` design) in every PCS implementation. |
| D | CRC32 **IEEE** polynomial everywhere. |
| — | Fingerprint digest is **SHA-256** (not MD5), PCS-encoded into six shards; each particle carries only its own opaque 16-byte shard. Plaintext digests must never be stored (confidentiality: no provider may learn a content fingerprint). |

## Particle file layout

```
[ particle payload (core or parity bytes) ][ 64-byte footer ]
```

The payload is exactly the bytes produced by the PCS transform for this
particle kind. `payload length = reported object size − 64` on every storage.

## Footer layout (64 bytes, little-endian, fixed offsets)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | magic | ASCII `P`, `C`, `S`, `0x00` |
| 4 | 2 | version (u16) | `1` |
| 6 | 1 | particle kind (u8) | 0=ec 1=oc 2=en 3=on 4=cp 5=np |
| 7 | 1 | flags (u8) | `0`; reserved (e.g. future compression inventory) |
| 8 | 8 | logical length (u64) | length of the original secret in bytes |
| 16 | 16 | fingerprint shard | this particle's PCS shard of SHA-256(secret) |
| 32 | 4 | own-payload CRC (u32) | CRC32-IEEE of **this** particle's payload |
| 36 | 4 | cross-CRC (u32) | CRC32-IEEE of the **partner** particle's payload |
| 40 | 8 | WriteID (u64) | random per-PUT nonce; identical on all six particles |
| 48 | 8 | mtime (i64) | ns since Unix epoch; `0` when unused |
| 56 | 8 | reserved | zero |

Parsers MUST reject: wrong magic, version ≠ 1, kind > 5, non-zero flags.
Writers MUST zero flags and reserved bytes. Future variants (e.g. a
compressing PCS) bump the version and/or define flag bits; the version implies
the footer length, which is fixed at 64 for v1.

### Field semantics

- **logical length** — replaces the underscore filename convention. Length
  parity (odd/even) steers parity-particle reconstruction: for odd length the
  parity payload is as long as the even payload and its **last byte is a
  verbatim copy of the even particle's last byte** (see `ParityPadded`);
  reconstruction of a missing odd particle must drop that phantom last XOR
  byte, and reconstruction of a missing even particle takes it verbatim.
- **fingerprint shard** — SHA-256 of the secret (32 bytes) is itself
  PCS-encoded: split/encrypt/parity exactly like a 32-byte secret, yielding
  six 16-byte shards (ec/oc/en/on of the digest are 16 bytes each — even and
  odd halves of cypher and noise — and cp/np are 16 bytes). Each particle
  stores only its own kind's shard. Verification reconstructs the digest from
  ≥ the recoverable shard set and compares with SHA-256 of the decoded secret.
  Shard recovery also enables fingerprint healing (see pcs-s3-gateway's
  `RecoverAllFingerprintShards` for the reference semantics).
- **own-payload CRC** — validates this particle in isolation; required when
  the partner particle is missing entirely (cross-CRC alone cannot cover that
  case).
- **cross-CRC** — CRC of the partner payload, enabling the "which of the pair
  is corrupt" verdict (see `VerifyCrossCRC` verdict logic in pcs-s3-gateway).
  Partner pairs: **ec↔oc, on↔en, cp↔np**.
- **WriteID** — random 64-bit nonce generated once per logical PUT and stamped
  identically into all six footers. WriteID MUST be non-zero; parsers MUST
  reject a zero WriteID. On read, all surviving particles MUST agree;
  disagreement means a torn / mixed-generation write and MUST fail the read
  (integrity error), never return silently mixed data.
- **mtime** — logical object modification time for stores that need it
  (future rclone PCS virtual remote). Gateways MAY write 0 or the source
  mtime; readers MUST tolerate 0.

CRCs cover the **payload only** (never the footer). All CRCs are CRC32 with
the IEEE polynomial (`hash/crc32.ChecksumIEEE`).

## Particle naming and placement (unified)

| Kind | Suffix | Storage |
|---|---|---|
| even cypher | `.ec` | A |
| odd cypher | `.oc` | B |
| even noise | `.en` | B |
| odd noise | `.on` | A |
| cypher parity | `.cp` | C |
| noise parity | `.np` | C |

No underscore variants. The demo-lineage suffixes `.e` / `.o` and
`.cp_` / `.np_` are retired.

## Size and parity derivation (no content reads)

All storages report object sizes without reading content (stat, WebDAV
PROPFIND, S3 listing/HEAD, Drive metadata). With `payload = size − 64`:

- even-type payloads (ec, en, cp, np) are `ceil(n/2)`;
  odd-type payloads (oc, on) are `floor(n/2)`
- any surviving even-type size + any surviving odd-type size yields the exact
  logical length `n`, including its parity
- **sole ambiguous case**: both odd particles (oc *and* on) missing — all
  surviving payloads equal `ceil(n/2)`, so `n ∈ {2c−1, 2c}`. Still
  recoverable (oc from ec⊕cp, on from en⊕np). Resolution needs no extra
  request: the footer trails the payload *in the same stream* and the payload
  boundary is known from the reported size, so the exact length arrives before
  the only decision that needs it (the final byte). Decoders hold back at most
  one output byte until the parity stream's footer is parsed.

## Streaming decode contract

Decoders take **six (reader, payload-length) pairs** (lengths from
stat/listing; a missing particle is a nil reader):

1. stream payloads chunk-wise; interior chunks are length-parity-agnostic
   (XOR reconstruction is positionally 1:1 until the final byte)
2. at each stream's known payload boundary, read and parse the 64-byte footer
3. at end of stream verify: own-CRCs, cross-CRCs, fingerprint (reconstruct
   digest from shards, compare to SHA-256 of decoded output), WriteID
   agreement across all particles that were read
4. any verification failure fails the read with an integrity error

**Fail-fast pre-read (optional optimization, not part of the contract):** on
range-capable storage (S3 `Range: bytes=-64`, local seek, WebDAV Range) a
reader MAY fetch all footers upfront to verify WriteID agreement before
streaming large bodies. This is the only way on S3 to detect a torn write
*before* the response starts. Range-less providers skip it; end-of-stream
verification remains authoritative either way.

## Streaming encode contract

Everything in the footer is computable in one pass: WriteID chosen at start;
length, SHA-256, and both CRC families accumulated incrementally; footers
assembled and appended after the last payload byte of each particle.

## Empty objects

`n = 0`: all payloads are empty; every particle file is exactly 64 bytes of
footer. Minimum valid particle file size is therefore 64.
