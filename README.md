# pcs

Go module implementing the [Particle Cloud Security (PCS)](https://github.com/eclipse-pcs) core:
math transforms, footer v1 codec, and streaming encoder/decoder.

Part of the PCS project family alongside [pcs-demo](https://github.com/eclipse-pcs/pcs-demo),
[pcs-service](https://github.com/eclipse-pcs/pcs-service),
[pcs-files-gateway](https://github.com/eclipse-pcs/pcs-files-gateway), and
[pcs-s3-gateway](https://github.com/eclipse-pcs/pcs-s3-gateway).

## Install

```bash
go get github.com/eclipse-pcs/pcs@v0.1.0
```

Requires Go 1.26+. No dependencies beyond the standard library.

## Packages

| Package | Purpose |
|---------|---------|
| `github.com/eclipse-pcs/pcs` | PCS math (`Split`, `Merge`, `Encrypt`, `Decrypt`, parity), layout helpers (`.ec` / `.oc` / … suffixes, storage roles), buffered `Encode` / `DecodeWithRecovery`, SHA-256 fingerprint shards |
| `github.com/eclipse-pcs/pcs/footer` | 64-byte footer v1: parse/marshal, cross-CRC and WriteID verification |
| `github.com/eclipse-pcs/pcs/stream` | O(chunk) streaming encoder and decoder with footer v1 |

On-disk particle layout: `[ payload ][ 64-byte footer ]`. See
[design/footer-v1.md](design/footer-v1.md) for the canonical format spec.

## Quick example

```go
import "github.com/eclipse-pcs/pcs"

secret := []byte("Hello Freiburg")
result, err := pcs.Encode(secret)
if err != nil { /* ... */ }

particles := map[pcs.ParticleKind][]byte{}
for _, kind := range pcs.AllParticleKinds {
    particles[kind] = pcs.EncodeResultShard(result, kind)
}

inv, _ := pcs.InventoryFromPresent(map[pcs.ParticleKind]bool{ /* ... */ })
decoded, usedParity, err := pcs.DecodeWithRecovery(inv, particles, int64(len(secret)))
```

Consumers attach footers and handle file/object I/O themselves; this module stays
storage-agnostic.

## Test

```bash
go test ./...
```

## License

Licensed under the [Eclipse Public License 2.0](LICENSE). See [NOTICE](NOTICE).
