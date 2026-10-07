# tsa-witness-evidence

Independent evidence store for Shyware period-close checkpoints — written to
by `ShywareLLC/core`'s `cmd/tsa-witness`, running on `shyvoting-validator-1`.

**Deliberately a separate GitHub organization repo, not stored only on the
validator's own disk or AWS account.** This is the "external witness" layer
threat-model.md T21 calls for: a party (GitHub, a different company) that
doesn't share control with the AWS account running the validator holds a
copy too, so an operator who could tamper with the validator's own disk
still can't erase the evidence trail here without that also being visible
in this repo's own commit history.

## What's here

For each `rolling_attestation`/`poll_closed` checkpoint `tsa-witness`
observes, two files land in `evidence/`:

- `<pollID>[-seq<N>|-close>].json` — the canonical payload that was
  timestamped (scoping ID, sequence, L1/L2 Merkle-root commitments, height).
  Field order is fixed by Go struct declaration, so anyone holding the
  chain's own public event history can reconstruct this file byte-for-byte
  from the event alone and confirm it matches.
- `<pollID>[-seq<N>|-close>].tsr` — the raw RFC 3161 response token from the
  Time Stamp Authority (`timestamp.digicert.com`), independently verifiable
  with any RFC 3161 client (e.g. Go's `github.com/digitorus/timestamp`) against
  the `.json` file's hash.

## Why no KMS/HSM signature appears anywhere here

This evidence is about the ledger's own structurally-computed Merkle roots
(L1/L2 commitments) existing, unaltered, at a given time — a property that
doesn't depend on any signing key. Shyware's core guarantees are
structurally information-theoretic, not cryptographic; a KMS/HSM signature
is a separate, optional, dependent convenience layer for third-party
portability, not a requirement for this evidence to mean anything. See
`ShywareLLC/core/cmd/tsa-witness/README.md` and
`docs.shyware.fyi/trust-tiers/` for the fuller picture.

## Verifying an entry yourself

```go
payload, _ := os.ReadFile("evidence/some-poll-seq0.json")
tsrBytes, _ := os.ReadFile("evidence/some-poll-seq0.tsr")
ts, _ := timestamp.ParseResponse(tsrBytes)   // github.com/digitorus/timestamp
wantHash := sha256.Sum256(payload)
// ts.HashedMessage should equal wantHash; ts.Time is DigiCert's own
// independently-signed claim of when that hash existed.
```
