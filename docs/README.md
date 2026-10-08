# Gateway docs index

This `docs/` tree is the repo's wiki. The platform does not use GitHub's built-in
wiki; each repo keeps its docs beside its code. Start with the top-level
[`README.md`](../README.md) (what the gateway does, current state, architecture,
configuration) and [`ROADMAP.md`](../ROADMAP.md) (what is built, what is not). The
pages below go deeper.

## Pages

- [`decisions/001-cert-chain-hierarchy.md`](decisions/001-cert-chain-hierarchy.md)
  — ADR: why the platform's PKI has one `hugmesh.net` root with per-stack and
  per-brand intermediates, and how
  [`scripts/pki/build-chained-cert.sh`](../scripts/pki/build-chained-cert.sh)
  (in this repo) builds the chain.
- [`testing/MULTI-ISSUER-SLICE.md`](testing/MULTI-ISSUER-SLICE.md) — the
  multi-issuer security-slice test pattern (`TestIssuer` and `SecuritySliceSupport`,
  under `src/test/.../testsupport` and `src/test/.../config`). It was built here
  first; each of the nine other resource-server repos now has a copy.
