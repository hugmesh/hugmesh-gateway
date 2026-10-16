# Gateway docs index

This `docs/` tree is the repo's "wiki" (the platform doesn't use GitHub's
built-in wiki feature — per-repo docs live here instead). Start with the
top-level [`README.md`](../README.md) (what the gateway does, current state,
architecture, configuration) and [`ROADMAP.md`](../ROADMAP.md) (what's shipped
vs. still to build); the pages below are deeper dives that the top-level docs
link out to.

## Pages

- [`decisions/001-cert-chain-hierarchy.md`](decisions/001-cert-chain-hierarchy.md)
  — ADR: why the platform's PKI is rooted at a single `hugmesh.net`
  root with per-stack/per-brand intermediates, and how
  [`scripts/pki/build-chained-cert.sh`](../scripts/pki/build-chained-cert.sh)
  (which lives in this repo) implements it.
- [`decisions/002-bff-register-authenticated.md`](decisions/002-bff-register-authenticated.md)
  — ADR: `POST /bff/register` and `/bff/register/**` are cookie-authenticated
  (kept out of `PUBLIC_PATHS`), why, and which tests guard it.
- [`testing/MULTI-ISSUER-SLICE.md`](testing/MULTI-ISSUER-SLICE.md) — the
  reusable multi-issuer security-slice test pattern (`TestIssuer` +
  `SecuritySliceSupport`, under `src/test/.../testsupport` and
  `src/test/.../config`) built first in this repo and meant to be replicated
  verbatim across the other HugMesh resource-server repos.
