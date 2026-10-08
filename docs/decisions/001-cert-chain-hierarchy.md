# 001 — Cert-chain hierarchy across HugMesh stacks

## Context

Each HugMesh platform stack and per-tier gateway instance
(`hugmesh-{pki,be,fe}-gateway`, and per-brand
`${BRAND}-{pki,be,fe}-gateway`) currently generates its own self-signed CA for
development and e2e via `scripts/gen-certs.sh`. In production this would leave the platform with
N disjoint trust roots — every downstream service that talks to another
stack has to import every other stack's CA into its truststore, and a
cert rotation in one stack forces a truststore update across all the
others.

The production cert hierarchy roots every stack at a single
**hugmesh.net** root, with one intermediate per stack/brand
chained from it. Any additional stack — including an **optional, opt-in**
add-on stack incubated inside the hugmesh.net container — derives
its trust from the same root:

```
hugmesh.net Root CA           (offline, long-lived)
   │
   ├── hugmesh.net Intermediate CA
   │      └── hugmesh-pki-gateway server cert
   │      └── hugmesh-be-gateway server cert
   │      └── hugmesh-fe-gateway server cert
   │
   └── per-brand Intermediate CA                     ←── chained from the same root
          └── ${BRAND}-{pki,be,fe}-gateway server certs
          └── per-brand frontend server cert
          └── per-brand BFF mTLS client cert
```

> The leaf names above are **illustrative** of the per-stack / per-tier / per-brand
> pattern. The running gateway instances follow the canonical tier naming
> (`hugmesh-{pki,be,fe}-gateway`, and per-brand `${BRAND}-{pki,be,fe}-gateway`);
> the legacy `hugmesh-id-gateway` / `hugmesh-systems-gateway` names are
> superseded — instances are `SPRING_APPLICATION_NAME` variants of the **one**
> gateway image, not separate certs per repo.

One root, one intermediate per stack/brand, leaf certs minted off the
intermediate that matches the deployment. Trust the root once and every
leaf validates.

## Decision

Production PKI is rooted at **hugmesh.net**. Each additional
stack/brand intermediate is **chained from** that root; all of a stack's
leaves chain back to hugmesh.net via that single intermediate.

In concrete terms:

1. The root CA + the hugmesh.net intermediate live on the
   hugmesh.net deployment host (offline-ish; only the
   intermediate is hot for signing).
2. Each additional stack/brand build receives its own intermediate +
   key as a signed deployable artefact (out-of-band from the
   hugmesh.net team). That stack uses its intermediate to
   mint its own leaves — but the chain stops at the hugmesh.net
   root.
3. Every HugMesh container ships with `ca-bundle.crt` containing
   ONLY the hugmesh.net root + the intermediates in use. No
   per-leaf trust.
4. The dev / e2e flow keeps the existing per-repo `scripts/gen-certs.sh`
   (one self-signed CA per stack) because:
   - Builds without internet access can't fetch the real root.
   - The dev cert never needs to interop with another stack — the
     stack is started in isolation.
   The script grows a `--chain-from <path>` flag for the rare case
   when a tester wants to validate chain-build locally; production
   builds always use the chained mode.

## Implementation

The cert-chain builder is
[`scripts/pki/build-chained-cert.sh`](../../scripts/pki/build-chained-cert.sh), in
this repo. The gateway is its natural home: it is the first thing every external
request hits and the platform's TLS terminator. The script:

1. Reads the hugmesh.net root certificate and key (`--root-ca`, `--root-key`).
2. Generates one new per-stack/per-brand intermediate (named by `--stack`) signed by that root.
3. Mints leaf certs (server + mTLS client) signed by the intermediate.
4. Emits a single `fullchain.pem` (leaf + intermediate, root excluded
   per RFC 5246). TLS clients should trust the root, not get it from
   the server.
5. Emits a `truststore.p12` with the root and the intermediate, for
   Java services that need both.

The script runs `openssl` and `keytool` inside short-lived Docker containers
(`alpine:3.20`, `eclipse-temurin:21-jre`), so the host needs only Docker. It
skips generation when `intermediate.crt` and `truststore.p12` already exist in
the output directory.

A follow-up PR (see below) was to update each consuming stack's
`scripts/gen-certs.sh` to call this script when `CERT_CHAIN_MODE=chained` is set
in the deploy env, and to fall back to the self-signed flow otherwise.

## Operational consequences

- **Cert rotation**: rotating a stack/brand intermediate
  does not touch the hugmesh.net root.
  Rotating the root needs a coordinated multi-stack rollout. That happens once
  every few years, and the trust bundle has the same shape in every stack.
- **mTLS between stacks**: a downstream stack's BFF presents its
  mTLS client cert to a hugmesh.net service, and the receiving
  side validates the chain through the shared root. No manual truststore appends.
- **CT logging**: production leaf certs for a stack's public
  hostnames still come from a publicly trusted CA (Let's Encrypt or similar).
  The HugMesh-rooted chain is the INTERNAL trust hierarchy for service-to-service
  traffic. The public edge cert is separate and sits in front of the gateway
  (each stack's `frontend/nginx-tls.conf` mount stays as it is).

## Follow-up PRs

- **Each consuming stack** — extend `scripts/gen-certs.sh` to accept
  `CERT_CHAIN_MODE=chained` + `HUGMESH_SYSTEMS_INTERMEDIATE_PATH`.
- **hugmesh.net** — publish the intermediate as a signed
  artefact via an internal release pipeline + document the rotation
  cadence.
- **All Spring services** — switch truststore generation to consume
  the shared bundle instead of importing one CA per stack.

## Status (checked 2026-10-07)

The builder script exists. The first follow-up does not: a search of `origin/main`
in every local `hugmesh-*` checkout for `CERT_CHAIN_MODE`, `chain-from` and
`HUGMESH_SYSTEMS_INTERMEDIATE_PATH` finds this file alone. The dev/e2e script that
exists is `tests/stack/gen-certs.sh` in `hugmesh-generator`. It makes one
self-signed CA and has no chained mode. This repo has no `scripts/gen-certs.sh`.
The other two follow-ups (the signed-intermediate release pipeline and the shared
truststore) were not checked.
