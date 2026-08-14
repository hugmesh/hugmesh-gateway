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

A reusable cert-chain builder lives at
[`scripts/pki/build-chained-cert.sh`](../../scripts/pki/build-chained-cert.sh) in this
repo (the gateway is the natural home — it's the first thing every
external request hits and the canonical TLS terminator for the
platform). The script:

1. Reads the hugmesh.net intermediate (`--root-ca` flag).
2. Generates a new per-stack/per-brand intermediate signed by that root.
3. Mints leaf certs (server + mTLS client) signed by the intermediate.
4. Emits a single `fullchain.pem` (leaf + intermediate, root excluded
   per RFC 5246 — TLS clients should trust the root, not get it from
   the server).
5. Emits a `truststore.p12` containing the root + intermediate for
   Java services that need both.

A consuming stack's existing `scripts/gen-certs.sh` is
updated in a follow-up PR (see below) to call this script when
`CERT_CHAIN_MODE=chained` is set in the deploy env, falling back to
the existing self-signed flow otherwise.

## Operational consequences

- **Cert rotation**: rotating a stack/brand intermediate
  doesn't require the hugmesh.net root to be touched.
  Rotating the root requires a coordinated multi-stack rollout — but
  that's a once-every-N-years event and the trust bundle is the
  same shape across all stacks.
- **mTLS between stacks**: a downstream stack's BFF can present its
  mTLS client cert to a hugmesh.net service and the receiving
  side validates the chain through the shared root automatically.
  No manual truststore appends.
- **CT logging**: production leaf certs intended for a stack's public
  hostnames on the public internet still need to come from a
  publicly-trusted CA (Let's Encrypt or similar). The HugMesh-rooted
  chain is the INTERNAL trust hierarchy for service-to-service comms;
  the public edge cert is separate and lives in front of the gateway
  (each stack's `frontend/nginx-tls.conf` mount stays as-is).

## Follow-up PRs

- **Each consuming stack** — extend `scripts/gen-certs.sh` to accept
  `CERT_CHAIN_MODE=chained` + `HUGMESH_SYSTEMS_INTERMEDIATE_PATH`.
- **hugmesh.net** — publish the intermediate as a signed
  artefact via an internal release pipeline + document the rotation
  cadence.
- **All Spring services** — switch truststore generation to consume
  the shared bundle instead of importing one CA per stack.
