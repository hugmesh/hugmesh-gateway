# Multi-issuer security-slice — the reusable test pattern

This is the **reference pattern** for proving a Spring WebFlux OAuth2 resource server
correctly handles **per-brand (multi-issuer) Casdoor tokens**, with the security
property that matters most: an **unknown issuer fails CLOSED (401)** and a token from
one brand can **never authenticate as another**.

It was built first in `hugmesh-gateway`. Replicate it verbatim across the
other [HugMesh](https://github.com/hugmesh) resource-server repos:

> [`hugmesh-actions`](https://github.com/hugmesh/hugmesh-actions),
> [`hugmesh-admin-bff`](https://github.com/hugmesh/hugmesh-admin-bff),
> [`hugmesh-mod-bff`](https://github.com/hugmesh/hugmesh-mod-bff),
> [`hugmesh-forum-bff`](https://github.com/hugmesh/hugmesh-forum-bff),
> [`hugmesh-wiki-bff`](https://github.com/hugmesh/hugmesh-wiki-bff),
> [`hugmesh-owncast-bff`](https://github.com/hugmesh/hugmesh-owncast-bff),
> [`hugmesh-tube-bff`](https://github.com/hugmesh/hugmesh-tube-bff),
> [`hugmesh-user-bff`](https://github.com/hugmesh/hugmesh-user-bff),
> [`hugmesh-federation-api`](https://github.com/hugmesh/hugmesh-federation-api).

The whole point is **determinism with no network and no live Casdoor**: each brand's
JWKS + OIDC discovery doc is served by a tiny in-process HTTP server bound to
`127.0.0.1`, so `ReactiveJwtDecoders.fromIssuerLocation(...)` validates real
RSA-signed tokens offline.

---

## What the slice asserts (the three keystones)

| # | Scenario | Expectation | Category |
|---|----------|-------------|----------|
| (a) | A brand-X-issuer JWT | resolves to brand-X's manager → **authenticated**, and the `DOMAIN_brandx` authority is emitted | USER-SITUATIONAL |
| (b) | A token from an issuer **not** in `app.tenancy.issuers` (well-formed, correctly signed, just unlisted) | the per-issuer resolver returns `Mono.empty()` → **401 fail-closed**, never a default-accept | CROSS-USER DENY |
| (c) | A brand-Y JWT presented to the resource server | scoped to brand-Y; can **never** become brand-X (no `DOMAIN_brandx`) | CROSS-USER DENY |

Plus the cheap fail-closed neighbours: a **tampered signature** and a **garbage
bearer** both 401.

---

## The two reusable seams

### 1. `TestIssuer` — mint issuer-specific JWTs against test JWKs (no network)

`src/test/java/.../testsupport/TestIssuer.java`. Each instance:

- generates a fresh RSA keypair;
- starts a JDK `HttpServer` on `127.0.0.1:<random-port>` serving
  `/.well-known/openid-configuration` (issuer + `jwks_uri`) and
  `/.well-known/jwks.json` (the public JWK set);
- exposes `issuerUri()` (the LHS of an `app.tenancy.issuers` pair) and
  `mint(subject, roleNames)` / `mintWithClaims(subject, claims)`.

A token minted by issuer A is cryptographically valid **only** against issuer A's
manager — that is exactly the cross-brand isolation (c). `AutoCloseable`; stop it in
`@AfterEach`.

Only dependency: `nimbus-jose-jwt`, already transitively on every resource-server's
classpath via `spring-boot-starter-oauth2-resource-server`. Copy the file as-is.

### 2. `SecuritySliceSupport` — build the REAL `SecurityWebFilterChain` into a `WebTestClient`

`src/test/java/.../config/SecuritySliceSupport.java`. It constructs the repo's real
`SecurityConfig.filterChain(ServerHttpSecurity.http())`, wraps it in a
`WebFilterChainProxy`, and installs it as a `webFilter` on
`WebTestClient.bindToController(...)`. **No full Spring Boot context** — the
production `authorizeExchange` policy and OAuth2 resource-server wiring run exactly
as deployed, but the test is a fast slice.

Helpers: `provider(resolver)` (take the multi-issuer swap) / `absent()` (single-issuer
`o.jwt(...)` path).

---

## How to replicate in another repo (checklist)

1. **Copy** `TestIssuer.java` into that repo's `testsupport` package (no edits).
2. **Copy** `SecuritySliceSupport.java` and point it at *that* repo's `SecurityConfig`
   constructor + `filterChain` signature. (If the repo's `SecurityConfig` takes
   different constructor args — e.g. no `DomainRegistry` — adjust `sliceClient`.)
3. **Write** `MultiIssuerSecuritySliceTest`:
   - `@BeforeEach`: spin up `brandX`, `brandY`, and a `rogue` (untrusted) `TestIssuer`;
   - build `DomainRegistry(brandX.issuerUri(), "<x>=brandx,<y>=brandy", "")` and assert
     `isMultiIssuer()`;
   - build the repo's multi-issuer resolver the way its tenancy config contributes it
     (`new TenancyResourceServerConfig(registry, "", "").tenantAuthManagerResolver()`);
   - `client = sliceClient(registry, provider(resolver), new AuthoritiesController())`;
   - add an `AuthoritiesController` (`GET /whoami`) that echoes
     `ReactiveSecurityContextHolder` authorities;
   - assert (a) `DOMAIN_brandx` + `ROLE_*`, (b) rogue → `isUnauthorized()`,
     (c) brand-Y → `DOMAIN_brandy` and NOT `DOMAIN_brandx`, plus tampered/garbage → 401.
4. **Optionally** add a coarse path-gate slice (see
   `SecurityConfigPathGateSliceTest` here) for that repo's own `authorizeExchange`
   rules — the slice plumbing is identical; only the path/role table changes.

> If a repo does NOT have multi-issuer (`TenancyResourceServerConfig`) wiring yet, the
> slice still applies once it does. Until then, copy the path-gate slice (single-issuer
> `absent()` path with a single `TestIssuer`) so its `authorizeExchange` policy is at
> least covered.

---

## Why fail-closed is the load-bearing assertion

The per-issuer resolver's allowlist is exactly `DomainRegistry.trustedIssuers()`. An
`iss` outside that set yields **no** authentication manager, so the
`JwtIssuerReactiveAuthenticationManagerResolver` surfaces a 401 **before any authority
is emitted** — there is no fallback "default" manager that could accept an unlisted
brand. Scenario (b) is the regression guard that keeps it that way: a future refactor
that introduces a default-accept (or routes an unknown `iss` to brand-X's manager)
turns (b) red.
