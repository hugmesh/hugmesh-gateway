# Multi-issuer security-slice — the reusable test pattern

This is the reference pattern for proving that a Spring WebFlux OAuth2 resource
server handles **per-brand (multi-issuer) Casdoor tokens** correctly. Two properties
matter most. An **unknown issuer fails CLOSED (401)**. A token from one brand can
**never authenticate as another**.

It was built first in `hugmesh-gateway`. Each of these
[HugMesh](https://github.com/hugmesh) resource-server repos now has its own copy of
`TestIssuer`, `SecuritySliceSupport` and `MultiIssuerSecuritySliceTest`
(`hugmesh-mod-bff-api` also has `Wave2` variants of the first two):

> [`hugmesh-actions`](https://github.com/hugmesh/hugmesh-actions),
> [`hugmesh-character-forge-bff-api`](https://github.com/hugmesh/hugmesh-character-forge-bff-api),
> [`hugmesh-admin-bff-api`](https://github.com/hugmesh/hugmesh-admin-bff-api),
> [`hugmesh-mod-bff-api`](https://github.com/hugmesh/hugmesh-mod-bff-api),
> [`hugmesh-forum-bff-api`](https://github.com/hugmesh/hugmesh-forum-bff-api),
> [`hugmesh-wiki-bff-api`](https://github.com/hugmesh/hugmesh-wiki-bff-api),
> [`hugmesh-owncast-bff-api`](https://github.com/hugmesh/hugmesh-owncast-bff-api),
> [`hugmesh-tube-bff-api`](https://github.com/hugmesh/hugmesh-tube-bff-api),
> [`hugmesh-user-bff-api`](https://github.com/hugmesh/hugmesh-user-bff-api),
> [`hugmesh-federation-api`](https://github.com/hugmesh/hugmesh-federation-api).

Use the same pattern in any new resource-server repo.

The tests need **no network and no live Casdoor**. A small in-process HTTP server
bound to `127.0.0.1` serves each brand's JWKS and OIDC discovery document, so
`ReactiveJwtDecoders.fromIssuerLocation(...)` validates real RSA-signed tokens
offline.

---

## What the slice asserts (the three keystones)

| # | Scenario | Expectation | Category |
|---|----------|-------------|----------|
| (a) | A brand-X-issuer JWT | resolves to brand-X's manager → **authenticated**, and the `DOMAIN_brandx` authority is emitted | USER-SITUATIONAL |
| (b) | A token from an issuer **not** in `app.tenancy.issuers` (well-formed, correctly signed, just unlisted) | the per-issuer resolver returns `Mono.empty()` → **401 fail-closed**, never a default-accept | CROSS-USER DENY |
| (c) | A brand-Y JWT presented to the resource server | scoped to brand-Y; can **never** become brand-X (no `DOMAIN_brandx`) | CROSS-USER DENY |

Two cheap neighbours also fail closed: a **tampered signature** and a **garbage
bearer** both give 401.

---

## The two reusable seams

### 1. `TestIssuer` — mint issuer-specific JWTs against test JWKs (no network)

`src/test/java/.../testsupport/TestIssuer.java`. Each instance:

- generates a fresh RSA keypair;
- starts a JDK `HttpServer` on `127.0.0.1:<random-port>` serving
  `/.well-known/openid-configuration` (issuer + `jwks_uri`) and
  `/.well-known/jwks.json` (the public JWK set);
- exposes `issuerUri()` (the left side of an `app.tenancy.issuers` pair) and
  `mint(subject, roleNames)` / `mintWithClaims(subject, claims)` /
  `mintExpired(subject, roleNames)`.

A token minted by issuer A is valid **only** against issuer A's manager. That is the
cross-brand isolation of scenario (c). `TestIssuer` is `AutoCloseable`; stop it in
`@AfterEach`.

Its only dependency is `nimbus-jose-jwt`, which every resource server already gets
through `spring-boot-starter-oauth2-resource-server`. Copy the file as it is.

### 2. `SecuritySliceSupport` — build the REAL `SecurityWebFilterChain` into a `WebTestClient`

`src/test/java/.../config/SecuritySliceSupport.java`. It builds the repo's real
`SecurityConfig.filterChain(ServerHttpSecurity.http())`, wraps it in a
`WebFilterChainProxy`, and installs it as a `webFilter` on
`WebTestClient.bindToController(...)`. **No full Spring Boot context.** The
production `authorizeExchange` policy and OAuth2 resource-server wiring run as
deployed, in a fast slice.

Helpers: `provider(resolver)` takes the multi-issuer swap; `absent()` takes the
single-issuer `o.jwt(...)` path.

---

## How to replicate in another repo (checklist)

1. **Copy** `TestIssuer.java` into that repo's `testsupport` package, unchanged.
2. **Copy** `SecuritySliceSupport.java` and point it at *that* repo's `SecurityConfig`
   constructor and `filterChain` signature. If the constructor takes different
   arguments (for example, no `DomainRegistry`), adjust `sliceClient`.
3. **Write** `MultiIssuerSecuritySliceTest`:
   - `@BeforeEach`: start `brandX`, `brandY`, and a `rogue` (untrusted) `TestIssuer`;
   - build `DomainRegistry(brandX.issuerUri(), "<x>=brandx,<y>=brandy", "")` and assert
     `isMultiIssuer()`;
   - build the repo's multi-issuer resolver the way its tenancy config contributes it
     (`new TenancyResourceServerConfig(registry, "", "").tenantAuthManagerResolver()`);
   - `client = sliceClient(registry, provider(resolver), new AuthoritiesController())`;
   - add an `AuthoritiesController` (`GET /whoami`) that echoes the
     `ReactiveSecurityContextHolder` authorities;
   - assert (a) `DOMAIN_brandx` + `ROLE_*`, (b) rogue → `isUnauthorized()`,
     (c) brand-Y → `DOMAIN_brandy` and NOT `DOMAIN_brandx`, plus tampered/garbage → 401.
4. **Optionally** add a coarse path-gate slice (see `SecurityConfigPathGateSliceTest`
   here) for that repo's own `authorizeExchange` rules. The plumbing is the same;
   only the path/role table changes.

> A repo without multi-issuer (`TenancyResourceServerConfig`) wiring can still copy the
> path-gate slice (the single-issuer `absent()` path with one `TestIssuer`), so its
> `authorizeExchange` policy is at least covered. Add the multi-issuer slice when the
> wiring arrives.

---

## Why fail-closed is the load-bearing assertion

The per-issuer resolver's allowlist is exactly `DomainRegistry.trustedIssuers()`. An
`iss` outside that set gets **no** authentication manager, so
`JwtIssuerReactiveAuthenticationManagerResolver` returns 401 **before any authority is
emitted**. No fallback "default" manager exists that could accept an unlisted brand.
Scenario (b) keeps it that way: a refactor that adds a default-accept, or routes an
unknown `iss` to brand-X's manager, turns (b) red.
