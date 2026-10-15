# 002 - POST /bff/register is an authenticated surface (kept closed)

Status: decided 2026-10-15 by the operator on their decisions page (option B of the
two options issue #29 offered). The operator's answer carried no written reason; the
reasoning below is taken from the code, not from a recorded statement.

## Context

user-bff serves `POST /bff/register` (email-provider registration) and, in its
own code, treats it as a `permitAll` mutating surface gated on an email
allow-list. Through this gateway an anonymous caller never reaches it: the
coarse `anyExchange().authenticated()` floor in `SecurityConfig` answers 401
because `/bff/register` is not in `PUBLIC_PATHS`, and the fe-gateway route-access
seed carries `/bff/register/**` as `ROLE_USER`, so the second layer would deny
it as well.

## Decision

`POST /bff/register` and everything under `/bff/register/**` (for example
`/bff/register/complete`, `/bff/register/google`, `/bff/register/discord`) are
**cookie-authenticated** surfaces. They stay out of `PUBLIC_PATHS` and the
route-access seed rows stay `ROLE_USER`. No gateway behaviour changes.

## Why

The reason, from the code: user-bff's register
endpoint mints a session for an allow-listed email without any proof that the
caller owns that address. Opening it to anonymous callers would let anyone who
knows an invited address obtain a session for it. (That behaviour lives in
hugmesh-user-bff-api's `SsoAuthController.register`; it is the stated premise
of the decision and is not tested in this repo.)

## The guard

The decision is held in place by tests in this repo, which go red if the
surface is opened in either layer:

- `GatewayRouteAccessServiceTest.canonicalSeed_feGateway_nativeLoginSurfacesAreAnonymous`
  asserts anonymous `DENY` for `/bff/register/start` (the original guard).
- `GatewayRouteAccessServiceTest.bffRegister_isAnAuthenticatedSurface_exactAndSubtree_inBothSeeds`
  pins anonymous `DENY` and `ROLE_USER` `ALLOW` for the exact path
  `/bff/register` as well as those subtree paths, in both the baked `CanonicalSeed`
  and `compose/route-access-seed.sql`, and fails if either seed carries a
  `PUBLIC` row under `/bff/register`.
- `SecurityConfigPathGateSliceTest.anonymous_deniedOn_bffRegister_exactAndSubtree`
  pins the coarse floor: anonymous `POST` and `GET` on `/bff/register`,
  `/bff/register/start`, `/complete`, `/google` and `/discord` are 401, which fails if
  any of them is added to `PUBLIC_PATHS`.

## Reopening

Making registration anonymous is a different decision. It needs a proof of
email ownership step in user-bff first, then, in this repo, an exact-path
`PUBLIC_PATHS` entry plus a `PUBLIC` row in `CanonicalSeed` and
`compose/route-access-seed.sql`, with the three tests above changed in the same
PR.
