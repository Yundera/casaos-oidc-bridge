# casaos-oidc-bridge

A minimal OIDC provider that fronts CasaOS's existing login API, so **Dex** (the
SSO broker) can authenticate the CasaOS user as just another OIDC connector.
Part of the Authelia→Dex migration (see `SSO-DEX-MIGRATION-PLAN.md` §4.1).

```
Dex ──OIDC connector──► casaos-oidc-bridge ──POST /v1/users/login──► CasaOS-UserService
                              │                                            │
                              └──── verifies CasaOS ES256 JWT via JWKS ◄────┘
```

## Status: SKELETON (validated 2026-06-17)

This is a proof of the end-to-end chain, **not production-hardened**. The isolated
harness (`dev/`) runs a CasaOS mock + an e2e client that plays Dex's role and
asserts the bridge issues a valid, correctly-signed `id_token`:

```bash
docker compose -f dev/docker-compose.yml up --build \
  --abort-on-container-exit --exit-code-from e2e
# expect: "E2E PASS"
```

The e2e exercises: discovery → `/authorize` → `/login` (proxied to CasaOS) →
CasaOS JWT verification via JWKS → authorization code (with `state`) → `/token`
(authorization_code + **PKCE S256**) → `id_token` signature + `iss`/`aud`/`nonce`
verification → `/userinfo`. Claims emitted: `sub`, `email`, `groups`.

## Design decision — credential proxy, not login-UI redirect (CONFIRM)

The plan's §4.1 sketch redirects the browser to CasaOS's own login UI. This
skeleton instead does what the admin app's `casaos/login.ts` already does:
serves its **own minimal login form** and POSTs the credentials to CasaOS
`/v1/users/login` **server-side**.

- **Why:** Gate 2 confirmed CasaOS login is a clean JSON API. Proxying avoids the
  redirect-chain fragility (the plan's #1 bridge UX risk: it is unproven that
  CasaOS's SPA supports redirect-back-with-token).
- **Cost:** the bridge ships its own login page instead of reusing CasaOS's.

**Open for ratification** — if reusing the CasaOS login page is a hard
requirement, the flow changes and the redirect-back contract must be validated
against the real CasaOS UI first.

## Identity mapping (Gate 2)

- The bridge POSTs login, then **verifies the returned `access_token`** (ES256)
  against CasaOS's JWKS as proof CasaOS issued it.
- Identity claims come from the login response `data.user`: `sub`=username,
  `email`, `groups`=`[role]`. Every CasaOS user is `role: "admin"` today, so
  `groups` is effectively `["admin"]` — build the path, not the policy.
- **JWKS is fetched dynamically with cache + refresh-on-failure** because CasaOS
  rotates its signing keypair on every restart. Never pin a static key.

## Not done yet (hardening backlog → §7.2 security review)

- ✅ **Persist the bridge's own signing key** — done: loaded from / written to
  `BRIDGE_KEY_PATH` (default `/data/signing-key.json`); falls back to an
  in-memory key with a warning if the path is unwritable. Mount a volume at the
  key dir in deployment. (Deliberate rotation is still a TODO.)
- Evaluate **building on `zitadel/oidc`** instead of the hand-rolled provider
  here, to avoid owning security-critical OIDC plumbing (A-vs-hand-roll decision).
- TTL eviction / persistence for the in-memory auth-request + code store.
- Wire against the **real** `CasaOS-UserService` (confirm the literal
  `jwt.JWKSPath`, real access-token claim shape, in-cluster vs public JWKS URL).
- Browser-reachable route + TLS, request logging, rate limiting, refresh tokens,
  `at_hash`/`c_hash`, full discovery metadata, error redirects per OIDC spec.

## Config (env)

| Var | Default | Meaning |
|---|---|---|
| `BRIDGE_ISSUER` | `http://localhost:8089` | Issuer; must equal the externally-reachable URL |
| `BRIDGE_ADDR` | `:8089` | Listen address |
| `CASAOS_LOGIN_URL` | `http://casaos-mock:8080/v1/users/login` | CasaOS login API |
| `CASAOS_JWKS_URL` | `http://casaos-mock:8080/.well-known/jwks.json` | CasaOS JWKS |
| `CLIENT_ID` / `CLIENT_SECRET` | `dex` / `dex-secret` | The single downstream client (Dex) |
| `REDIRECT_URIS` | `http://localhost:9000/callback` | Comma-separated allowed redirect URIs |

## Layout

```
main.go        config, key init, HTTP wiring
oidc.go        OIDC endpoints (discovery/authorize/login/token/jwks/userinfo) + PKCE
casaos.go      CasaOS login client + ES256 JWT verification via cached JWKS
store.go       in-memory auth-request + one-time-code store
Dockerfile     distroless static build
dev/           isolated harness: casaos-mock + e2e (plays Dex) + docker-compose
```
