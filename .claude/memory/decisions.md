# Architecture decision log

Record decisions here as they're made so future sessions (and humans) have the
context. Newest first. Keep entries short: what was decided, why, what was
rejected.

## Template

```
## YYYY-MM-DD — Decision title
**Decided:** ...
**Why:** ...
**Rejected alternatives:** ...
```

## 2026-07-15 — No-build deployment via $ENV{} config expansion
**Decided:** Use the official `freeradius/freeradius-server:3.2.7` image with
project raddb files bind-mounted over the stock ones. All site-specific values
come from `.env` via FreeRADIUS's native `$ENV{...}` parse-time expansion.
**Why:** User requirement: `docker compose up -d` with zero build steps.
`$ENV{}` avoids both custom images and entrypoint templating (envsubst).
**Rejected alternatives:** Custom Dockerfile (build step), envsubst entrypoint
script (extra moving part, ordering issues with the image's own entrypoint).

## 2026-07-15 — Bind-as-user (Auth-Type ldap) as the primary auth path
**Decided:** PAP requests authenticate by binding to the directory as the
user. MSCHAPv2/PEAP only works where the directory exposes a readable
password (dev OpenLDAP), not plain AD.
**Why:** Works identically for AD and generic LDAP with no extra services.
**Rejected alternatives:** Samba/winbind + ntlm_auth for AD MSCHAPv2 —
deferred to roadmap; it needs a domain join, which breaks the
zero-configuration compose story.

## 2026-07-15 — Dev LDAP behind a compose profile
**Decided:** `osixia/openldap:1.5.0` seeded with test users, started only via
`docker compose --profile dev up -d`.
**Why:** Default `up -d` should run exactly the production shape (external
directory); the dev directory is opt-in.
**Rejected alternatives:** Bitnami OpenLDAP (image distribution moved to
bitnamilegacy in 2025, uncertain availability); always-on dev LDAP service.
