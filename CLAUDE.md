# docker-freeradius-ldap

Docker-deployed FreeRADIUS server with an LDAP / Active Directory user
database backend. A web front end for configuration is planned but not built
yet.

## Hard constraints

- **No build step.** `docker compose up -d` must be the entire deployment.
  Official upstream images only; project config is bind-mounted over the
  image's stock raddb. Do not introduce Dockerfiles for the core stack.
- **All site-specific config comes from `.env`.** FreeRADIUS configs use
  native `$ENV{VAR}` expansion (parsed at startup). Never hardcode
  credentials, hosts, or filters in raddb files; add a variable to
  `.env.example` instead and document it there.
- Secrets live only in `.env` (git- and claude-ignored). `.env.example`
  carries safe placeholders and is the single source of documentation for
  every variable.

## Architecture

- `freeradius` service: official `freeradius/freeradius-server:3.2.7-alpine`
  image, UDP 1812/1813, logs to stdout (`radiusd -f -l stdout`). Alpine
  variant is required: its libldap links OpenSSL like FreeRADIUS itself,
  while the Ubuntu image mixes GnuTLS/OpenSSL (rlm_ldap warns of TLS
  instability/crashes).
- Mounted config (repo `freeradius/raddb/` → container `/etc/raddb/`):
  - `clients.conf` — NAS clients, `$ENV`-driven
  - `mods-enabled/ldap` — rlm_ldap; user+group lookup, bind-as-user auth;
    `pool.start = 0` so the server starts even if LDAP is down
  - `sites-available/default` and `inner-tunnel` — replace stock sites
    (stock `sites-enabled/` symlinks point there, so mounting over
    sites-available is sufficient). PAP → `Auth-Type ldap` (bind-as-user);
    EAP handled via inner-tunnel; optional group gate via
    `RADIUS_REQUIRED_GROUP` (empty = allow all directory users).
- `openldap` service behind compose profile `dev`: osixia/openldap:1.5.0
  seeded from `dev/ldif/01-seed.ldif` (testuser/testpassword in
  `radius-users`; nogroup/nogrouppass in no group). Production points
  `LDAP_SERVER` at a real directory instead.

## Gotchas / domain notes

- **AD + MSCHAPv2 (PEAP) does not work** via plain LDAP — AD never exposes
  password hashes. PAP/EAP-TTLS-PAP (bind-as-user) is the supported AD path;
  MSCHAPv2 against AD would require Samba/winbind + ntlm_auth (roadmap).
- The ldap module's `update` section caches `userPassword` when readable
  (dev OpenLDAP), which is what makes CHAP/MSCHAP work in dev only.
- `$ENV{...}` is expanded when the config file is parsed. Unlang conditions
  can't reliably contain `$ENV`, so env values used in conditions are first
  copied into `&control:Tmp-String-9` via `update` (see the group check in
  both sites).
- **Line endings matter**: raddb/LDIF/compose files must stay LF —
  `.gitattributes` enforces this. CRLF breaks parsing inside the containers.
- `chase_referrals = yes` + `rebind = yes` in the ldap module are required
  for multi-DC Active Directory.
- Compose fails fast if `.env` is missing (`env_file` is required) — that's
  intentional, it forces `cp .env.example .env`.

## Commands

```sh
docker compose --profile dev up -d      # stack + throwaway dev LDAP
docker compose up -d                    # production (external directory)
docker compose logs -f freeradius
docker compose exec freeradius radtest testuser testpassword localhost 0 testing123
docker compose run --rm freeradius radiusd -X    # debug mode (stop the service first)
docker compose up -d --force-recreate freeradius # apply .env changes
```

## Testing changes

There is no test suite; verification is behavioral. After any raddb change:
`radiusd -XC` inside the container checks config syntax
(`docker compose run --rm freeradius radiusd -XC`), then run the radtest
matrix against the dev profile: testuser accepts, wrong password rejects,
and with `RADIUS_REQUIRED_GROUP=radius-users` the `nogroup` user rejects.

> Note (2026-07-15): the dev machine this repo was scaffolded on had no
> Docker/WSL, so the initial config has been reviewed but not yet executed.
> First person to run it: expect possible small unlang/module-name fixes;
> use `radiusd -XC` output to iterate.

## Conventions

- Keep raddb files minimal and commented — they replace stock files, so
  anything not listed falls back to image defaults (all other mods-enabled,
  policies, dictionaries).
- Config style follows stock FreeRADIUS 3.2 raddb (tabs, `&attribute`
  references in unlang).
- Decision log: `.claude/memory/decisions.md`. Open roadmap: README.

## Roadmap (agreed)

- Web front end container for RADIUS client/policy management (mechanism for
  handing config to FreeRADIUS still undecided)
- ntlm_auth/winbind option for PEAP-MSCHAPv2 against AD
- EAP TLS certificate management (currently image snakeoil certs)
