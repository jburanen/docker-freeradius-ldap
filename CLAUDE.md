# docker-freeradius-ldap

Docker-deployed FreeRADIUS server with an LDAP / Active Directory user
database backend, plus a web admin panel (`radius-admin`) for managing
custom RADIUS reply attributes.

## Hard constraints

- **`docker compose up -d` must be the entire deployment.** The freeradius
  service stays on the unmodified official image with config bind-mounted —
  never add a Dockerfile for it. The web panel is the one exception: compose
  builds `web/Dockerfile` automatically on first `up`; no manual build
  commands may ever be required.
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
- `radius-admin` service (`web/`): Flask + ldap3 + waitress on python alpine,
  built by compose. Manages "attribute rules" (LDAP group [+ optional NAS
  IP] → RADIUS reply attributes) stored in the `admin-data` volume as
  rules.json, rendered as a FreeRADIUS users file into the `radius-policy`
  volume, which freeradius mounts at `/opt/etc/raddb/mods-config/files`
  (read by the stock `files` module; both sites call `files` in authorize).
  Apply = rewrite file + SIGHUP radiusd via shared PID namespace
  (`pid: "container:freeradius"`). Login = LDAP bind-as-user with the same
  `LDAP_*` env vars, gated by `ADMIN_GROUP` membership (memberOf first, then
  member/uniqueMember/memberUid group search). Vendor presets: Cisco
  (Cisco-AVPair shell:priv-lvl), Check Point Gaia (CP-Gaia-User-Role,
  CP-Gaia-SuperUser-Access), Brocade ICX (Foundry-Privilege-Level) — all in
  dictionaries FreeRADIUS 3.2 loads by default (verified against v3.2.x
  share/dictionary on GitHub).

## Gotchas / domain notes

- **AD + MSCHAPv2 (PEAP) does not work** via plain LDAP — AD never exposes
  password hashes. PAP/EAP-TTLS-PAP (bind-as-user) is the supported AD path;
  MSCHAPv2 against AD would require Samba/winbind + ntlm_auth (roadmap).
- The ldap module's `update` section caches `userPassword` when the bind
  account can read it — that's what makes CHAP/MSCHAP possible on
  directories that expose passwords (never AD).
- `$ENV{...}` is expanded when the config file is parsed. Unlang conditions
  can't reliably contain `$ENV`, so env values used in conditions are first
  copied into `&control:Tmp-String-9` via `update` (see the group check in
  both sites).
- The startup warning `Please change "%{control:Tmp-String-9}" to
  &control:Tmp-String-9` in the Ldap-Group condition is a **false positive —
  do not apply it**. Ldap-Group is a virtual comparison attribute; an
  &attribute reference on the RHS is a fatal parse error ("Cannot use
  attribute reference on right side of condition"). Verified 2026-07-15.
- **Line endings matter**: raddb/LDIF/compose files must stay LF —
  `.gitattributes` enforces this. CRLF breaks parsing inside the containers.
- `chase_referrals = yes` + `rebind = yes` in the ldap module are required
  for multi-DC Active Directory.
- BlastRADIUS (CVE-2024-3596): clients.conf sets
  `require_message_authenticator` / `limit_proxy_state` from env
  (`RADIUS_REQUIRE_MESSAGE_AUTHENTICATOR` default yes). Because there is one
  catch-all client block, "auto" would let a single patched NAS upgrade the
  requirement for all devices — that's why the default is explicit.
- Compose fails fast if `.env` is missing (`env_file` is required) — that's
  intentional, it forces `cp .env.example .env`.
- SIGHUP reload of rlm_files is transactional: a users file that fails to
  parse leaves the previously loaded rules active, so a bad Apply can't take
  auth down. radius-admin overwrites the generated `authorize` on its own
  startup (from rules.json) but only HUPs on explicit Apply.
- If the freeradius container is recreated, radius-admin must be recreated
  too (its PID namespace ref breaks); `docker compose up -d` handles this
  via depends_on.
- The `radius-policy` named volume prepopulates from the image's stock
  mods-config/files on first create — freeradius must be created before
  radius-admin (depends_on guarantees it), or rlm_files would see an empty
  dir and fail.

## Commands

```sh
docker compose up -d                    # deploy / apply compose changes
docker compose logs -f freeradius
docker compose logs -f radius-admin
docker compose exec freeradius radtest <user> <pass> localhost 0 <secret>
docker compose run --rm freeradius radiusd -X    # debug mode (stop the service first)
docker compose up -d --force-recreate freeradius # apply .env changes
docker compose up -d --build radius-admin        # after changing web/
```

## Testing changes

There is no test suite; verification is behavioral, against a real
LDAP/AD directory (there is no bundled dev directory — removed 2026-07-15).
After any raddb change: `radiusd -XC` inside the container checks config
syntax (`docker compose run --rm freeradius radiusd -XC`), then radtest a
known directory account: valid password accepts, wrong password rejects,
and with `RADIUS_REQUIRED_GROUP` set a non-member rejects.

> Note (2026-07-15): the Windows machine this repo is developed on has no
> Docker/WSL; changes ship reviewed but unexecuted and are verified on the
> deployment host. Expect to iterate from `radiusd -XC` / container logs.

## Conventions

- Keep raddb files minimal and commented — they replace stock files, so
  anything not listed falls back to image defaults (all other mods-enabled,
  policies, dictionaries).
- Config style follows stock FreeRADIUS 3.2 raddb (tabs, `&attribute`
  references in unlang).
- Decision log: `.claude/memory/decisions.md`. Open roadmap: README.

## Roadmap (agreed)

- ntlm_auth/winbind option for PEAP-MSCHAPv2 against AD
- EAP TLS certificate management (currently image snakeoil certs)
- Manage NAS clients and the RADIUS_REQUIRED_GROUP gate from the admin panel
