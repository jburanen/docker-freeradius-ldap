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
- **Most site-specific config comes from `.env`.** FreeRADIUS configs use
  native `$ENV{VAR}` expansion (parsed at startup). Never hardcode
  credentials, hosts, or filters in raddb files; add a variable to
  `.env.example` instead and document it there. Exception: RADIUS **clients**
  (NAS devices) are managed in the panel's Clients tab and rendered into
  `clients.conf` on a shared volume, not driven by `.env`.
- Secrets live only in `.env` (git- and claude-ignored). `.env.example`
  carries safe placeholders and is the single source of documentation for
  every variable.

## Architecture

- `freeradius` service: official `freeradius/freeradius-server:3.2.7-alpine`
  image (overridable via `FREERADIUS_IMAGE`; the default is duplicated in
  radius-admin's environment for the footer fallback — keep in sync),
  UDP 1812/1813. PID 1 is a small `sh` supervisor loop (in the compose
  `command`) that keeps radiusd running and relaunches it on exit; radiusd's
  stdout is mirrored to `/logs/radius.log` on the `radius-logs` volume via a
  fifo + `tee`. The supervisor (not `exec radiusd`) is PID 1 so the shared
  PID namespace survives a radiusd restart — that is how the panel applies
  client changes (SIGHUP can't reload clients) without taking radius-admin
  down. A `trap` forwards SIGTERM so `docker stop` stays clean.
  Alpine variant is required: its libldap links OpenSSL like FreeRADIUS itself,
  while the Ubuntu image mixes GnuTLS/OpenSSL (rlm_ldap warns of TLS
  instability/crashes).
- Mounted config (repo `freeradius/raddb/` → container `/etc/raddb/`):
  - `clients.conf` — thin stub; `$-INCLUDE clients-generated/clients.conf`
    (optional include) pulls the panel-generated client list from the
    `radius-clients` volume (mounted at `/etc/raddb/clients-generated`)
  - `mods-enabled/ldap` — rlm_ldap; user+group lookup, bind-as-user auth;
    `pool.start = 0` so the server starts even if LDAP is down
  - `mods-enabled/linelog-authlog` — two linelog instances appending one
    line per final auth result to `/logs/auth.log`; called from the outer
    site's post-auth / Post-Auth-Type REJECT (outer only, or EAP would
    double-log)
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
  (`pid: "container:freeradius"`). A **Clients** tab manages RADIUS clients
  (clients.json in admin-data → `clients.conf` on the `radius-clients`
  volume); its Apply rewrites the file and **restarts** radiusd (SIGTERM the
  radiusd child → supervisor relaunches; SIGHUP does NOT reload clients),
  keeping a `.prev` backup and rolling back automatically if the new file
  fails to load (a crash-looping radiusd never stays up ~2s, which is the
  failure signal). Default client is seeded on first run. Login = LDAP
  bind-as-user with the same
  `LDAP_*` env vars, gated by `ADMIN_GROUP` membership (memberOf first, then
  member/uniqueMember/memberUid group search). A tabbed "Logs" page tails
  `/logs/radius.log` (raw radiusd, incl. rlm_ldap) and `/logs/auth.log`
  (per-request auth results from linelog, `radius:` prefix, interleaved
  with the panel's own LDAP logins/binds/applies via a root-logger
  FileHandler, `radius-admin:` prefix) from the `radius-logs` volume —
  3 s auto-refresh, clear button, copytruncate rotation at
  `RADIUS_LOG_MAX_MB` (default 10) each. Clustering (optional, enabled by a
  shared `CLUSTER_SECRET`): peers registered by URL on the Cluster page
  (mutual registration + one-hop list propagation = full mesh from one
  action; peers.json in admin-data), Apply box multi-selects target
  instances, remote applies POST the full ruleset to
  `/api/cluster/{status,register,peers,apply}` — JSON signed with
  HMAC-SHA256 over "ts.body" (±5 min window, CSRF-exempt, stdlib urllib
  with proxies disabled), receiver validates/saves rules, rewrites
  authorize, HUPs its own radiusd. Applies to unreachable members queue in
  pending.json on the origin (newest per peer) and a daemon thread retries
  every 60 s; every apply carries config_ts so receivers 409 stale queued
  deliveries superseded by a newer direct apply. A login-gated footer shows
  `ADMIN_VERSION` and the running FreeRADIUS version, found by regex-scanning
  the radiusd binary / libfreeradius-server.so through `/proc/<pid>` in the
  shared PID namespace (cached per radiusd pid; the compiled-in version
  literal is the only live source — radiusd logs it only under -v/-X and
  the .so filenames are unversioned). Falls back to the `FREERADIUS_IMAGE`
  tag. Vendor presets: Cisco
  (Cisco-AVPair shell:priv-lvl), Check Point Gaia (CP-Gaia-User-Role,
  CP-Gaia-SuperUser-Access), Brocade ICX (Foundry-Privilege-Level) — all in
  dictionaries FreeRADIUS 3.2 loads by default (verified against v3.2.x
  share/dictionary on GitHub). A **Clients** tab manages RADIUS clients
  (name, IP/CIDR, secret, proto, nas_type, per-client
  require_message_authenticator / limit_proxy_state, free-form extra
  directives) → clients.json → `clients.conf`; Apply restarts radiusd with
  rollback.

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
- **SIGHUP does NOT reload clients** (verified against v3.2.x
  `main_config_hup()`: it reloads only modules, virtual servers, and log
  files). Client changes need a radiusd restart — hence the PID-1 supervisor
  and the panel's SIGTERM-the-child restart. Rule/users-file changes still
  use SIGHUP (transactional).
- A bad `clients.conf` makes radiusd fail to start → the supervisor
  crash-loops it (throttled 1/s). `apply_clients` detects this (no radiusd
  stays up ~2s within a 20 s window) and rolls back to `clients.conf.prev`,
  so a typo can't leave auth down. radius-admin stays up throughout because
  the supervisor (PID 1) never dies — the admin can still fix it in the panel.
- BlastRADIUS (CVE-2024-3596): `require_message_authenticator` /
  `limit_proxy_state` are now **per-client** fields in the Clients tab
  (default yes / auto on the seeded client). Per-client granularity means a
  patched NAS can require it without forcing every device, unlike the old
  single catch-all `$ENV`-driven block.
- Compose fails fast if `.env` is missing (`env_file` is required) — that's
  intentional, it forces `cp .env.example .env`.
- Timestamps are stored/exchanged as ISO-8601 UTC (state.json, pending.json,
  cluster API) and only converted for display by the `|localtime` Jinja
  filter. Both containers mount `/etc/localtime:ro` from the (Linux) host so
  rendered stamps and log lines follow the host timezone.
- Cluster sync is deliberately last-apply-wins full replacement of
  rules.json — no merging, no conflict detection. Concurrent edits on two
  panels are resolved by whichever admin applies last. Peer removal is
  local-only (each instance owns its peers.json).
- tee holds an O_APPEND fd on `/logs/radius.log` and the panel's FileHandler
  one on `/logs/auth.log`, so radius-admin must rotate and clear them with
  in-place `os.truncate` — never `os.replace`, which would leave the writer
  appending to an orphaned inode (linelog reopens auth.log per message and
  tolerates either). The volume mounts at `/logs`, deliberately not
  `/var/log/radius`, so radacct detail files stay out of it.
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
- The `radius-clients` volume starts empty, so on the very first `up`
  freeradius comes up with **zero clients** (the `$-INCLUDE` finds nothing
  and rejects everything); radius-admin's startup seeds the default client,
  writes `clients.conf`, and restarts radiusd once to load it. This is why
  the stub uses `$-INCLUDE` (optional) not `$INCLUDE` — otherwise radiusd
  would refuse to start on first boot. Subsequent boots read the persisted
  `clients.conf` directly, no restart.

## Commands

```sh
docker compose up -d                    # deploy / apply compose changes
./merge-env.sh                          # after git pull: append new .env vars
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
- Bump `ADMIN_VERSION` in `web/app/app.py` (shown in the footer) whenever
  the panel's behavior changes.
- Decision log: `.claude/memory/decisions.md`. Open roadmap: README.

## Roadmap (agreed)

- ntlm_auth/winbind option for PEAP-MSCHAPv2 against AD
- EAP TLS certificate management (currently image snakeoil certs)
- Manage the RADIUS_REQUIRED_GROUP gate from the admin panel (NAS clients
  are now managed there via the Clients tab)
- Sync clients (not just rules) across the cluster — currently the Clients
  tab is per-instance; cluster Apply only pushes attribute rules
