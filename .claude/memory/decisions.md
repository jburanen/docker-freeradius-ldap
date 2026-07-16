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

## 2026-07-16 — Admin panel log viewer via fifo + tee onto a shared volume
**Decided:** radiusd keeps logging to stdout, but the compose command routes
it through a fifo into `tee -a /logs/radius.log` (named volume `radius-logs`,
mounted rw in radius-admin). `exec` keeps radiusd as PID 1 for docker-stop
signals. The panel's `/logs` page tails the last 64 KB with 3 s polling;
rotation is copytruncate at `RADIUS_LOG_MAX_MB` (default 10, one `.1`
generation) because tee holds an O_APPEND fd — never replace the inode.
Volume mounts at `/logs`, not `/var/log/radius`, to keep radacct out of it.
**Why:** No docker.sock in a web-facing container, no custom image, and
`docker compose logs -f freeradius` still works unchanged.
**Rejected alternatives:** docker.sock + logs API (root-equivalent exposure);
`-l /path/file` only (loses docker logs); reading radiusd's stdout fd via the
shared PID namespace (would steal data from the docker log driver).
**Amended same day (twice):** the page is now tabbed. Second tab is
`/logs/auth.log`, shared by two writers: FreeRADIUS linelog instances
(mods-enabled/linelog-authlog, called from the outer post-auth /
Post-Auth-Type REJECT — outer only, or EAP double-logs) emitting one
`radius:` line per final Access-Accept/Reject incl. Module-Failure-Message,
and radius-admin's root-logger FileHandler (`radius-admin:` lines for panel
logins/binds/applies). Chosen over `log { auth = yes }` because that needs
mounting/maintaining the whole stock radiusd.conf and lands in the wrong
stream anyway. Both writers append, so in-place truncate rules apply.

## 2026-07-15 — Custom attributes via rlm_files users file + SIGHUP
**Decided:** The admin panel renders attribute rules (LDAP group → reply
attributes) into a FreeRADIUS users file on a shared named volume
(`radius-policy`); Apply sends SIGHUP to radiusd through a shared PID
namespace (`pid: "container:freeradius"`). rlm_files HUP reload is
transactional — parse failure keeps old rules.
**Why:** Uses only stock FreeRADIUS mechanisms (files module is enabled by
default), no SQL backend, no docker.sock exposure, no custom freeradius image.
**Rejected alternatives:** SQL module + DB (heavy, new service);
mounting docker.sock into web container to restart freeradius (security);
rest_module (needs FreeRADIUS 4 features / more moving parts).

## 2026-07-15 — Admin panel is compose-built Flask (exception to no-build)
**Decided:** `web/` is a small Flask+ldap3+waitress app on python:3.12-alpine,
built automatically by `docker compose up -d` (`build: ./web`). The
"no build" hard constraint is narrowed to: no *manual* build steps, and the
freeradius service itself stays on the unmodified official image.
**Why:** LDAP client + web framework need dependencies; pip-install-at-startup
is fragile (network dependency on every recreate, unpinned drift).
**Rejected alternatives:** stdlib-only Python (would mean hand-writing an
LDAP BER client); pip at container startup; publishing a prebuilt image
(possible later; adds registry/release overhead now).

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

## 2026-07-15 — Dev LDAP container removed (supersedes earlier decision)
**Decided:** Dropped the bundled dev OpenLDAP (`--profile dev`, osixia image,
seed LDIF) entirely, same day it was added. All testing happens against a
real LDAP/AD directory.
**Why:** Jason asked to remove it — testing is done against real
infrastructure, and the extra container/profile/seed data was dead weight.
**Note:** RADIUS_REQUIRED_GROUP / ADMIN_GROUP defaults in .env.example
(`radius-users` / `radius-admins`) are now just suggested group names.
