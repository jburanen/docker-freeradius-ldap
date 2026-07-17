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

## 2026-07-17 — RADIUS clients managed in the panel; radiusd restart via PID-1 supervisor
**Decided:** Clients move out of `$ENV`-driven clients.conf into the panel's
Clients tab (clients.json in admin-data → rendered clients.conf on the new
`radius-clients` volume, `$-INCLUDE`d by a thin bind-mounted stub). The four
RADIUS_CLIENT_* env vars are removed; their old values seed a default client
on first run. Applying clients rewrites the file and RESTARTS radiusd, because
SIGHUP does not reload clients (verified against v3.2.x `main_config_hup()` —
only modules/virtual-servers/logfiles reload). To restart radiusd without
docker.sock and without dropping radius-admin, the freeradius container's
PID 1 is now a shell supervisor loop; radius-admin SIGTERMs the radiusd child
and the supervisor relaunches it. apply_clients keeps a `.prev` and rolls
back if the new file crash-loops radiusd (detected: no radiusd stays up ~2s
in a 20s window). Because the supervisor (PID 1) never dies, the shared PID
namespace and radius-admin survive, so a bad clients.conf is recoverable from
the panel.
**Why:** User wanted granular per-client config in the UI. Restart is
unavoidable for clients; the supervisor makes it safe (namespace-preserving)
and rollback-able.
**Rejected alternatives:** killing radiusd-as-PID-1 to force a container
restart (breaks radius-admin's shared PID namespace → both crash-loop on a
bad file, locking the admin out of the fix); docker.sock to `restart`
freeradius (security, already rejected for the rules feature); FreeRADIUS
dynamic clients (runtime lookup from SQL/file — heavier, changes auth flow);
leaving clients in `.env` (not the requested granular UI control).
**Scope note:** Clients are per-instance; cluster Apply still syncs only
attribute rules. Cross-cluster client sync is on the roadmap.

## 2026-07-16 — Clustering: HMAC-signed peer API, full-ruleset push, mesh via one-hop merge
**Decided:** Multiple deployments cluster through radius-admin itself. Peers
live in /data/peers.json (name+URL). Server-to-server calls are JSON POSTs
signed HMAC-SHA256 over "unix_ts.body" with a shared CLUSTER_SECRET (never
transmitted; ±5 min window; endpoints 404 when the secret is unset and are
CSRF-exempt). Apply multi-selects targets; remote targets get the FULL
ruleset (validated structurally, then save + render + HUP on the receiver)
— last apply wins, no merging. Registration is mutual (register endpoint
adds the caller and returns its own list) plus a one-hop /api/cluster/peers
push of the merged list to all members, so registering one member joins the
mesh. Peer removal is local-only. HTTP client is stdlib urllib with
ProxyHandler({}) so http_proxy env never hijacks peer calls. Node identity
from CLUSTER_NODE_NAME/CLUSTER_NODE_URL in .env.
**Why:** No new services or deps; works with the existing per-instance
LDAP login; "log in anywhere, apply everywhere" with per-instance
multi-select was the requirement.
**Rejected alternatives:** shared database / config replication daemon
(new service, conflicts with compose-only constraint); rsync/scp of
rules.json (no HUP, no auth); making one node a master (defeats redundancy
— any panel must be usable when others are down); bearer-token auth
(secret would cross plain HTTP).
**Amended same day — offline members catch up:** applies that can't reach a
targeted member queue in /data/pending.json on the ORIGIN (newest ruleset
per peer wins) and a daemon thread retries every 60 s. Chosen over
pull-on-startup by the returning member because only the origin knows the
apply's intent — a later apply that deliberately excluded that member must
NOT reach it. Ordering: every apply carries config_ts (wall clock, NTP
assumed — same trust as the HMAC window); receivers 409 anything older than
their current config_ts, and the origin drops queued entries on 400/409.
Limitation (documented): if the origin is down too, delivery waits for the
origin's return.

## 2026-07-16 — Footer FreeRADIUS version probed via /proc/<pid>/root
**Decided:** The panel footer shows `ADMIN_VERSION` (constant in app.py,
bump on panel changes) and the running FreeRADIUS version, read through the
already-shared PID namespace (same-uid access, both containers run root):
regex-scan `/proc/<pid>/exe` and `/proc/<pid>/root/opt/lib/
libfreeradius-server*.so` for the compiled-in "FreeRADIUS Version x.y.z"
literal, cached per radiusd pid (failed probes retried at most 1/min).
Last resort: parse the `FREERADIUS_IMAGE` tag, interpolated in compose for
the freeradius image and passed to radius-admin (defaults duplicated in
compose — keep in sync). Versions render only when logged in.
**Why the binary scan (learned 2026-07-16, first attempt shipped broken):**
the image's .so filenames are UNVERSIONED (no `-3.2.7.so` suffix), and
radiusd logs its version banner only under -v/-X, never in normal mode —
verified against v3.2.x radiusd.c and the alpine Dockerfile (prefix /opt,
no USER directive). So filename-glob and log-banner probes can never work.
**Rejected alternatives:** Status-Server query (needs a RADIUS client lib +
secret); mounting docker.sock (security).

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
