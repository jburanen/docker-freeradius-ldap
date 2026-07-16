# docker-freeradius-ldap

A Docker-deployed [FreeRADIUS](https://freeradius.org/) server backed by an
LDAP or Active Directory user database, with a web admin panel for managing
custom RADIUS reply attributes (Cisco IOS, Check Point Gaia, Brocade ICX
presets included). `docker compose up -d` is the entire deployment — the
FreeRADIUS service runs the unmodified official image configured through
`.env`, and Compose builds the small admin panel image automatically on
first run.

## Quick start

```sh
cp .env.example .env        # point it at your AD/LDAP and set secrets
docker compose up -d
```

Test authentication with a directory account:

```sh
docker compose exec freeradius radtest <username> <password> localhost 0 <RADIUS_CLIENT_SECRET>
```

Expect `Access-Accept`. From another machine, point `radtest`/your NAS at UDP
1812 with the shared secret from `RADIUS_CLIENT_SECRET`.

Then open the admin panel at `http://<host>:8080` (port from `ADMIN_PORT`)
and log in with directory credentials — access requires membership in the
group named by `ADMIN_GROUP`.

## Admin panel

The `radius-admin` service manages **attribute rules**: each rule maps an
LDAP/AD group (optionally restricted to a single NAS IP) to a list of RADIUS
reply attributes. Typical use: members of `netadmins` get
`Cisco-AVPair = "shell:priv-lvl=15"` on Cisco switches, `CP-Gaia-User-Role =
adminRole` on Check Point Gaia, `Foundry-Privilege-Level = 0` on Brocade ICX —
all available as one-click presets, plus free-form attributes from any
dictionary FreeRADIUS loads.

- **Login** uses the same `LDAP_*` settings as RADIUS auth (bind-as-user).
  Access requires membership in the group named by `ADMIN_GROUP`.
- **Apply & reload** renders the rules into a FreeRADIUS `users` file on a
  shared volume and sends radiusd a SIGHUP. The reload is transactional: if
  the new file fails to parse, FreeRADIUS keeps the previous rules.
- Saving a rule never touches the running server until you press Apply; the
  dashboard shows a "pending changes" badge and a live preview of the
  generated file.

![screencap of the rule management page](images/rules.png)

![screencap of the rule addition page](images/newrule.png)

- **Logs** shows two live, auto-refreshing tails: the raw radiusd output
  (the same stream as `docker compose logs freeradius`, including rlm_ldap
  directory messages), and an **LDAP / auth** log with one line per RADIUS
  authentication result — Access-Accept/Reject with the failure detail,
  which in this stack means the LDAP bind outcome — interleaved with the
  panel's own logins, binds, and rule applies. Both files live on a shared
  volume, each capped at `RADIUS_LOG_MAX_MB` (default 10 MB, one previous
  generation kept).

![screencap of the logs page](images/logs.png)

- The panel speaks plain HTTP; put a TLS reverse proxy in front of it for
  production.

## Clustering (redundant deployments)

Deploy the stack on two or more hosts and join them into a cluster: log in
to **any** instance's panel and apply the ruleset to all of them — or
multi-select which instances receive it — in one click.

1. In each instance's `.env`, set the **same** `CLUSTER_SECRET`, a friendly
   `CLUSTER_NODE_NAME`, and `CLUSTER_NODE_URL` (that panel's address as the
   other instances reach it), then `docker compose up -d --build radius-admin`.
2. On the new instance's **Cluster** page, register the URL of any existing
   member (or vice versa). Registration is mutual and the member list is
   shared, so one action joins the full mesh.
3. The dashboard's Apply box then lists every instance with checkboxes
   (all selected by default).

![screencap of the cluster status page](images/cluster.png)

Notes: instance-to-instance calls are HMAC-signed with `CLUSTER_SECRET`
(the secret is never transmitted; clocks must agree within 5 minutes).
Rules are pushed as a full replacement — the last apply wins. Each instance
still authenticates panel logins against its own LDAP settings, and the
Cluster page shows reachability, version, and whether each member's rules
match the instance you're looking at.

If a targeted instance is **offline during an apply**, the apply is queued
on the instance you used and retried every 60 seconds until the member is
back — it catches up automatically. Every apply carries a timestamp, so a
queued (older) delivery is discarded if a newer apply already reached the
member directly. Queued deliveries are shown on the Cluster page, where
they can also be cancelled. The queue lives on the originating instance:
if that instance is itself down, delivery resumes when it returns.

## How it works

- **freeradius** runs the official `freeradius/freeradius-server` image.
  Project config files are bind-mounted over the stock ones; FreeRADIUS's
  native `$ENV{...}` expansion pulls every site-specific value (LDAP server,
  bind credentials, filters, shared secret) from the container environment,
  which Compose loads from `.env`. Nothing is baked into an image.
- **Users** are looked up in LDAP/AD; plaintext (PAP) requests authenticate by
  binding to the directory as the user — the standard approach for Active
  Directory, which never exposes password hashes.
- **Groups**: set `RADIUS_REQUIRED_GROUP` in `.env` to restrict access to
  members of one LDAP/AD group; leave it empty to allow any directory user.

## Configuration

Every setting is documented inline in [.env.example](.env.example), including
Active Directory example values for each section (server URI, bind DN, user
filter with `sAMAccountName`, `memberOf` group membership).

| Area | Variables |
|------|-----------|
| Ports | `RADIUS_AUTH_PORT`, `RADIUS_ACCT_PORT`, `ADMIN_PORT` |
| Server image | `FREERADIUS_IMAGE` (optional override) |
| RADIUS clients | `RADIUS_CLIENT_IP`, `RADIUS_CLIENT_SECRET` |
| Access policy | `RADIUS_REQUIRED_GROUP` |
| Admin panel | `ADMIN_GROUP`, `ADMIN_SESSION_SECRET`, `RADIUS_LOG_MAX_MB` |
| Cluster | `CLUSTER_SECRET`, `CLUSTER_NODE_NAME`, `CLUSTER_NODE_URL` |
| Directory connection | `LDAP_SERVER`, `LDAP_START_TLS`, `LDAP_TLS_REQUIRE_CERT`, `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD`, `LDAP_BASE_DN` |
| User lookup | `LDAP_USER_BASE_DN`, `LDAP_USER_OBJECT_FILTER`, `LDAP_USER_NAME_ATTRIBUTE` |
| Group lookup | `LDAP_GROUP_BASE_DN`, `LDAP_GROUP_OBJECT_FILTER`, `LDAP_GROUP_MEMBERSHIP_FILTER`, `LDAP_GROUP_MEMBERSHIP_ATTRIBUTE` |

After changing `.env`, apply with `docker compose up -d --force-recreate freeradius`.

### Upgrading

New versions can introduce new `.env` variables. After a `git pull`, merge
them into your existing `.env` without touching your customizations:

```sh
./merge-env.sh
```

It appends any variable that `.env.example` has and your `.env` lacks
(backing `.env` up to `.env.bak` first), prints exactly what it added, and
never modifies existing lines — run it as often as you like. Review the
added values (each is documented in `.env.example`; some are placeholders
like `CLUSTER_NODE_NAME`), then `docker compose up -d --build --force-recreate`.
Optional variables that ship commented out (e.g. `FREERADIUS_IMAGE`) are
not copied — enable those by hand.

## Authentication methods

| Method | Works against | Notes |
|--------|--------------|-------|
| PAP (incl. EAP-TTLS/PAP) | AD and any LDAP | Bind-as-user; recommended for AD |
| CHAP / MSCHAPv2 (incl. PEAP) | Directories that expose a readable password | **Not** plain AD — AD needs Samba/winbind + `ntlm_auth` (not included yet) |

## Troubleshooting

```sh
docker compose logs -f freeradius     # server log (stdout)
docker compose stop freeradius
docker compose run --rm freeradius radiusd -X   # full debug mode, foreground
```

## Repository layout

```
docker-compose.yml            # the whole stack
.env.example                  # all settings, documented (copy to .env)
merge-env.sh                  # after git pull: append new vars to your .env
freeradius/raddb/             # config mounted over the image defaults
  clients.conf                #   NAS clients ($ENV-driven)
  mods-enabled/ldap           #   LDAP module ($ENV-driven)
  sites-available/default     #   outer virtual server
  sites-available/inner-tunnel#   EAP inner tunnel
web/                          # radius-admin panel (Flask; compose builds it)
CLAUDE.md                     # project context for AI-assisted development
```

## Security

- `.env` holds all secrets and is git-ignored; only `.env.example` (safe
  placeholders) is committed.
- Restrict `RADIUS_CLIENT_IP` to your NAS subnet in production.
- Use `ldaps://` or `LDAP_START_TLS=yes` plus a least-privilege bind account
  against production directories.

## Roadmap

- `ntlm_auth` option for PEAP/MSCHAPv2 against Active Directory
- TLS certificate management for EAP
- Manage NAS clients and the group gate from the admin panel

## License

TBD
