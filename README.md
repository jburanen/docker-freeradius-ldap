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
- **Logs** shows two live, auto-refreshing tails: the radiusd output (the
  same stream as `docker compose logs freeradius`, including rlm_ldap
  directory messages) — handy for watching Access-Accept/Reject results
  while testing rules — and the panel's own LDAP log (service binds, panel
  logins, applies). Both files live on a shared volume, each capped at
  `RADIUS_LOG_MAX_MB` (default 10 MB, one previous generation kept).
- The panel speaks plain HTTP; put a TLS reverse proxy in front of it for
  production.

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
| RADIUS clients | `RADIUS_CLIENT_IP`, `RADIUS_CLIENT_SECRET` |
| Access policy | `RADIUS_REQUIRED_GROUP` |
| Admin panel | `ADMIN_GROUP`, `ADMIN_SESSION_SECRET`, `RADIUS_LOG_MAX_MB` |
| Directory connection | `LDAP_SERVER`, `LDAP_START_TLS`, `LDAP_TLS_REQUIRE_CERT`, `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD`, `LDAP_BASE_DN` |
| User lookup | `LDAP_USER_BASE_DN`, `LDAP_USER_OBJECT_FILTER`, `LDAP_USER_NAME_ATTRIBUTE` |
| Group lookup | `LDAP_GROUP_BASE_DN`, `LDAP_GROUP_OBJECT_FILTER`, `LDAP_GROUP_MEMBERSHIP_FILTER`, `LDAP_GROUP_MEMBERSHIP_ATTRIBUTE` |

After changing `.env`, apply with `docker compose up -d --force-recreate freeradius`.

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
