# docker-freeradius-ldap

A Docker-deployed [FreeRADIUS](https://freeradius.org/) server backed by an
LDAP or Active Directory user database. No image builds required — `docker
compose up -d` runs the official FreeRADIUS image with configuration driven
entirely by environment variables in `.env`.

A web front end for day-to-day configuration is planned; today all settings
live in `.env`.

## Quick start

```sh
cp .env.example .env        # then edit .env for your environment

# Option A: test drive with the bundled dev LDAP (seeded test users)
docker compose --profile dev up -d

# Option B: production — point .env at your AD/LDAP server
docker compose up -d
```

Test authentication (dev profile defaults):

```sh
docker compose exec freeradius radtest testuser testpassword localhost 0 testing123
```

Expect `Access-Accept`. From another machine, point `radtest`/your NAS at UDP
1812 with the shared secret from `RADIUS_CLIENT_SECRET`.

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
- **openldap** (started only with `--profile dev`) is a throwaway directory
  seeded from [dev/ldif/01-seed.ldif](dev/ldif/01-seed.ldif) with two test
  accounts: `testuser`/`testpassword` (member of `radius-users`) and
  `nogroup`/`nogrouppass` (no groups).

## Configuration

Every setting is documented inline in [.env.example](.env.example), including
Active Directory example values for each section (server URI, bind DN, user
filter with `sAMAccountName`, `memberOf` group membership).

| Area | Variables |
|------|-----------|
| RADIUS clients | `RADIUS_CLIENT_IP`, `RADIUS_CLIENT_SECRET` |
| Access policy | `RADIUS_REQUIRED_GROUP` |
| Directory connection | `LDAP_SERVER`, `LDAP_START_TLS`, `LDAP_TLS_REQUIRE_CERT`, `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD`, `LDAP_BASE_DN` |
| User lookup | `LDAP_USER_BASE_DN`, `LDAP_USER_OBJECT_FILTER`, `LDAP_USER_NAME_ATTRIBUTE` |
| Group lookup | `LDAP_GROUP_BASE_DN`, `LDAP_GROUP_OBJECT_FILTER`, `LDAP_GROUP_MEMBERSHIP_FILTER`, `LDAP_GROUP_MEMBERSHIP_ATTRIBUTE` |

After changing `.env`, apply with `docker compose up -d --force-recreate freeradius`.

## Authentication methods

| Method | Works against | Notes |
|--------|--------------|-------|
| PAP (incl. EAP-TTLS/PAP) | AD and any LDAP | Bind-as-user; recommended for AD |
| CHAP / MSCHAPv2 (incl. PEAP) | Directories that expose a readable password | Works with the dev OpenLDAP; **not** plain AD — AD needs Samba/winbind + `ntlm_auth` (not included yet) |

## Troubleshooting

```sh
docker compose logs -f freeradius     # server log (stdout)
docker compose stop freeradius
docker compose run --rm freeradius radiusd -X   # full debug mode, foreground
```

## Repository layout

```
docker-compose.yml            # the whole stack; dev LDAP behind --profile dev
.env.example                  # all settings, documented (copy to .env)
freeradius/raddb/             # config mounted over the image defaults
  clients.conf                #   NAS clients ($ENV-driven)
  mods-enabled/ldap           #   LDAP module ($ENV-driven)
  sites-available/default     #   outer virtual server
  sites-available/inner-tunnel#   EAP inner tunnel
dev/ldif/                     # seed data for the dev LDAP
CLAUDE.md                     # project context for AI-assisted development
```

## Security

- `.env` holds all secrets and is git-ignored; only `.env.example` (safe
  placeholders) is committed.
- Restrict `RADIUS_CLIENT_IP` to your NAS subnet in production.
- Use `ldaps://` or `LDAP_START_TLS=yes` plus a least-privilege bind account
  against production directories.

## Roadmap

- Web front end for RADIUS client/policy management
- `ntlm_auth` option for PEAP/MSCHAPv2 against Active Directory
- TLS certificate management for EAP

## License

TBD
