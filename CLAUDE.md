# docker-freeradius-ldap

Docker-deployed FreeRADIUS server with a web front end for configuration and an
LDAP / Active Directory user database backend.

## Project status

Early scaffolding — no application code yet. Architecture and stack decisions
below reflect the current plan; update this file as decisions are made or changed.

## Architecture

Three services orchestrated with Docker Compose:

1. **freeradius** — FreeRADIUS server (RADIUS auth/acct on UDP 1812/1813).
   Authenticates users against the LDAP/AD backend via the `ldap` module.
2. **web** — Web UI for managing FreeRADIUS configuration (clients/NAS
   entries, policies, LDAP connection settings) and viewing status/logs.
3. **ldap backend** — External LDAP or Active Directory server. Not
   containerized in production (points at the org's existing directory), but a
   local OpenLDAP/Samba AD container may be included for development/testing.

Configuration generated or edited by the web UI is shared with the FreeRADIUS
container (shared volume or config-reload mechanism — TBD).

## Planned repository layout

```
docker-compose.yml          # service orchestration
.env.example                # template for environment/secrets (never commit real .env)
freeradius/                 # FreeRADIUS image: Dockerfile, raddb config templates
web/                        # web front end source + Dockerfile
docs/                       # architecture notes, setup guides
```

## Conventions

- All services run via `docker compose up`; no host-installed dependencies
  beyond Docker.
- Secrets (RADIUS shared secrets, LDAP bind credentials, TLS keys) come from
  environment variables / `.env` files or Docker secrets — never hardcoded in
  config files or committed to git.
- `.env.example` documents every required variable with safe placeholder values.
- FreeRADIUS config lives in `freeradius/raddb/` as templates; container
  startup renders them from environment variables.
- TLS certificates and keys are generated locally or mounted at runtime; only
  generation scripts belong in the repo, never the certs themselves.

## Development commands

(To be filled in as the stack is built.)

```
docker compose up -d          # start the stack
docker compose logs -f        # follow logs
docker compose down           # stop
```

Testing RADIUS auth locally: `radtest <user> <pass> localhost 0 <secret>` from
the freeradius container, or `docker compose exec freeradius radtest ...`.

## Security notes

- This project handles authentication infrastructure. Treat all credential
  material as sensitive; review changes to auth flows carefully.
- LDAP bind should use a least-privilege service account, LDAPS or StartTLS
  in production.
- The web UI must require authentication before exposing any configuration.

## Open decisions

- Web front end stack (custom app vs. adapting an existing tool like daloRADIUS)
- Config hand-off mechanism between web UI and FreeRADIUS (shared volume +
  reload vs. rest_module vs. SQL-backed config)
- Whether to bundle a dev-only OpenLDAP container in compose
