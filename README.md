# docker-freeradius-ldap

A Docker-deployed [FreeRADIUS](https://freeradius.org/) server with a web front
end for configuration, backed by an LDAP or Active Directory user database.

> **Status:** early development — scaffolding only, no runnable stack yet.

## What this will provide

- **FreeRADIUS** container handling RADIUS authentication and accounting
  (UDP 1812/1813), authenticating users against your directory
- **Web UI** container for managing RADIUS clients (NAS devices), policies,
  and LDAP connection settings without hand-editing raddb files
- **LDAP/AD integration** with your existing directory — an optional local
  OpenLDAP container will be available for development and testing

## Planned quick start

```sh
cp .env.example .env    # fill in LDAP bind credentials, RADIUS secrets
docker compose up -d
```

Then open the web UI, register your first NAS client, and test with:

```sh
docker compose exec freeradius radtest <username> <password> localhost 0 <shared-secret>
```

## Requirements

- Docker with the Compose plugin
- An LDAP or Active Directory server reachable from the Docker host
  (or use the bundled dev directory once available)

## Repository layout

```
docker-compose.yml    # service orchestration (planned)
freeradius/           # FreeRADIUS image and config templates (planned)
web/                  # web front end (planned)
docs/                 # architecture and setup docs (planned)
CLAUDE.md             # project context for AI-assisted development
```

## Security

Secrets (LDAP bind credentials, RADIUS shared secrets, TLS keys) are supplied
via `.env` / Docker secrets and are never committed to this repository. See
`.gitignore` and the conventions section of `CLAUDE.md`.

## License

TBD
