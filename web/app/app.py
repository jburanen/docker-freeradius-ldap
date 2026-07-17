"""radius-admin: web panel for managing custom RADIUS reply attributes.

Rules map an LDAP/AD group (plus optional NAS IP) to a list of RADIUS reply
attributes. They are stored in /data/rules.json and rendered into a FreeRADIUS
users file at /radius-files/authorize (a volume shared with the freeradius
container). "Apply" rewrites the file and sends SIGHUP to radiusd, which
re-reads it transactionally -- a file that fails to parse leaves the old
rules active.

Login uses the same LDAP settings as RADIUS itself (bind-as-user), gated by
membership in the ADMIN_GROUP group.
"""

import glob
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from functools import wraps

from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)
from ldap3 import NONE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("radius-admin")

# Shown in the footer; bump when the panel changes.
ADMIN_VERSION = "1.6.2"


def env(name, default=None, required=False):
    value = os.environ.get(name, default)
    if required and not value:
        raise RuntimeError(f"required environment variable {name} is not set")
    return value


LDAP_SERVER = env("LDAP_SERVER", required=True)
LDAP_START_TLS = env("LDAP_START_TLS", "no").strip().lower() in ("yes", "true", "1", "on")
LDAP_TLS_REQUIRE_CERT = env("LDAP_TLS_REQUIRE_CERT", "allow").strip().lower()
LDAP_BIND_DN = env("LDAP_BIND_DN", required=True)
LDAP_BIND_PASSWORD = env("LDAP_BIND_PASSWORD", required=True)
LDAP_USER_BASE_DN = env("LDAP_USER_BASE_DN", required=True)
LDAP_USER_OBJECT_FILTER = env("LDAP_USER_OBJECT_FILTER", "(objectClass=person)")
LDAP_USER_NAME_ATTRIBUTE = env("LDAP_USER_NAME_ATTRIBUTE", "uid")
LDAP_GROUP_BASE_DN = env("LDAP_GROUP_BASE_DN", required=True)
LDAP_GROUP_OBJECT_FILTER = env("LDAP_GROUP_OBJECT_FILTER", "(objectClass=groupOfNames)")
ADMIN_GROUP = env("ADMIN_GROUP", required=True)

DATA_DIR = env("ADMIN_DATA_DIR", "/data")
RADIUS_FILES_DIR = env("RADIUS_FILES_DIR", "/radius-files")
RADIUS_CLIENTS_DIR = env("RADIUS_CLIENTS_DIR", "/radius-clients")
RULES_PATH = os.path.join(DATA_DIR, "rules.json")
STATE_PATH = os.path.join(DATA_DIR, "state.json")
PEERS_PATH = os.path.join(DATA_DIR, "peers.json")
PENDING_PATH = os.path.join(DATA_DIR, "pending.json")
CLIENTS_PATH = os.path.join(DATA_DIR, "clients.json")
CLIENTS_STATE_PATH = os.path.join(DATA_DIR, "clients_state.json")
AUTHORIZE_PATH = os.path.join(RADIUS_FILES_DIR, "authorize")
# Generated client list on the shared radius-clients volume; freeradius
# $-INCLUDEs it (see freeradius/raddb/clients.conf).
CLIENTS_CONF_PATH = os.path.join(RADIUS_CLIENTS_DIR, "clients.conf")

# Cluster: several deployments of this stack can be registered with each
# other and applied to together. All instances must share CLUSTER_SECRET
# (empty disables clustering and its API); CLUSTER_NODE_URL is how the
# other panels reach this one.
CLUSTER_SECRET = env("CLUSTER_SECRET", "")
CLUSTER_NODE_NAME = env("CLUSTER_NODE_NAME", "") or socket.gethostname()
CLUSTER_NODE_URL = (env("CLUSTER_NODE_URL", "") or "").strip().rstrip("/")
CLUSTER_TIMEOUT = 6
# Applying clients restarts radiusd on the receiver (with rollback), which
# can take tens of seconds -- well past CLUSTER_TIMEOUT -- so peer client
# applies use their own generous timeout.
CLIENTS_APPLY_TIMEOUT = 60
PENDING_RETRY_SECONDS = 60

# Cluster-synced config kinds: which peer endpoint delivers each, and the
# JSON key its payload travels under. Drives both direct applies and the
# offline-catch-up retry loop.
SYNC_KINDS = {
    "rules": {"endpoint": "/api/cluster/apply", "key": "rules"},
    "clients": {"endpoint": "/api/cluster/apply-clients", "key": "clients"},
}

# Log files shown on the Logs page, both on the shared radius-logs volume:
# radius.log is tee'd from the freeradius container's stdout (see
# docker-compose.yml, includes rlm_ldap messages); auth.log collects every
# RADIUS authentication result (written by FreeRADIUS's linelog module, see
# mods-enabled/linelog-authlog) plus this app's own logging (LDAP binds,
# panel logins, applies) via the handler below.
LOG_DIR = env("RADIUS_LOG_DIR", "/logs")
LOG_FILES = {
    "freeradius": {"label": "FreeRADIUS Daemon", "path": os.path.join(LOG_DIR, "radius.log")},
    "auth": {"label": "Authentication", "path": os.path.join(LOG_DIR, "auth.log")},
}
RADIUS_LOG_MAX_MB = int(env("RADIUS_LOG_MAX_MB", "10"))
LOG_TAIL_BYTES = 64 * 1024

try:
    # Append mode (O_APPEND), so in-place truncation by rotate/clear is safe.
    _file_handler = logging.FileHandler(LOG_FILES["auth"]["path"])
    _file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s radius-admin: %(message)s"))
    logging.getLogger().addHandler(_file_handler)
except OSError as _exc:
    log.warning("cannot open %s: %s -- auth log page will be incomplete",
                LOG_FILES["auth"]["path"], _exc)

ATTR_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
UNQUOTED_VALUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
OPERATORS = ("=", ":=", "+=")

# --- Client profiles, managed by the Clients tab ---
# A profile is a named parameter set (secret, proto, options, ...) plus one or
# more CIDRs. Each CIDR is rendered as its own FreeRADIUS client{} block, all
# sharing the profile name as their shortname.
CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
NAS_TYPE_RE = re.compile(r"^[A-Za-z0-9_-]+$")
# Each free-form extra line must be `directive = value`; no braces (which
# would break out of the client{} block) or line breaks.
CLIENT_EXTRA_RE = re.compile(r"^[A-Za-z0-9_]+\s*=\s*[^{}\r\n]+$")
TRISTATE = ("yes", "no", "auto")
CLIENT_PROTOS = ("udp", "tcp", "*")

# Out-of-box profile: the same values the four removed RADIUS_CLIENT_* env
# vars used to seed. Written on first run; editable in the panel afterwards.
def default_clients():
    return [{
        "id": uuid.uuid4().hex[:12],
        "name": "default",
        "cidrs": ["0.0.0.0/0"],
        "secret": "testing123",
        "proto": "udp",
        "nas_type": "other",
        "require_message_authenticator": "yes",
        "limit_proxy_state": "auto",
        "extra": "",
        "enabled": True,
    }]

# Presets are inserted client-side into the rule form; attribute names come
# from dictionaries FreeRADIUS 3.2 loads by default (cisco, checkpoint,
# foundry).
PRESETS = {
    "cisco-admin": {
        "label": "Cisco IOS — admin (priv 15)",
        "attributes": [["Cisco-AVPair", "+=", "shell:priv-lvl=15"]],
    },
    "cisco-readonly": {
        "label": "Cisco IOS — read-only (priv 1)",
        "attributes": [["Cisco-AVPair", "+=", "shell:priv-lvl=1"]],
    },
    "gaia-admin": {
        "label": "Check Point Gaia — adminRole (superuser)",
        "attributes": [
            ["CP-Gaia-User-Role", "=", "adminRole"],
            ["CP-Gaia-SuperUser-Access", "=", "1"],
        ],
    },
    "gaia-monitor": {
        "label": "Check Point Gaia — monitorRole (read-only)",
        "attributes": [["CP-Gaia-User-Role", "=", "monitorRole"]],
    },
    "icx-admin": {
        "label": "Brocade ICX — super-user (level 0)",
        "attributes": [["Foundry-Privilege-Level", "=", "0"]],
    },
    "icx-readonly": {
        "label": "Brocade ICX — read-only (level 5)",
        "attributes": [["Foundry-Privilege-Level", "=", "5"]],
    },
}

app = Flask(__name__)
app.secret_key = env("ADMIN_SESSION_SECRET") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

def atomic_write(path, content):
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    os.replace(tmp, path)


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def load_rules():
    return load_json(RULES_PATH, {"rules": []})["rules"]


def save_rules(rules):
    atomic_write(RULES_PATH, json.dumps({"rules": rules}, indent=2))


def load_state():
    return load_json(STATE_PATH, {})


def save_state(state):
    atomic_write(STATE_PATH, json.dumps(state, indent=2))


def _migrate_profile(p):
    """Upgrade a legacy single-`ipaddr` client (<= 1.3) to a `cidrs` profile."""
    if isinstance(p, dict) and "cidrs" not in p and "ipaddr" in p:
        p = dict(p)
        p["cidrs"] = [p.pop("ipaddr")]
    return p


def load_clients():
    return [_migrate_profile(p)
            for p in load_json(CLIENTS_PATH, {"clients": []})["clients"]]


def save_clients(clients):
    atomic_write(CLIENTS_PATH, json.dumps({"clients": clients}, indent=2))


def load_clients_state():
    return load_json(CLIENTS_STATE_PATH, {})


def save_clients_state(state):
    atomic_write(CLIENTS_STATE_PATH, json.dumps(state, indent=2))


# ---------------------------------------------------------------------------
# users-file rendering
# ---------------------------------------------------------------------------

def render_users_value(value):
    if UNQUOTED_VALUE_RE.fullmatch(value):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def render_users_file(rules):
    lines = [
        "# Generated by radius-admin -- DO NOT EDIT, changes are overwritten.",
        f"# Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        "",
    ]
    for rule in rules:
        if not rule.get("enabled", True) or not rule["attributes"]:
            continue
        group = rule["ldap_group"].replace("\\", "\\\\").replace('"', '\\"')
        checks = [f'Ldap-Group == "{group}"']
        if rule.get("nas_profile"):
            # A profile groups one or more CIDRs that all share the profile
            # name as their client shortname; the sites copy %{client:shortname}
            # into &request:Tmp-String-8 before calling files, so matching the
            # name here scopes the rule to every NAS in the profile.
            prof = rule["nas_profile"].replace("\\", "\\\\").replace('"', '\\"')
            checks.append(f'Tmp-String-8 == "{prof}"')
        elif rule.get("nas_ip"):
            checks.append(f"NAS-IP-Address == {rule['nas_ip']}")
        lines.append(f"# rule: {rule['name']}")
        lines.append("DEFAULT\t" + ", ".join(checks))
        for a in rule["attributes"]:
            lines.append(f"\t{a['attr']} {a['op']} {render_users_value(a['value'])},")
        lines.append("\tFall-Through = Yes")
        lines.append("")
    return "\n".join(lines) + "\n"


def rendered_hash(rules):
    # Hash only the rule content, not the timestamp header, so an unchanged
    # ruleset never shows as pending.
    body = json.dumps(
        [r for r in rules if r.get("enabled", True)], sort_keys=True
    )
    return hashlib.sha256(body.encode()).hexdigest()


def write_authorize(rules):
    atomic_write(AUTHORIZE_PATH, render_users_file(rules))


# ---------------------------------------------------------------------------
# clients.conf rendering (profile -> one client{} block per CIDR)
# ---------------------------------------------------------------------------

def _quote_secret(value):
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def profile_cidrs(profile):
    return [c for c in profile.get("cidrs", []) if str(c).strip()]


def render_profile_blocks(profile):
    """One FreeRADIUS client{} block per CIDR. Block names must be unique, so
    multi-CIDR profiles get a numeric suffix; all blocks share the profile
    name as their shortname so logs identify the profile, not the CIDR."""
    cidrs = profile_cidrs(profile)
    name = profile["name"]
    blocks = []
    for i, cidr in enumerate(cidrs):
        block_name = name if len(cidrs) == 1 else f"{name}-{i + 1}"
        # In FreeRADIUS 3.2 `ipaddr` accepts IPv4, IPv6, and CIDR for both.
        lines = [f'client {block_name} {{']
        lines.append(f'\tipaddr = {cidr}')
        if block_name != name:
            lines.append(f'\tshortname = {name}')
        lines.append(f'\tproto = {profile.get("proto", "udp")}')
        lines.append(f'\tsecret = {_quote_secret(profile["secret"])}')
        if profile.get("nas_type"):
            lines.append(f'\tnas_type = {profile["nas_type"]}')
        lines.append("\trequire_message_authenticator = "
                     f'{profile.get("require_message_authenticator", "yes")}')
        lines.append(f'\tlimit_proxy_state = {profile.get("limit_proxy_state", "auto")}')
        for extra in profile.get("extra", "").splitlines():
            if extra.strip():
                lines.append(f"\t{extra.strip()}")
        lines.append("}")
        blocks.append("\n".join(lines))
    return blocks


def render_clients_conf(clients):
    lines = [
        "# Generated by radius-admin -- DO NOT EDIT, changes are overwritten.",
        f"# Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        "",
    ]
    for profile in clients:
        if not profile.get("enabled", True) or not profile_cidrs(profile):
            continue
        lines.append(f"# profile: {profile['name']}")
        for block in render_profile_blocks(profile):
            lines.append(block)
        lines.append("")
    return "\n".join(lines) + "\n"


def clients_hash(clients):
    # Hash enabled clients' content (not the timestamp header) so an unchanged
    # set never shows as pending.
    body = json.dumps(
        [{k: v for k, v in c.items() if k != "id"}
         for c in clients if c.get("enabled", True)],
        sort_keys=True,
    )
    return hashlib.sha256(body.encode()).hexdigest()


def write_clients_conf(clients):
    atomic_write(CLIENTS_CONF_PATH, render_clients_conf(clients))


def clients_pending(clients):
    return load_clients_state().get("applied_hash") != clients_hash(clients)


# ---------------------------------------------------------------------------
# FreeRADIUS reload (shared PID namespace with the freeradius container)
# ---------------------------------------------------------------------------

def find_radiusd_pid():
    pids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/comm", encoding="utf-8") as f:
                if f.read().strip() == "radiusd":
                    pids.append(int(entry))
        except OSError:
            continue
    return min(pids) if pids else None


def reload_freeradius():
    pid = find_radiusd_pid()
    if pid is None:
        return False, "radiusd process not found -- is the freeradius container running?"
    try:
        os.kill(pid, signal.SIGHUP)
    except OSError as exc:
        return False, f"failed to signal radiusd (pid {pid}): {exc}"
    return True, f"sent HUP to radiusd (pid {pid})"


# --- radiusd restart, for client changes (SIGHUP cannot reload clients) ---
# The freeradius container's PID 1 is a supervisor loop (docker-compose.yml):
# SIGTERM'ing the radiusd child makes it relaunch, re-reading clients.conf.
# A crash-looping radiusd (bad clients.conf) never stays up for 2s, which is
# how we detect failure and roll back.

def _await_radiusd_up(old_pid, timeout=20):
    """Wait for a radiusd that differs from old_pid and stays up >= ~2s."""
    deadline = time.monotonic() + timeout
    prev = None
    while time.monotonic() < deadline:
        time.sleep(2)
        pid = find_radiusd_pid()
        if pid and pid != old_pid and pid == prev:
            return True, f"radiusd restarted (pid {pid})"
        prev = pid
    return False, "radiusd did not stay up after restart -- check the FreeRADIUS log"


def _signal_restart():
    """SIGTERM the current radiusd so the supervisor relaunches it. Returns
    the pid signalled (or None if radiusd is not running yet)."""
    pid = find_radiusd_pid()
    if pid is not None:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    return pid


def apply_clients(clients, applied_by, config_ts=None):
    """Render clients.conf, restart radiusd, and roll back to the previous
    file if the new one fails to load -- a bad clients.conf must never leave
    authentication down. config_ts orders applies across the cluster.
    Returns (ok, message)."""
    backup = CLIENTS_CONF_PATH + ".prev"
    had_backup = os.path.exists(CLIENTS_CONF_PATH)
    if had_backup:
        try:
            shutil.copyfile(CLIENTS_CONF_PATH, backup)
        except OSError:
            had_backup = False
    write_clients_conf(clients)

    ok, message = _await_radiusd_up(_signal_restart())
    if not ok and had_backup:
        log.error("clients apply left radiusd down; rolling back to %s", backup)
        try:
            shutil.copyfile(backup, CLIENTS_CONF_PATH)
        except OSError as exc:
            message += f"; ROLLBACK FAILED ({exc}) -- fix clients.conf by hand"
            save_clients_state({
                "applied_hash": None,
                "applied_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "applied_by": applied_by,
                "result": message,
                "config_ts": config_ts or time.time(),
            })
            return False, message
        rb_ok, rb_msg = _await_radiusd_up(_signal_restart())
        message = ("new clients.conf failed to load, rolled back to the "
                   f"previous clients ({rb_msg})")

    save_clients_state({
        "applied_hash": clients_hash(clients) if ok else None,
        "applied_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "applied_by": applied_by,
        "result": message,
        "config_ts": config_ts or time.time(),
    })
    return ok, message


# The full version string ("FreeRADIUS Version 3.2.7, for host ...") is a
# compile-time literal in radiusd / libfreeradius-server.so. radiusd never
# logs it outside -v/-X, and the installed .so filenames are unversioned,
# so reading the binaries is the only live source (verified against
# v3.2.x radiusd.c and the official image Dockerfile, 2026-07-16).
FR_VERSION_RE = re.compile(rb"FreeRADIUS Version (\d+\.\d+[0-9A-Za-z.]*)")
FREERADIUS_IMAGE = env("FREERADIUS_IMAGE", "")
_fr_version_cache = {"pid": None, "version": None, "checked": 0.0}


def _probe_freeradius_version(pid):
    # Both containers run uid 0 in the shared PID namespace, which makes
    # /proc/<pid>/root and /proc/<pid>/exe readable (LSM policy permitting).
    candidates = [f"/proc/{pid}/exe"]
    for libdir in ("opt/lib", "opt/lib/freeradius", "usr/lib", "usr/lib/freeradius"):
        candidates += glob.glob(f"/proc/{pid}/root/{libdir}/libfreeradius-server*.so")
    for path in candidates:
        try:
            with open(path, "rb") as f:
                m = FR_VERSION_RE.search(f.read())
        except OSError:
            continue
        if m:
            return m.group(1).decode()
    return None


def image_tag_version():
    # freeradius/freeradius-server:3.2.7-alpine -> "3.2.7"
    m = re.search(r":(\d+\.\d+[0-9A-Za-z.]*)", FREERADIUS_IMAGE)
    return m.group(1) if m else None


def freeradius_version():
    """Version of the running radiusd, else the configured image tag.

    Probe results are cached per radiusd pid; failures are retried at most
    once a minute so page loads stay cheap.
    """
    pid = find_radiusd_pid()
    now = time.monotonic()
    if pid is not None:
        cache = _fr_version_cache
        if cache["pid"] == pid and (cache["version"] or now - cache["checked"] < 60):
            version = cache["version"]
        else:
            version = _probe_freeradius_version(pid)
            if version is None and cache["pid"] != pid:
                log.info("cannot read the radiusd binary via /proc/%d (LSM "
                         "policy?); footer shows the FREERADIUS_IMAGE tag", pid)
            cache.update(pid=pid, version=version, checked=now)
        if version:
            return version
    return image_tag_version()


# ---------------------------------------------------------------------------
# Cluster (multi-instance sync)
# ---------------------------------------------------------------------------
# Every instance runs this same app against its own freeradius. Peers are
# registered by URL; server-to-server calls are JSON POSTs signed with
# HMAC-SHA256 over "<unix ts>.<body>" so the shared secret never travels
# (5-minute freshness window). Apply pushes the full ruleset -- last apply
# wins, there is no merging.

def load_peers():
    return load_json(PEERS_PATH, {"peers": []})["peers"]


def save_peers(peers):
    atomic_write(PEERS_PATH, json.dumps({"peers": peers}, indent=2))


def normalize_url(url):
    return (url or "").strip().rstrip("/")


def merge_peers(new_entries):
    """Add unknown instances (keyed by URL, never self) to the peer list."""
    peers = load_peers()
    known = {p["url"] for p in peers} | {CLUSTER_NODE_URL}
    changed = False
    for entry in new_entries:
        url = normalize_url(entry.get("url"))
        if not url.startswith(("http://", "https://")) or url in known:
            continue
        peers.append({"name": str(entry.get("name") or url), "url": url})
        known.add(url)
        changed = True
    if changed:
        save_peers(peers)
    return peers


def cluster_sign(timestamp, body):
    return hmac.new(CLUSTER_SECRET.encode(),
                    f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()


class ClusterError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status  # HTTP status if the peer answered, else None


# Peer calls go to other instances directly, never through a proxy.
_cluster_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def cluster_call(base_url, endpoint, payload, timeout=CLUSTER_TIMEOUT):
    body = json.dumps(payload).encode()
    ts = str(int(time.time()))
    req = urllib.request.Request(
        normalize_url(base_url) + endpoint,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Cluster-Timestamp": ts,
            "X-Cluster-Signature": cluster_sign(ts, body),
        },
    )
    try:
        with _cluster_opener.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            raise ClusterError("signature refused -- do both instances share "
                               "CLUSTER_SECRET, and are their clocks in sync?",
                               status=403) from exc
        if exc.code == 404:
            raise ClusterError("no cluster API there -- is it radius-admin "
                               ">= 1.1 with CLUSTER_SECRET set?",
                               status=404) from exc
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("message", "")
        except (ValueError, OSError, AttributeError):
            detail = ""
        raise ClusterError(detail or f"HTTP {exc.code}", status=exc.code) from exc
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise ClusterError(str(getattr(exc, "reason", exc))) from exc


def cluster_api(view):
    """Auth for the server-to-server endpoints (HMAC, not the login session)."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not CLUSTER_SECRET:
            abort(404)
        ts = request.headers.get("X-Cluster-Timestamp", "")
        sig = request.headers.get("X-Cluster-Signature", "")
        if not ts.isdigit() or abs(time.time() - int(ts)) > 300:
            abort(403)
        if not hmac.compare_digest(cluster_sign(ts, request.get_data()), sig):
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def validate_rules_payload(rules):
    """Structural check of a pushed ruleset; returns an error string or None."""
    if not isinstance(rules, list):
        return "rules must be a list"
    for rule in rules:
        if not isinstance(rule, dict):
            return "rule entries must be objects"
        name = str(rule.get("name", "")).strip()
        if not name or not str(rule.get("ldap_group", "")).strip():
            return "every rule needs a name and an LDAP group"
        if rule.get("nas_ip"):
            try:
                ipaddress.ip_address(rule["nas_ip"])
            except ValueError:
                return f"invalid NAS IP in rule {name!r}"
        profile = rule.get("nas_profile")
        if profile is not None and (not isinstance(profile, str) or "\n" in profile):
            return f"invalid NAS profile in rule {name!r}"
        attrs = rule.get("attributes")
        if not isinstance(attrs, list) or not attrs:
            return f"rule {name!r} has no attributes"
        for a in attrs:
            if not isinstance(a, dict) or not ATTR_NAME_RE.fullmatch(str(a.get("attr", ""))):
                return f"invalid attribute name in rule {name!r}"
            if a.get("op") not in OPERATORS:
                return f"invalid operator in rule {name!r}"
            value = a.get("value")
            if not isinstance(value, str) or not value or "\n" in value or "\r" in value:
                return f"invalid attribute value in rule {name!r}"
        rule.setdefault("id", uuid.uuid4().hex[:12])
        rule["enabled"] = bool(rule.get("enabled", True))
    return None


def validate_clients_payload(clients):
    """Structural check of a pushed profile list; returns an error string or
    None. Mirrors validate_profile_form so a peer can't be handed a
    clients.conf that would crash-loop its radiusd."""
    if not isinstance(clients, list):
        return "clients must be a list"
    if not any(isinstance(c, dict) and c.get("enabled", True) for c in clients):
        return "at least one enabled profile is required"
    seen = set()
    for profile in clients:
        profile = _migrate_profile(profile)
        if not isinstance(profile, dict):
            return "profile entries must be objects"
        name = str(profile.get("name", ""))
        if not CLIENT_NAME_RE.fullmatch(name):
            return f"invalid profile name {name!r}"
        if name.lower() in seen:
            return f"duplicate profile name {name!r}"
        seen.add(name.lower())
        cidrs = profile.get("cidrs")
        if not isinstance(cidrs, list) or not any(str(c).strip() for c in cidrs):
            return f"profile {name!r} has no CIDRs"
        for cidr in cidrs:
            try:
                ipaddress.ip_network(str(cidr), strict=False)
            except ValueError:
                return f"invalid CIDR {cidr!r} in profile {name!r}"
        secret = profile.get("secret")
        if not isinstance(secret, str) or not secret or "\n" in secret or "\r" in secret:
            return f"invalid secret in profile {name!r}"
        if profile.get("proto", "udp") not in CLIENT_PROTOS:
            return f"invalid proto in profile {name!r}"
        if profile.get("nas_type") and not NAS_TYPE_RE.fullmatch(str(profile["nas_type"])):
            return f"invalid nas_type in profile {name!r}"
        if profile.get("require_message_authenticator", "yes") not in TRISTATE:
            return f"invalid require_message_authenticator in profile {name!r}"
        if profile.get("limit_proxy_state", "auto") not in TRISTATE:
            return f"invalid limit_proxy_state in profile {name!r}"
        for line in str(profile.get("extra", "")).splitlines():
            if line.strip() and not CLIENT_EXTRA_RE.fullmatch(line.strip()):
                return f"invalid extra directive in profile {name!r}"
        profile.setdefault("id", uuid.uuid4().hex[:12])
        profile["enabled"] = bool(profile.get("enabled", True))
    return None


def apply_rules_locally(rules, applied_by, config_ts=None):
    """Write the users file, HUP radiusd, record state. Shared by the local
    Apply path and the cluster API. config_ts is the wall-clock time of the
    originating admin action, used to order applies across the cluster."""
    write_authorize(rules)
    ok, message = reload_freeradius()
    save_state({
        "applied_hash": rendered_hash(rules) if ok else None,
        "applied_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "applied_by": applied_by,
        "result": message,
        "config_ts": config_ts or time.time(),
    })
    return ok, message


# --- Pending deliveries: applies that targeted an unreachable instance ---
# Queued on the originating instance and retried in the background until
# delivered, so a member that was down catches up automatically. Keyed by
# peer URL then kind ("rules" / "clients"), so a queued rules apply and a
# queued clients apply for the same peer are independent (newest per kind
# wins). The receiver's config_ts check drops a queued payload superseded by
# a newer apply in the meantime.

_pending_lock = threading.Lock()


def load_pending():
    return load_json(PENDING_PATH, {"pending": {}})["pending"]


def _save_pending(pending):
    atomic_write(PENDING_PATH, json.dumps({"pending": pending}, indent=2))


def queue_pending(kind, url, payload, applied_by, config_ts):
    with _pending_lock:
        pending = load_pending()
        pending.setdefault(url, {})[kind] = {
            "payload": payload,
            "applied_by": applied_by,
            "config_ts": config_ts,
            "queued_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        _save_pending(pending)


def clear_pending(url, kind=None):
    """Drop queued deliveries for a peer -- one kind, or all when kind=None."""
    with _pending_lock:
        pending = load_pending()
        if url not in pending:
            return
        if kind is None or not isinstance(pending[url], dict):
            del pending[url]
        else:
            pending[url].pop(kind, None)
            if not pending[url]:
                del pending[url]
        _save_pending(pending)


def pending_retry_loop():
    while True:
        time.sleep(PENDING_RETRY_SECONDS)
        try:
            peer_urls = {p["url"] for p in load_peers()}
            for url, kinds in list(load_pending().items()):
                if url not in peer_urls:  # peer was removed meanwhile
                    clear_pending(url)
                    continue
                if not isinstance(kinds, dict):
                    clear_pending(url)  # legacy/malformed entry
                    continue
                for kind, entry in list(kinds.items()):
                    spec = SYNC_KINDS.get(kind)
                    if not spec or not isinstance(entry, dict) or "payload" not in entry:
                        clear_pending(url, kind)
                        continue
                    timeout = (CLIENTS_APPLY_TIMEOUT if kind == "clients"
                               else CLUSTER_TIMEOUT)
                    try:
                        resp = cluster_call(url, spec["endpoint"], {
                            spec["key"]: entry["payload"],
                            "applied_by": entry["applied_by"],
                            "config_ts": entry["config_ts"],
                        }, timeout=timeout)
                    except ClusterError as exc:
                        if exc.status in (400, 409):
                            # Rejected for good: invalid, or superseded by a
                            # newer apply that already reached the peer.
                            clear_pending(url, kind)
                            log.info("dropped queued %s apply for %s: %s",
                                     kind, url, exc)
                        continue
                    clear_pending(url, kind)
                    log.info("delivered queued %s apply to %s: %s",
                             kind, url, resp.get("message"))
        except Exception:
            log.exception("pending delivery loop error")


# ---------------------------------------------------------------------------
# Log viewing (shared radius-logs volume)
# ---------------------------------------------------------------------------

def read_log_tail(path):
    """Last LOG_TAIL_BYTES of a log file, or None if there is no file."""
    try:
        with open(path, "rb") as f:
            size = f.seek(0, os.SEEK_END)
            f.seek(max(0, size - LOG_TAIL_BYTES))
            data = f.read()
    except OSError:
        return None
    text = data.decode("utf-8", "replace")
    if size > LOG_TAIL_BYTES:
        text = text.split("\n", 1)[-1]  # drop the leading partial line
    return text


def rotate_log_if_needed(path):
    """Cap a log at RADIUS_LOG_MAX_MB, keeping one previous generation.

    The persistent writers (tee for radius.log, the FileHandler for auth.log)
    hold an O_APPEND fd on the file, so it must be truncated in place --
    replacing the file would leave the writer appending to an orphaned inode
    (linelog reopens auth.log per message, so it is safe either way). Lines
    written between the copy and the truncate are lost, the same trade-off
    as logrotate's copytruncate.
    """
    try:
        if os.path.getsize(path) <= RADIUS_LOG_MAX_MB * 1024 * 1024:
            return
        shutil.copyfile(path, path + ".1")
        os.truncate(path, 0)
        log.info("rotated %s (> %d MB)", path, RADIUS_LOG_MAX_MB)
    except OSError as exc:
        log.warning("log rotation failed: %s", exc)


# ---------------------------------------------------------------------------
# LDAP authentication
# ---------------------------------------------------------------------------

def ldap_connection(user_dn, password):
    tls = Tls(
        validate=ssl.CERT_REQUIRED
        if LDAP_TLS_REQUIRE_CERT == "demand"
        else ssl.CERT_NONE
    )
    server = Server(LDAP_SERVER, tls=tls, get_info=NONE, connect_timeout=5)
    conn = Connection(server, user=user_dn, password=password, receive_timeout=10)
    conn.open()
    if LDAP_START_TLS:
        conn.start_tls()
    if not conn.bind():
        conn.unbind()
        return None
    return conn


def first_rdn_value(dn):
    first = dn.split(",", 1)[0]
    return first.split("=", 1)[1].strip() if "=" in first else first.strip()


def check_admin_group(service_conn, user_dn, username, member_of):
    wanted = ADMIN_GROUP.lower()
    if any(first_rdn_value(g).lower() == wanted for g in member_of):
        return True
    # Directories without memberOf (e.g. plain OpenLDAP groupOfNames):
    # search for a group entry that lists the user.
    flt = (
        "(&"
        + LDAP_GROUP_OBJECT_FILTER
        + f"(cn={escape_filter_chars(ADMIN_GROUP)})"
        + "(|"
        + f"(member={escape_filter_chars(user_dn)})"
        + f"(uniqueMember={escape_filter_chars(user_dn)})"
        + f"(memberUid={escape_filter_chars(username)})"
        + "))"
    )
    service_conn.search(LDAP_GROUP_BASE_DN, flt, attributes=["cn"])
    return len(service_conn.entries) > 0


def authenticate(username, password):
    """Returns (ok, message). Never raises on bad credentials."""
    if not username or not password:
        # Guard against LDAP unauthenticated binds: an empty password would
        # "succeed" as an anonymous bind on many servers.
        return False, "Username and password are required."
    try:
        svc = ldap_connection(LDAP_BIND_DN, LDAP_BIND_PASSWORD)
        if svc is None:
            log.error("service account bind failed -- check LDAP_BIND_DN/PASSWORD")
            return False, "Directory configuration error. Check the container logs."
        try:
            flt = (
                "(&"
                + LDAP_USER_OBJECT_FILTER
                + f"({LDAP_USER_NAME_ATTRIBUTE}={escape_filter_chars(username)})"
                + ")"
            )
            svc.search(LDAP_USER_BASE_DN, flt, attributes=["memberOf"])
            if len(svc.entries) != 1:
                return False, "Invalid username or password."
            entry = svc.entries[0]
            user_dn = entry.entry_dn
            member_of = (
                [str(v) for v in entry.memberOf.values]
                if "memberOf" in entry
                else []
            )

            user_conn = ldap_connection(user_dn, password)
            if user_conn is None:
                return False, "Invalid username or password."
            user_conn.unbind()

            if not check_admin_group(svc, user_dn, username, member_of):
                log.warning("login denied for %s: not in group %r", username, ADMIN_GROUP)
                return False, f"You are not a member of the required group ({ADMIN_GROUP})."
            return True, None
        finally:
            svc.unbind()
    except LDAPException as exc:
        log.error("LDAP error during login: %s", exc)
        return False, "Could not reach the directory server."


# ---------------------------------------------------------------------------
# Web plumbing
# ---------------------------------------------------------------------------

def csrf_token():
    token = session.get("_csrf")
    if not token:
        token = secrets.token_hex(16)
        session["_csrf"] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


@app.template_filter("localtime")
def format_localtime(iso_ts):
    """Render a stored ISO-8601 UTC stamp in the host's timezone (the
    containers mount /etc/localtime). Stamps stay UTC on disk and on the
    cluster API; peers' stamps are converted by the viewing instance."""
    if not iso_ts:
        return "never"
    try:
        dt = datetime.fromisoformat(str(iso_ts))
    except ValueError:
        return iso_ts
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


@app.context_processor
def inject_versions():
    # Versions are footer-only and gated on login, so the login page does
    # not disclose what server versions are running.
    return {
        "admin_version": ADMIN_VERSION,
        "freeradius_version": freeradius_version() if session.get("user") else None,
    }


@app.before_request
def csrf_protect():
    if request.path.startswith("/api/"):
        return None  # server-to-server endpoints authenticate via HMAC
    if request.method == "POST":
        if request.form.get("_csrf") != session.get("_csrf"):
            abort(400, "CSRF token mismatch -- reload the page and try again.")
    return None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def validate_rule_form(form, profile_names=()):
    errors = []
    name = form.get("name", "").strip()
    ldap_group = form.get("ldap_group", "").strip()
    nas_mode = form.get("nas_mode", "any").strip()
    nas_ip = ""
    nas_profile = ""
    enabled = form.get("enabled") == "on"
    if not name:
        errors.append("Rule name is required.")
    if not ldap_group or "\n" in ldap_group:
        errors.append("LDAP group is required (single line).")
    if nas_mode == "ip":
        nas_ip = form.get("nas_ip", "").strip()
        if nas_ip:
            try:
                ipaddress.ip_address(nas_ip)
            except ValueError:
                errors.append("NAS IP must be a single valid IP address (or empty).")
    elif nas_mode == "profile":
        nas_profile = form.get("nas_profile", "").strip()
        if not nas_profile:
            errors.append("Select a client profile, or choose a different match.")
        elif profile_names and nas_profile not in profile_names:
            errors.append(f"Unknown client profile: {nas_profile!r}")

    attributes = []
    for attr, op, value in zip(
        form.getlist("attr"), form.getlist("op"), form.getlist("value")
    ):
        attr, op, value = attr.strip(), op.strip(), value.strip()
        if not attr and not value:
            continue  # blank row
        if not ATTR_NAME_RE.fullmatch(attr):
            errors.append(f"Invalid attribute name: {attr!r}")
        if op not in OPERATORS:
            errors.append(f"Invalid operator for {attr}: {op!r}")
        if not value or "\n" in value or "\r" in value:
            errors.append(f"Invalid value for {attr} (required, single line).")
        attributes.append({"attr": attr, "op": op, "value": value})
    if not attributes:
        errors.append("At least one attribute is required.")

    rule = {
        "name": name,
        "ldap_group": ldap_group,
        "nas_ip": nas_ip,
        "nas_profile": nas_profile,
        "enabled": enabled,
        "attributes": attributes,
    }
    return rule, errors


def validate_profile_form(form):
    errors = []
    name = form.get("name", "").strip()
    cidrs = [c.strip() for c in form.getlist("cidr") if c.strip()]
    secret = form.get("secret", "")
    proto = form.get("proto", "udp").strip()
    nas_type = form.get("nas_type", "").strip()
    msg_auth = form.get("require_message_authenticator", "yes").strip()
    limit_proxy = form.get("limit_proxy_state", "auto").strip()
    extra = form.get("extra", "").replace("\r\n", "\n").strip()
    enabled = form.get("enabled") == "on"

    if not CLIENT_NAME_RE.fullmatch(name):
        errors.append("Profile name is required (letters, digits, . _ - ).")
    if not cidrs:
        errors.append("At least one IP address / CIDR is required.")
    for cidr in cidrs:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            errors.append(f"Invalid IP address or CIDR: {cidr!r}")
    if not secret or "\n" in secret or "\r" in secret:
        errors.append("Shared secret is required (single line).")
    if proto not in CLIENT_PROTOS:
        errors.append(f"Protocol must be one of {', '.join(CLIENT_PROTOS)}.")
    if nas_type and not NAS_TYPE_RE.fullmatch(nas_type):
        errors.append("NAS type may contain only letters, digits, _ and -.")
    if msg_auth not in TRISTATE:
        errors.append("Require-Message-Authenticator must be yes, no, or auto.")
    if limit_proxy not in TRISTATE:
        errors.append("Limit-Proxy-State must be yes, no, or auto.")
    for line in extra.split("\n"):
        if line.strip() and not CLIENT_EXTRA_RE.fullmatch(line.strip()):
            errors.append(f"Invalid extra directive: {line.strip()!r} "
                          "(use `directive = value`, no braces).")

    profile = {
        "name": name,
        "cidrs": cidrs,
        "secret": secret,
        "proto": proto,
        "nas_type": nas_type,
        "require_message_authenticator": msg_auth,
        "limit_proxy_state": limit_proxy,
        "extra": extra,
        "enabled": enabled,
    }
    return profile, errors


def profile_name_taken(profiles, name, exclude_id=None):
    lowered = name.strip().lower()
    return any(p["name"].strip().lower() == lowered and p.get("id") != exclude_id
               for p in profiles)


def pending_changes(rules):
    return load_state().get("applied_hash") != rendered_hash(rules)


def flash_vendor_reminders(rule):
    """Post-save hints for attributes that need matching device-side config."""
    if any(a["attr"].startswith("CP-Gaia") for a in rule["attributes"]):
        flash(
            {
                "text": "Check Point Gaia: this rule only works once the "
                        "matching RBA role exists on each Gaia device. Run "
                        "this in clish on each device:",
                "command": f"add rba role radius-group-{rule['ldap_group']} "
                           "domain-type System all-features",
            },
            "info",
        )


def parse_apply_targets(form):
    """Selected apply targets. Without a cluster (no has_targets field) returns
    ['local']; with the cluster form, returns the checked targets or None when
    nothing was selected (the caller should flash and redirect)."""
    if not form.get("has_targets"):
        return ["local"]
    return form.getlist("target") or None


def push_config_to_peers(kind, payload, peers, targets, config_ts, user):
    """Push a config payload (rules/clients) to the selected peers, queueing
    for retry when a peer is unreachable. Flashes a per-peer result."""
    spec = SYNC_KINDS[kind]
    timeout = CLIENTS_APPLY_TIMEOUT if kind == "clients" else CLUSTER_TIMEOUT
    applied_by = f"{user} (via {CLUSTER_NODE_NAME})"
    for peer in peers:
        if peer["url"] not in targets:
            continue
        try:
            resp = cluster_call(peer["url"], spec["endpoint"],
                                {spec["key"]: payload, "applied_by": applied_by,
                                 "config_ts": config_ts}, timeout=timeout)
            ok = bool(resp.get("ok"))
            message = resp.get("message", "no response detail")
            clear_pending(peer["url"], kind)  # this apply supersedes any queued
        except ClusterError as exc:
            if exc.status in (400, 409):  # rejected, retrying won't help
                ok, message = False, str(exc)
            else:
                queue_pending(kind, peer["url"], payload, applied_by, config_ts)
                log.info("cluster %s apply to %s failed (%s); queued for retry",
                         kind, peer["url"], exc)
                flash(f"{peer['name']}: unreachable ({exc}) -- {kind} apply "
                      f"queued, delivered automatically when the instance is "
                      f"back (retried every {PENDING_RETRY_SECONDS} s).", "info")
                continue
        log.info("cluster %s apply to %s by %s: %s", kind, peer["url"], user, message)
        flash(f"{peer['name']}: {message}", "ok" if ok else "error")


def fetch_peer_statuses(peers, timeout=4):
    """Query each peer's /api/cluster/status. Values are always dicts with
    `state` and `clients_state` present (a peer on an older version omits
    newer keys; an error/non-dict response becomes {'error': ...})."""
    statuses = {}
    for peer in peers:
        try:
            status = cluster_call(peer["url"], "/api/cluster/status", {}, timeout=timeout)
            if not isinstance(status, dict):
                status = {"error": "unexpected response from peer"}
        except ClusterError as exc:
            status = {"error": str(exc)}
        status.setdefault("state", {})
        status.setdefault("clients_state", {})
        statuses[peer["url"]] = status
    return statuses


def instance_sync_rows(kind, peers, statuses, local_pending, local_hash):
    """Per-instance apply status for the dashboard Apply box. Each row is
    applied (this instance's running config == the config shown here),
    pending (an Apply would change it), or unreachable. kind in
    {rules, clients}."""
    state_key = "state" if kind == "rules" else "clients_state"
    rows = [{
        "value": "local",
        "name": CLUSTER_NODE_NAME,
        "local": True,
        "status": "pending" if local_pending else "applied",
    }]
    for peer in peers:
        status = statuses.get(peer["url"], {})
        if status.get("error"):
            state = "unreachable"
        else:
            applied_hash = (status.get(state_key) or {}).get("applied_hash")
            state = "applied" if applied_hash == local_hash else "pending"
        rows.append({"value": peer["url"], "name": peer.get("name"),
                     "local": False, "status": state})
    return rows


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ok, message = authenticate(username, password)
        if ok:
            session["user"] = username
            log.info("login ok: %s", username)
            return redirect(url_for("clients_page"))
        time.sleep(1)  # slow down brute force
        flash(message, "error")
    return render_template("login.html")


@app.post("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    rules = load_rules()
    peers = load_peers()
    local_pending = pending_changes(rules)
    statuses = fetch_peer_statuses(peers) if peers else {}
    return render_template(
        "index.html",
        rules=rules,
        preview=render_users_file(rules),
        state=load_state(),
        peers=peers,
        node_name=CLUSTER_NODE_NAME,
        local_status="pending" if local_pending else "applied",
        instances=instance_sync_rows("rules", peers, statuses, local_pending,
                                     rendered_hash(rules)),
    )


@app.route("/rules/new", methods=["GET", "POST"])
@login_required
def rule_new():
    profiles = [c["name"] for c in load_clients()]
    if request.method == "POST":
        rule, errors = validate_rule_form(request.form, profiles)
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            rule["id"] = uuid.uuid4().hex[:12]
            rules = load_rules()
            rules.append(rule)
            save_rules(rules)
            flash(f"Rule '{rule['name']}' saved. Apply to activate it.", "ok")
            flash_vendor_reminders(rule)
            return redirect(url_for("index"))
    return render_template("edit.html", rule=None, presets=PRESETS, profiles=profiles)


@app.route("/rules/<rule_id>/edit", methods=["GET", "POST"])
@login_required
def rule_edit(rule_id):
    rules = load_rules()
    existing = next((r for r in rules if r["id"] == rule_id), None)
    if existing is None:
        abort(404)
    profiles = [c["name"] for c in load_clients()]
    if request.method == "POST":
        rule, errors = validate_rule_form(request.form, profiles)
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            rule["id"] = rule_id
            rules[rules.index(existing)] = rule
            save_rules(rules)
            flash(f"Rule '{rule['name']}' updated. Apply to activate the change.", "ok")
            flash_vendor_reminders(rule)
            return redirect(url_for("index"))
    return render_template("edit.html", rule=existing, presets=PRESETS, profiles=profiles)


@app.post("/rules/<rule_id>/delete")
@login_required
def rule_delete(rule_id):
    rules = [r for r in load_rules() if r["id"] != rule_id]
    save_rules(rules)
    flash("Rule deleted. Apply to activate the change.", "ok")
    return redirect(url_for("index"))


@app.post("/rules/<rule_id>/toggle")
@login_required
def rule_toggle(rule_id):
    rules = load_rules()
    for r in rules:
        if r["id"] == rule_id:
            r["enabled"] = not r.get("enabled", True)
    save_rules(rules)
    flash("Rule toggled. Apply to activate the change.", "ok")
    return redirect(url_for("index"))


# --- Client profiles (parameter set + one or more CIDRs) ---

@app.route("/clients")
@login_required
def clients_page():
    clients = load_clients()
    peers = load_peers()
    local_pending = clients_pending(clients)
    statuses = fetch_peer_statuses(peers) if peers else {}
    return render_template(
        "clients.html",
        clients=clients,
        preview=render_clients_conf(clients),
        state=load_clients_state(),
        peers=peers,
        node_name=CLUSTER_NODE_NAME,
        local_status="pending" if local_pending else "applied",
        instances=instance_sync_rows("clients", peers, statuses, local_pending,
                                     clients_hash(clients)),
    )


@app.route("/clients/new", methods=["GET", "POST"])
@login_required
def client_new():
    if request.method == "POST":
        profile, errors = validate_profile_form(request.form)
        if not errors and profile_name_taken(load_clients(), profile["name"]):
            errors.append(f"A profile named {profile['name']!r} already exists.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("client_edit.html", profile=profile, protos=CLIENT_PROTOS)
        profile["id"] = uuid.uuid4().hex[:12]
        clients = load_clients()
        clients.append(profile)
        save_clients(clients)
        flash(f"Profile '{profile['name']}' saved. Apply to activate it.", "ok")
        return redirect(url_for("clients_page"))
    return render_template("client_edit.html", profile=None, protos=CLIENT_PROTOS)


@app.route("/clients/<client_id>/edit", methods=["GET", "POST"])
@login_required
def client_edit(client_id):
    clients = load_clients()
    existing = next((c for c in clients if c["id"] == client_id), None)
    if existing is None:
        abort(404)
    if request.method == "POST":
        profile, errors = validate_profile_form(request.form)
        if not errors and profile_name_taken(clients, profile["name"], client_id):
            errors.append(f"A profile named {profile['name']!r} already exists.")
        if errors:
            for e in errors:
                flash(e, "error")
            profile["id"] = client_id
            return render_template("client_edit.html", profile=profile, protos=CLIENT_PROTOS)
        profile["id"] = client_id
        clients[clients.index(existing)] = profile
        save_clients(clients)
        flash(f"Profile '{profile['name']}' updated. Apply to activate the change.", "ok")
        return redirect(url_for("clients_page"))
    return render_template("client_edit.html", profile=existing, protos=CLIENT_PROTOS)


@app.post("/clients/<client_id>/delete")
@login_required
def client_delete(client_id):
    clients = [c for c in load_clients() if c["id"] != client_id]
    save_clients(clients)
    flash("Profile deleted. Apply to activate the change.", "ok")
    return redirect(url_for("clients_page"))


@app.post("/clients/<client_id>/toggle")
@login_required
def client_toggle(client_id):
    clients = load_clients()
    for c in clients:
        if c["id"] == client_id:
            c["enabled"] = not c.get("enabled", True)
    save_clients(clients)
    flash("Profile toggled. Apply to activate the change.", "ok")
    return redirect(url_for("clients_page"))


@app.post("/clients/apply")
@login_required
def clients_apply():
    clients = load_clients()
    user = session.get("user")
    peers = load_peers()
    if not any(c.get("enabled", True) and profile_cidrs(c) for c in clients):
        flash("Refusing to apply: no enabled profile with a CIDR means the "
              "server would reject every request. Add or enable a profile "
              "first.", "error")
        return redirect(url_for("clients_page"))
    targets = parse_apply_targets(request.form)
    if targets is None:
        flash("Select at least one instance to apply to.", "error")
        return redirect(url_for("clients_page"))

    config_ts = time.time()
    if "local" in targets:
        ok, message = apply_clients(clients, user, config_ts)
        log.info("clients apply by %s: %s", user, message)
        flash(f"{CLUSTER_NODE_NAME}: {message}" if peers else message,
              "ok" if ok else "error")

    push_config_to_peers("clients", clients, peers, targets, config_ts, user)
    return redirect(url_for("clients_page"))


@app.post("/apply")
@login_required
def apply():
    rules = load_rules()
    user = session.get("user")
    peers = load_peers()
    targets = parse_apply_targets(request.form)
    if targets is None:
        flash("Select at least one instance to apply to.", "error")
        return redirect(url_for("index"))

    config_ts = time.time()  # orders this apply across the cluster
    if "local" in targets:
        ok, message = apply_rules_locally(rules, user, config_ts)
        log.info("apply by %s: %s", user, message)
        # Only name the instance when there is a cluster to disambiguate.
        flash(f"{CLUSTER_NODE_NAME}: {message}" if peers else message,
              "ok" if ok else "error")

    push_config_to_peers("rules", rules, peers, targets, config_ts, user)
    return redirect(url_for("index"))


# --- Cluster UI ---

@app.route("/cluster")
@login_required
def cluster():
    peers = load_peers()
    statuses = fetch_peer_statuses(peers)
    return render_template(
        "cluster.html",
        peers=peers,
        statuses=statuses,
        pending=load_pending(),
        local_hash=rendered_hash(load_rules()),
        local_clients_hash=clients_hash(load_clients()),
        node_name=CLUSTER_NODE_NAME,
        node_url=CLUSTER_NODE_URL,
        cluster_enabled=bool(CLUSTER_SECRET),
    )


@app.post("/cluster/add")
@login_required
def cluster_add():
    if not CLUSTER_SECRET or not CLUSTER_NODE_URL:
        flash("Set CLUSTER_SECRET and CLUSTER_NODE_URL in .env on every "
              "instance first (see .env.example).", "error")
        return redirect(url_for("cluster"))
    url = normalize_url(request.form.get("url", ""))
    if not url.startswith(("http://", "https://")):
        flash("Instance URL must start with http:// or https://.", "error")
        return redirect(url_for("cluster"))
    if url == CLUSTER_NODE_URL:
        flash("That is this instance's own URL.", "error")
        return redirect(url_for("cluster"))
    try:
        resp = cluster_call(url, "/api/cluster/register",
                            {"name": CLUSTER_NODE_NAME, "url": CLUSTER_NODE_URL,
                             "peers": load_peers()})
    except ClusterError as exc:
        flash(f"Could not register with {url}: {exc}", "error")
        return redirect(url_for("cluster"))
    merge_peers([{"name": resp.get("name"), "url": url}]
                + [e for e in resp.get("peers", []) if isinstance(e, dict)])
    # One-hop propagation so every member ends up with the full list.
    peers = load_peers()
    full_list = peers + [{"name": CLUSTER_NODE_NAME, "url": CLUSTER_NODE_URL}]
    for peer in peers:
        try:
            cluster_call(peer["url"], "/api/cluster/peers", {"peers": full_list})
        except ClusterError as exc:
            flash(f"{peer['name']}: could not sync the instance list ({exc})", "error")
    log.info("cluster: registered with %s (%s)", resp.get("name"), url)
    flash(f"Registered with {resp.get('name') or url}.", "ok")
    return redirect(url_for("cluster"))


@app.post("/cluster/remove")
@login_required
def cluster_remove():
    url = normalize_url(request.form.get("url", ""))
    save_peers([p for p in load_peers() if p["url"] != url])
    clear_pending(url)
    log.info("cluster: removed peer %s", url)
    flash("Instance removed from this instance's list (other instances keep "
          "their own lists).", "ok")
    return redirect(url_for("cluster"))


@app.post("/cluster/pending/cancel")
@login_required
def cluster_pending_cancel():
    url = normalize_url(request.form.get("url", ""))
    kind = request.form.get("kind") or None
    clear_pending(url, kind)
    log.info("cluster: cancelled queued %s apply for %s by %s",
             kind or "all", url, session.get("user"))
    flash("Queued apply cancelled.", "ok")
    return redirect(url_for("cluster"))


# --- Cluster server-to-server API (HMAC-authenticated, no login session) ---

@app.post("/api/cluster/status")
@cluster_api
def api_cluster_status():
    return {
        "name": CLUSTER_NODE_NAME,
        "url": CLUSTER_NODE_URL,
        "version": ADMIN_VERSION,
        "rules_hash": rendered_hash(load_rules()),
        "state": load_state(),
        "clients_hash": clients_hash(load_clients()),
        "clients_state": load_clients_state(),
        "peers": load_peers(),
    }


@app.post("/api/cluster/register")
@cluster_api
def api_cluster_register():
    data = request.get_json(silent=True) or {}
    entries = [{"name": data.get("name"), "url": data.get("url")}]
    entries += [e for e in data.get("peers", []) if isinstance(e, dict)]
    merge_peers(entries)
    log.info("cluster: instance %s (%s) registered here",
             data.get("name"), data.get("url"))
    return {"name": CLUSTER_NODE_NAME, "url": CLUSTER_NODE_URL,
            "peers": load_peers()}


@app.post("/api/cluster/peers")
@cluster_api
def api_cluster_peers():
    data = request.get_json(silent=True) or {}
    merge_peers([e for e in data.get("peers", []) if isinstance(e, dict)])
    return {"ok": True}


@app.post("/api/cluster/apply")
@cluster_api
def api_cluster_apply():
    data = request.get_json(silent=True) or {}
    rules = data.get("rules")
    error = validate_rules_payload(rules)
    if error:
        log.warning("cluster apply rejected: %s", error)
        return {"ok": False, "message": f"ruleset rejected: {error}"}, 400
    try:
        incoming_ts = float(data.get("config_ts") or 0)
    except (TypeError, ValueError):
        incoming_ts = 0
    current_ts = float(load_state().get("config_ts") or 0)
    if incoming_ts and incoming_ts < current_ts:
        # A queued (catch-up) delivery arriving after a newer direct apply.
        return {"ok": False, "message": "stale ruleset -- a newer apply "
                                        "already reached this instance"}, 409
    save_rules(rules)
    applied_by = str(data.get("applied_by") or "cluster peer")
    ok, message = apply_rules_locally(rules, applied_by, incoming_ts or None)
    log.info("cluster apply from %s: %s", applied_by, message)
    return {"ok": ok, "message": message}


@app.post("/api/cluster/apply-clients")
@cluster_api
def api_cluster_apply_clients():
    data = request.get_json(silent=True) or {}
    clients = data.get("clients")
    error = validate_clients_payload(clients)
    if error:
        log.warning("cluster clients apply rejected: %s", error)
        return {"ok": False, "message": f"clients rejected: {error}"}, 400
    try:
        incoming_ts = float(data.get("config_ts") or 0)
    except (TypeError, ValueError):
        incoming_ts = 0
    cstate = load_clients_state()
    current_ts = float(cstate.get("config_ts") or 0)
    if incoming_ts and incoming_ts < current_ts:
        # A queued (catch-up) delivery superseded by a newer direct apply.
        return {"ok": False, "message": "stale clients -- a newer apply "
                                        "already reached this instance"}, 409
    # Idempotent: if these clients are already applied here, don't restart
    # radiusd again (retries after a timeout would otherwise churn).
    if clients_hash(clients) == cstate.get("applied_hash"):
        return {"ok": True, "message": "already in sync (no restart needed)"}
    save_clients(clients)
    applied_by = str(data.get("applied_by") or "cluster peer")
    ok, message = apply_clients(clients, applied_by, incoming_ts or None)
    log.info("cluster clients apply from %s: %s", applied_by, message)
    return {"ok": ok, "message": message}


def log_file_or_404(log_name):
    if log_name not in LOG_FILES:
        abort(404)
    return LOG_FILES[log_name]


@app.route("/logs")
@login_required
def logs_index():
    return redirect(url_for("logs", log_name="freeradius"))


@app.route("/logs/<log_name>")
@login_required
def logs(log_name):
    info = log_file_or_404(log_name)
    rotate_log_if_needed(info["path"])
    return render_template(
        "logs.html",
        log_name=log_name,
        log_files=LOG_FILES,
        log_text=read_log_tail(info["path"]),
        tail_kb=LOG_TAIL_BYTES // 1024,
        max_mb=RADIUS_LOG_MAX_MB,
    )


@app.get("/logs/<log_name>/tail")
@login_required
def logs_tail(log_name):
    # Polled by the auto-refresh script on the logs page.
    text = read_log_tail(log_file_or_404(log_name)["path"])
    return (text or "", {"Content-Type": "text/plain; charset=utf-8"})


@app.post("/logs/<log_name>/clear")
@login_required
def logs_clear(log_name):
    info = log_file_or_404(log_name)
    try:
        # In place: the writer (tee / FileHandler) keeps its O_APPEND fd.
        os.truncate(info["path"], 0)
        log.info("%s log cleared by %s", log_name, session.get("user"))
        flash(f"{info['label']} log cleared.", "ok")
    except OSError as exc:
        flash(f"Could not clear the log: {exc}", "error")
    return redirect(url_for("logs", log_name=log_name))


# ---------------------------------------------------------------------------

def startup():
    os.makedirs(DATA_DIR, exist_ok=True)
    # Make the generated file reflect the stored rules from the start, so the
    # stock users file from the FreeRADIUS image never lingers. radiusd is
    # only reloaded on an explicit Apply.
    try:
        write_authorize(load_rules())
    except OSError as exc:
        log.warning("could not write %s at startup: %s", AUTHORIZE_PATH, exc)

    # Seed the default client on first run, then always (re)write clients.conf
    # so it reflects the stored clients. On the very first boot the shared
    # volume was empty when freeradius started ($-INCLUDE found nothing, zero
    # clients loaded), so restart radiusd once to pick up the seed.
    try:
        if not os.path.exists(CLIENTS_PATH):
            save_clients(default_clients())
            log.info("seeded the default RADIUS client (secret 'testing123')")
        conf_existed = os.path.exists(CLIENTS_CONF_PATH)
        write_clients_conf(load_clients())
        if not conf_existed:
            ok, msg = _await_radiusd_up(_signal_restart())
            log.info("clients.conf seeded; radiusd restart: %s", msg)
    except OSError as exc:
        log.warning("could not write %s at startup: %s", CLIENTS_CONF_PATH, exc)

    if CLUSTER_SECRET:
        # Delivers applies that targeted an instance while it was offline.
        threading.Thread(target=pending_retry_loop, daemon=True,
                         name="pending-retry").start()


if __name__ == "__main__":
    from waitress import serve

    startup()
    log.info("radius-admin listening on :8080 (admin group: %s)", ADMIN_GROUP)
    serve(app, host="0.0.0.0", port=8080)
