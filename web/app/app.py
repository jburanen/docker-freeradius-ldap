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

import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import signal
import ssl
import time
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
RULES_PATH = os.path.join(DATA_DIR, "rules.json")
STATE_PATH = os.path.join(DATA_DIR, "state.json")
AUTHORIZE_PATH = os.path.join(RADIUS_FILES_DIR, "authorize")

# radiusd log file, tee'd from the freeradius container's stdout onto the
# shared radius-logs volume (see docker-compose.yml).
RADIUS_LOG_PATH = os.path.join(env("RADIUS_LOG_DIR", "/logs"), "radius.log")
RADIUS_LOG_MAX_MB = int(env("RADIUS_LOG_MAX_MB", "10"))
LOG_TAIL_BYTES = 64 * 1024

ATTR_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
UNQUOTED_VALUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
OPERATORS = ("=", ":=", "+=")

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
        if rule.get("nas_ip"):
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


# ---------------------------------------------------------------------------
# radiusd log viewing (shared radius-logs volume)
# ---------------------------------------------------------------------------

def read_log_tail():
    """Last LOG_TAIL_BYTES of the radiusd log, or None if there is no file."""
    try:
        with open(RADIUS_LOG_PATH, "rb") as f:
            size = f.seek(0, os.SEEK_END)
            f.seek(max(0, size - LOG_TAIL_BYTES))
            data = f.read()
    except OSError:
        return None
    text = data.decode("utf-8", "replace")
    if size > LOG_TAIL_BYTES:
        text = text.split("\n", 1)[-1]  # drop the leading partial line
    return text


def rotate_log_if_needed():
    """Cap the log at RADIUS_LOG_MAX_MB, keeping one previous generation.

    tee holds an O_APPEND fd on the file, so it must be truncated in place --
    replacing the file would leave tee appending to an orphaned inode. Lines
    written between the copy and the truncate are lost, the same trade-off
    as logrotate's copytruncate.
    """
    try:
        if os.path.getsize(RADIUS_LOG_PATH) <= RADIUS_LOG_MAX_MB * 1024 * 1024:
            return
        shutil.copyfile(RADIUS_LOG_PATH, RADIUS_LOG_PATH + ".1")
        os.truncate(RADIUS_LOG_PATH, 0)
        log.info("rotated %s (> %d MB)", RADIUS_LOG_PATH, RADIUS_LOG_MAX_MB)
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


@app.before_request
def csrf_protect():
    if request.method == "POST":
        if request.form.get("_csrf") != session.get("_csrf"):
            abort(400, "CSRF token mismatch -- reload the page and try again.")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def validate_rule_form(form):
    errors = []
    name = form.get("name", "").strip()
    ldap_group = form.get("ldap_group", "").strip()
    nas_ip = form.get("nas_ip", "").strip()
    enabled = form.get("enabled") == "on"
    if not name:
        errors.append("Rule name is required.")
    if not ldap_group or "\n" in ldap_group:
        errors.append("LDAP group is required (single line).")
    if nas_ip:
        try:
            ipaddress.ip_address(nas_ip)
        except ValueError:
            errors.append("NAS IP must be a single valid IP address (or empty).")

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
        "enabled": enabled,
        "attributes": attributes,
    }
    return rule, errors


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
            return redirect(url_for("index"))
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
    return render_template(
        "index.html",
        rules=rules,
        preview=render_users_file(rules),
        state=load_state(),
        pending=pending_changes(rules),
    )


@app.route("/rules/new", methods=["GET", "POST"])
@login_required
def rule_new():
    if request.method == "POST":
        rule, errors = validate_rule_form(request.form)
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
    return render_template("edit.html", rule=None, presets=PRESETS)


@app.route("/rules/<rule_id>/edit", methods=["GET", "POST"])
@login_required
def rule_edit(rule_id):
    rules = load_rules()
    existing = next((r for r in rules if r["id"] == rule_id), None)
    if existing is None:
        abort(404)
    if request.method == "POST":
        rule, errors = validate_rule_form(request.form)
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
    return render_template("edit.html", rule=existing, presets=PRESETS)


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


@app.post("/apply")
@login_required
def apply():
    rules = load_rules()
    write_authorize(rules)
    ok, message = reload_freeradius()
    state = {
        "applied_hash": rendered_hash(rules) if ok else None,
        "applied_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "applied_by": session.get("user"),
        "result": message,
    }
    save_state(state)
    log.info("apply by %s: %s", session.get("user"), message)
    flash(message, "ok" if ok else "error")
    return redirect(url_for("index"))


@app.route("/logs")
@login_required
def logs():
    rotate_log_if_needed()
    return render_template(
        "logs.html",
        log_text=read_log_tail(),
        tail_kb=LOG_TAIL_BYTES // 1024,
        max_mb=RADIUS_LOG_MAX_MB,
    )


@app.get("/logs/tail")
@login_required
def logs_tail():
    # Polled by the auto-refresh script on the logs page.
    text = read_log_tail()
    return (text or "", {"Content-Type": "text/plain; charset=utf-8"})


@app.post("/logs/clear")
@login_required
def logs_clear():
    try:
        os.truncate(RADIUS_LOG_PATH, 0)  # in place: tee keeps its O_APPEND fd
        log.info("log cleared by %s", session.get("user"))
        flash("Server log cleared.", "ok")
    except OSError as exc:
        flash(f"Could not clear the log: {exc}", "error")
    return redirect(url_for("logs"))


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


if __name__ == "__main__":
    from waitress import serve

    startup()
    log.info("radius-admin listening on :8080 (admin group: %s)", ADMIN_GROUP)
    serve(app, host="0.0.0.0", port=8080)
