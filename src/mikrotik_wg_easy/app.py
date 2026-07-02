#!/usr/bin/env python3
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import time
import uuid
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
APP_PORT = int(os.getenv("APP_PORT", "8080"))
APP_DATA = Path(os.getenv("APP_DATA", "/data"))
DB_PATH = APP_DATA / "mikrotik-wg-easy.sqlite3"
COOKIE_SECURE = os.getenv("APP_COOKIE_SECURE", "0") == "1"
SESSION_TTL_SECONDS = int(os.getenv("APP_SESSION_TTL_SECONDS", "28800"))
RATE_WINDOW_SECONDS = 60
RATE_LIMIT = int(os.getenv("APP_RATE_LIMIT_PER_MINUTE", "120"))
TRUST_PROXY_HEADERS = os.getenv("APP_TRUST_PROXY_HEADERS", "0") == "1"

DEFAULT_SETTINGS = {
    "router_host": os.getenv("ROS_HOST", "172.17.0.1"),
    "router_user": os.getenv("ROS_USER", "wg-easy"),
    "router_port": os.getenv("ROS_SSH_PORT", "22"),
    "ssh_key": os.getenv("ROS_SSH_KEY", "/data/id_ed25519"),
    "wg_interface": os.getenv("WG_INTERFACE", "wg0"),
    "listen_port": os.getenv("WG_LISTEN_PORT", "13231"),
    "client_cidr": os.getenv("WG_CLIENT_CIDR", "10.8.0.0/24"),
    "router_address": os.getenv("WG_ROUTER_ADDRESS", "10.8.0.1/24"),
    "endpoint": os.getenv("WG_ENDPOINT", ""),
    "dns": os.getenv("WG_DNS", "10.8.0.1"),
    "allowed_ips": os.getenv("WG_ALLOWED_IPS", "0.0.0.0/0"),
    "keepalive": os.getenv("WG_KEEPALIVE", "25"),
    "wan_interface_list": os.getenv("WG_WAN_LIST", "WAN"),
}

SESSIONS = {}
RATE_STATE = {}


def password_hash_from_env():
    configured_hash = os.getenv("APP_PASSWORD_HASH", "")
    if configured_hash:
        return configured_hash
    password = os.getenv("APP_PASSWORD", "")
    if password:
        return hash_password(password)
    if os.getenv("APP_INSECURE_DEV", "0") == "1":
        return hash_password("admin")
    return ""


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return "pbkdf2_sha256$310000$%s$%s" % (
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode(),
    )


def verify_password(password, stored):
    try:
        algo, rounds, salt_b64, digest_b64 = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


APP_PASSWORD_HASH = password_hash_from_env()


def db():
    APP_DATA.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("create table if not exists settings (key text primary key, value text not null)")
    conn.execute(
        """
        create table if not exists clients (
            id text primary key,
            name text not null,
            address text not null,
            comment text not null,
            config text not null,
            disabled integer not null default 0,
            created_at datetime not null default current_timestamp
        )
        """
    )
    conn.commit()
    return conn


def load_settings():
    rows = db().execute("select key, value from settings").fetchall()
    data = DEFAULT_SETTINGS.copy()
    data.update({row["key"]: row["value"] for row in rows})
    return data


def save_settings(payload):
    allowed = set(DEFAULT_SETTINGS)
    current = load_settings()
    candidate = current.copy()
    for key, value in payload.items():
        if key in allowed:
            candidate[key] = str(value).strip()
    validate_settings(candidate)
    conn = db()
    for key, value in candidate.items():
        if key in allowed:
            conn.execute(
                "insert into settings(key, value) values(?, ?) "
                "on conflict(key) do update set value=excluded.value",
                (key, value),
            )
    conn.commit()


def validate_name(value, field):
    if not value or len(value) > 64:
        raise ValueError(f"{field} is required and must be <= 64 chars")
    if not re.fullmatch(r"[A-Za-z0-9_.:@+-]+", value):
        raise ValueError(f"{field} contains unsupported characters")


def validate_client_name(value):
    if not value or len(value) > 64:
        raise ValueError("client name is required and must be <= 64 chars")
    if any(ch in value for ch in "\r\n\t"):
        raise ValueError("client name contains control characters")


def validate_port(value, field):
    try:
        port = int(value)
    except ValueError:
        raise ValueError(f"{field} must be a number")
    if port < 1 or port > 65535:
        raise ValueError(f"{field} must be between 1 and 65535")


def validate_settings(settings):
    validate_name(settings["router_user"], "router_user")
    validate_name(settings["wg_interface"], "wg_interface")
    validate_name(settings["wan_interface_list"], "wan_interface_list")
    validate_port(settings["router_port"], "router_port")
    validate_port(settings["listen_port"], "listen_port")
    try:
        client_net = ipaddress.ip_network(settings["client_cidr"], strict=False)
        router_addr = ipaddress.ip_interface(settings["router_address"])
    except ValueError as exc:
        raise ValueError(f"invalid WireGuard addressing: {exc}")
    if router_addr.ip not in client_net:
        raise ValueError("router_address must be inside client_cidr")
    for part in settings["allowed_ips"].split(","):
        ipaddress.ip_network(part.strip(), strict=False)
    for part in settings["dns"].split(","):
        ipaddress.ip_address(part.strip())
    try:
        keepalive = int(settings["keepalive"])
    except ValueError:
        raise ValueError("keepalive must be a number")
    if keepalive < 0 or keepalive > 65535:
        raise ValueError("keepalive must be between 0 and 65535")
    for field in ("router_host", "endpoint", "ssh_key"):
        value = settings.get(field, "")
        if any(ch in value for ch in "\r\n\t"):
            raise ValueError(f"{field} contains control characters")


def ros_quote(value):
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def ssh_base(settings):
    cmd = [
        "ssh",
        "-p",
        str(settings["router_port"]),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=2",
    ]
    if settings.get("ssh_key"):
        cmd.extend(["-i", settings["ssh_key"]])
    cmd.append(f'{settings["router_user"]}@{settings["router_host"]}')
    return cmd


def run_routeros(command, timeout=30):
    settings = load_settings()
    proc = subprocess.run(
        ssh_base(settings) + [command],
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "RouterOS SSH command failed").strip())
    return proc.stdout.strip()


def run_routeros_many(commands):
    script = "\n".join(commands)
    return run_routeros(script, timeout=60)


def parse_routeros_pairs(text):
    result = {}
    for token in text.replace("\n", " ").split():
        if "=" in token:
            key, value = token.split("=", 1)
            result[key.strip()] = value.strip().strip('"')
    return result


def peer_find(comment):
    return f'[find where comment={ros_quote(comment)}]'


def routeros_peer_addresses(settings):
    used = set()
    try:
        output = run_routeros(
            f'/interface/wireguard/peers/print as-value where interface={ros_quote(settings["wg_interface"])}',
            timeout=20,
        )
    except RuntimeError:
        return used
    for line in output.splitlines():
        pairs = parse_routeros_pairs(line)
        for key in ("allowed-address", "client-address"):
            value = pairs.get(key, "")
            for part in value.split(","):
                part = part.strip()
                if part:
                    used.add(part)
                    try:
                        used.add(f"{ipaddress.ip_interface(part).ip}/32")
                    except ValueError:
                        pass
    return used


def discover_router_settings():
    discovered = {}
    raw = {}

    resource = run_routeros("/system/resource/print as-value")
    raw["resource"] = resource
    pairs = parse_routeros_pairs(resource)
    discovered["routeros_version"] = pairs.get("version", "")
    discovered["architecture"] = pairs.get("architecture-name", "")

    identity = run_routeros("/system/identity/print as-value")
    raw["identity"] = identity
    discovered["identity"] = parse_routeros_pairs(identity).get("name", "")

    dns = run_routeros("/ip/dns/print as-value")
    raw["dns"] = dns
    dns_pairs = parse_routeros_pairs(dns)
    if dns_pairs.get("servers"):
        discovered["dns"] = dns_pairs["servers"].split(",")[0]

    try:
        cloud = run_routeros("/ip/cloud/print as-value")
        raw["cloud"] = cloud
        cloud_pairs = parse_routeros_pairs(cloud)
        if cloud_pairs.get("dns-name"):
            discovered["endpoint"] = cloud_pairs["dns-name"]
    except RuntimeError as exc:
        raw["cloud_error"] = str(exc)

    try:
        wg = run_routeros('/interface/wireguard/print as-value where comment~"mikrotik-wg-easy"')
        raw["wireguard"] = wg
        wg_pairs = parse_routeros_pairs(wg)
        if wg_pairs.get("name"):
            discovered["wg_interface"] = wg_pairs["name"]
        if wg_pairs.get("listen-port"):
            discovered["listen_port"] = wg_pairs["listen-port"]
    except RuntimeError as exc:
        raw["wireguard_error"] = str(exc)

    saveable = {k: v for k, v in discovered.items() if k in DEFAULT_SETTINGS and v}
    if saveable:
        save_settings(saveable)
    return {"settings": load_settings(), "discovered": discovered, "raw": raw}


def next_client_address(settings):
    network = ipaddress.ip_network(settings["client_cidr"], strict=False)
    router_ip = ipaddress.ip_interface(settings["router_address"]).ip
    used = {row["address"] for row in db().execute("select address from clients").fetchall()}
    used.update(routeros_peer_addresses(settings))
    for host in network.hosts():
        if host == router_ip:
            continue
        address = f"{host}/32"
        if address not in used:
            return address
    raise ValueError("No free client addresses in configured CIDR")


def bootstrap_router():
    s = load_settings()
    validate_settings(s)
    commands = [
        f':if ([:len [/interface/wireguard/find where name={ros_quote(s["wg_interface"])}]] = 0) do={{/interface/wireguard/add name={ros_quote(s["wg_interface"])} listen-port={s["listen_port"]} comment="mikrotik-wg-easy"}} else={{/interface/wireguard/set [find where name={ros_quote(s["wg_interface"])}] listen-port={s["listen_port"]} comment="mikrotik-wg-easy"}}',
        f':if ([:len [/ip/address/find where comment="mikrotik-wg-easy"]] = 0) do={{/ip/address/add address={ros_quote(s["router_address"])} interface={ros_quote(s["wg_interface"])} comment="mikrotik-wg-easy"}} else={{/ip/address/set [find where comment="mikrotik-wg-easy"] address={ros_quote(s["router_address"])} interface={ros_quote(s["wg_interface"])}}}',
        f':if ([:len [/ip/firewall/filter/find where comment="mikrotik-wg-easy: allow wireguard"]] = 0) do={{/ip/firewall/filter/add chain=input action=accept protocol=udp dst-port={s["listen_port"]} comment="mikrotik-wg-easy: allow wireguard"}} else={{/ip/firewall/filter/set [find where comment="mikrotik-wg-easy: allow wireguard"] chain=input action=accept protocol=udp dst-port={s["listen_port"]}}}',
        f':if ([:len [/ip/firewall/filter/find where comment="mikrotik-wg-easy: allow wg clients"]] = 0) do={{/ip/firewall/filter/add chain=input action=accept src-address={ros_quote(s["client_cidr"])} comment="mikrotik-wg-easy: allow wg clients"}} else={{/ip/firewall/filter/set [find where comment="mikrotik-wg-easy: allow wg clients"] chain=input action=accept src-address={ros_quote(s["client_cidr"])}}}',
        f':if ([:len [/ip/firewall/nat/find where comment="mikrotik-wg-easy: full tunnel"]] = 0) do={{/ip/firewall/nat/add chain=srcnat action=masquerade src-address={ros_quote(s["client_cidr"])} out-interface-list={ros_quote(s["wan_interface_list"])} comment="mikrotik-wg-easy: full tunnel"}} else={{/ip/firewall/nat/set [find where comment="mikrotik-wg-easy: full tunnel"] chain=srcnat action=masquerade src-address={ros_quote(s["client_cidr"])} out-interface-list={ros_quote(s["wan_interface_list"])}}}',
    ]
    output = run_routeros_many(commands)
    return [{"command": command, "output": output, "ok": True} for command in commands]


def build_client_config(name, client_address):
    s = load_settings()
    validate_settings(s)
    comment = f"mikrotik-wg-easy:{uuid.uuid4()}"
    endpoint = s["endpoint"] or s["router_host"]
    command = (
        "/interface/wireguard/peers/add "
        f'interface={ros_quote(s["wg_interface"])} '
        f'name={ros_quote(name)} '
        "private-key=auto "
        f'allowed-address={ros_quote(client_address)} '
        f'client-address={ros_quote(client_address)} '
        f'client-dns={ros_quote(s["dns"])} '
        f'client-endpoint={ros_quote(endpoint + ":" + s["listen_port"])} '
        f'client-keepalive={s["keepalive"]} '
        f'client-allowed-address={ros_quote(s["allowed_ips"])} '
        f'comment={ros_quote(comment)}'
    )
    run_routeros(command)

    show_command = (
        f':put [/interface/wireguard/peers/show-client-config '
        f'[find where comment={ros_quote(comment)}]]'
    )
    config = run_routeros(show_command)
    if "[Interface]" not in config:
        raise RuntimeError("RouterOS did not return client config through show-client-config")
    return comment, config


def client_by_id(client_id):
    row = db().execute("select * from clients where id=?", (client_id,)).fetchone()
    if not row:
        raise ValueError("client not found")
    return row


def set_client_disabled(client_id, disabled):
    row = client_by_id(client_id)
    value = "yes" if disabled else "no"
    run_routeros(f'/interface/wireguard/peers/set {peer_find(row["comment"])} disabled={value}')
    conn = db()
    conn.execute("update clients set disabled=? where id=?", (1 if disabled else 0, client_id))
    conn.commit()
    return dict(client_by_id(client_id))


def delete_client(client_id):
    row = client_by_id(client_id)
    run_routeros(f'/interface/wireguard/peers/remove {peer_find(row["comment"])}')
    conn = db()
    conn.execute("delete from clients where id=?", (client_id,))
    conn.commit()
    return {"ok": True}


def recreate_client_config(client_id):
    row = client_by_id(client_id)
    show_command = f':put [/interface/wireguard/peers/show-client-config {peer_find(row["comment"])}]'
    config = run_routeros(show_command)
    if "[Interface]" not in config:
        raise RuntimeError("RouterOS did not return client config through show-client-config")
    conn = db()
    conn.execute("update clients set config=? where id=?", (config, client_id))
    conn.commit()
    return {"name": row["name"], "config": config}


def list_clients():
    rows = db().execute(
        "select id, name, address, comment, disabled, created_at from clients order by created_at desc"
    ).fetchall()
    return [dict(row) for row in rows]


def qr_svg(config):
    if not shutil.which("qrencode"):
        raise RuntimeError("qrencode is not installed")
    with tempfile.NamedTemporaryFile("w+", suffix=".svg") as tmp:
        proc = subprocess.run(
            ["qrencode", "-t", "SVG", "-o", tmp.name, config],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or "qrencode failed")
        tmp.seek(0)
        return tmp.read()


LOGIN_PAGE = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MikroTik WireGuard Easy</title><style>
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;background:#f6f7f8;color:#1d252c}
main{max-width:360px;margin:12vh auto;padding:24px;background:white;border:1px solid #dde2e7;border-radius:8px}
input,button{box-sizing:border-box;width:100%;padding:10px;border-radius:6px}input{border:1px solid #c9d1d9}button{border:0;background:#135cc8;color:white;margin-top:12px}
p{color:#52606d}
</style></head><body><main><h1>WireGuard Easy</h1><p>Вход в админ-панель MikroTik container.</p>
<form method="post" action="/login"><input name="password" type="password" autocomplete="current-password" autofocus placeholder="Пароль"><button>Войти</button></form>
</main></body></html>"""


LOCKED_PAGE = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MikroTik WireGuard Easy</title></head><body>
<h1>Web UI locked</h1>
<p>Set APP_PASSWORD_HASH or APP_PASSWORD before starting the container.</p>
</body></html>"""


PAGE = """<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>MikroTik WireGuard Easy</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;background:#f6f7f8;color:#1d252c}
    main{max-width:1120px;margin:0 auto;padding:28px}
    header{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:20px}
    h1{font-size:24px;margin:0} h2{font-size:18px;margin:0 0 12px}
    section{background:white;border:1px solid #dde2e7;border-radius:8px;padding:16px;margin-bottom:16px}
    label{font-size:13px;color:#52606d;display:block;margin-bottom:5px}
    input{box-sizing:border-box;width:100%;padding:9px;border:1px solid #c9d1d9;border-radius:6px}
    .grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
    button{border:0;border-radius:6px;background:#135cc8;color:white;padding:9px 12px;cursor:pointer}
    button.secondary{background:#eef2f7;color:#1d252c;border:1px solid #ccd4dd}
    a{color:#135cc8} table{width:100%;border-collapse:collapse} th,td{text-align:left;border-bottom:1px solid #e5e9ee;padding:9px}
    pre{white-space:pre-wrap;background:#111827;color:#f9fafb;border-radius:8px;padding:12px;overflow:auto}
    dialog{border:0;border-radius:8px;max-width:760px;width:calc(100% - 32px)}
    #qr svg{max-width:320px;width:100%;height:auto}.actions{display:flex;gap:8px;flex-wrap:wrap}
    @media(max-width:840px){.grid{grid-template-columns:1fr 1fr} header{align-items:flex-start;flex-direction:column}}
    @media(max-width:560px){.grid{grid-template-columns:1fr}}
  </style>
</head>
<body>
<main>
  <header>
    <h1>MikroTik WireGuard Easy</h1>
    <div class="actions">
      <button class="secondary" onclick="discover()">Подтянуть из MikroTik</button>
      <button onclick="bootstrap()">Применить настройку</button>
      <button class="secondary" onclick="logout()">Выйти</button>
    </div>
  </header>
  <section>
    <h2>Настройки</h2>
    <div class="grid" id="settings"></div>
    <p><button class="secondary" onclick="saveSettings()">Сохранить</button></p>
  </section>
  <section>
    <h2>Клиенты</h2>
    <p><input id="clientName" placeholder="Имя клиента"><button onclick="createClient()">Создать клиента</button></p>
    <table><thead><tr><th>Имя</th><th>Адрес</th><th>Создан</th><th></th></tr></thead><tbody id="clients"></tbody></table>
  </section>
</main>
<dialog id="clientDialog">
  <h2 id="dialogTitle"></h2>
  <div id="qr"></div>
  <pre id="config"></pre>
  <button onclick="clientDialog.close()">Закрыть</button>
</dialog>
<script>
let csrf = "";
const fields = ["router_host","router_user","router_port","ssh_key","wg_interface","listen_port","client_cidr","router_address","endpoint","dns","allowed_ips","keepalive","wan_interface_list"];
function esc(v){return String(v||"").replaceAll("&","&amp;").replaceAll('"',"&quot;").replaceAll("<","&lt;")}
async function api(path, opts={}) {
  const headers = {"content-type":"application/json", ...(opts.headers||{})};
  if (opts.method && opts.method !== "GET") headers["x-csrf-token"] = csrf;
  const res = await fetch(path, {...opts, headers});
  const text = await res.text();
  let data; try { data = text ? JSON.parse(text) : null } catch { data = text }
  if (!res.ok) throw new Error(data?.error || text || res.statusText);
  return data;
}
async function load() {
  const session = await api("/api/session"); csrf = session.csrf;
  const s = await api("/api/settings");
  settings.innerHTML = fields.map(k => `<div><label>${k}</label><input id="s_${k}" value="${esc(s[k])}"></div>`).join("");
  const rows = await api("/api/clients");
  clients.innerHTML = rows.map(c => `<tr><td>${esc(c.name)}</td><td>${esc(c.address)}</td><td>${c.disabled ? "Отключен" : "Активен"}</td><td class="actions"><button class="secondary" onclick="showClient('${c.id}')">QR/Config</button><a href="/api/clients/${c.id}/download">.conf</a><button class="secondary" onclick="toggleClient('${c.id}', ${c.disabled ? "false" : "true"})">${c.disabled ? "Включить" : "Отключить"}</button><button class="secondary" onclick="recreateConfig('${c.id}')">Пересоздать конфиг</button><button class="secondary" onclick="deleteClient('${c.id}')">Удалить</button></td></tr>`).join("");
}
async function saveSettings() {
  const payload = {}; fields.forEach(k => payload[k] = document.getElementById("s_"+k).value);
  await api("/api/settings", {method:"POST", body:JSON.stringify(payload)}); await load();
}
async function discover() {
  await saveSettings();
  const result = await api("/api/discover", {method:"POST", body:"{}"});
  alert("Параметры подтянуты: " + Object.keys(result.discovered || {}).join(", "));
  await load();
}
async function bootstrap() {
  await saveSettings();
  const result = await api("/api/bootstrap", {method:"POST", body:"{}"});
  alert(result.map(r => `${r.ok ? "OK" : "ERR"} ${r.command}`).join("\\n"));
}
async function createClient() {
  const name = clientName.value.trim(); if (!name) return;
  const c = await api("/api/clients", {method:"POST", body:JSON.stringify({name})});
  clientName.value = ""; await load(); await showClient(c.id);
}
async function showClient(id) {
  const conf = await api(`/api/clients/${id}/config`);
  dialogTitle.textContent = conf.name; config.textContent = conf.config; qr.innerHTML = "";
  try { qr.innerHTML = await (await fetch(`/api/clients/${id}/qr`)).text(); } catch {}
  clientDialog.showModal();
}
async function toggleClient(id, disabled) {
  await api(`/api/clients/${id}/${disabled ? "disable" : "enable"}`, {method:"POST", body:"{}"});
  await load();
}
async function recreateConfig(id) {
  const conf = await api(`/api/clients/${id}/recreate-config`, {method:"POST", body:"{}"});
  await load();
  dialogTitle.textContent = conf.name; config.textContent = conf.config; qr.innerHTML = "";
  try { qr.innerHTML = await (await fetch(`/api/clients/${id}/qr`)).text(); } catch {}
  clientDialog.showModal();
}
async function deleteClient(id) {
  if (!confirm("Удалить клиента и peer на MikroTik?")) return;
  await api(`/api/clients/${id}`, {method:"DELETE", body:"{}"});
  await load();
}
async function logout(){ await api("/logout", {method:"POST", body:"{}"}); location.href="/login"; }
load().catch(e => alert(e.message));
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def client_ip(self):
        if TRUST_PROXY_HEADERS:
            return self.headers.get("x-forwarded-for", self.client_address[0]).split(",")[0].strip()
        return self.client_address[0]

    def rate_limited(self):
        now = time.time()
        ip = self.client_ip()
        bucket = [stamp for stamp in RATE_STATE.get(ip, []) if now - stamp < RATE_WINDOW_SECONDS]
        bucket.append(now)
        RATE_STATE[ip] = bucket
        return len(bucket) > RATE_LIMIT

    def send_common_headers(self):
        self.send_header("x-frame-options", "DENY")
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("referrer-policy", "no-referrer")
        self.send_header("cache-control", "no-store")
        self.send_header("content-security-policy", "default-src 'self'; style-src 'unsafe-inline' 'self'; script-src 'unsafe-inline' 'self'; img-src 'self' data:")

    def respond(self, status=200, body=b"", content_type="application/json", extra_headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode()
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.send_common_headers()
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("content-length", "0"))
        if length > 64 * 1024:
            raise ValueError("request body is too large")
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw or b"{}")

    def read_form(self):
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length).decode()
        return {key: values[0] for key, values in parse_qs(raw).items()}

    def handle_error(self, exc):
        self.respond(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

    def session(self):
        cookie = SimpleCookie(self.headers.get("cookie", ""))
        sid = cookie.get("mwg_session")
        if not sid:
            return None
        data = SESSIONS.get(sid.value)
        if not data or data["expires"] < time.time():
            SESSIONS.pop(sid.value, None)
            return None
        return sid.value, data

    def require_auth(self):
        if not APP_PASSWORD_HASH:
            self.respond(503, LOCKED_PAGE, "text/html; charset=utf-8")
            return None
        session = self.session()
        if session:
            return session
        if self.path.startswith("/api/"):
            self.respond(401, {"error": "authentication required"})
        else:
            self.respond(302, "", extra_headers={"location": "/login"})
        return None

    def require_csrf(self, session):
        if self.command in ("GET", "HEAD"):
            return True
        provided = self.headers.get("x-csrf-token", "")
        return hmac.compare_digest(provided, session[1]["csrf"])

    def create_session(self):
        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        SESSIONS[sid] = {"csrf": csrf, "expires": time.time() + SESSION_TTL_SECONDS}
        flags = "HttpOnly; SameSite=Strict; Path=/"
        if COOKIE_SECURE:
            flags += "; Secure"
        return sid, csrf, f"mwg_session={sid}; Max-Age={SESSION_TTL_SECONDS}; {flags}"

    def do_GET(self):
        if self.rate_limited():
            return self.respond(429, {"error": "rate limit exceeded"})
        try:
            path = urlparse(self.path).path
            if path == "/login":
                if not APP_PASSWORD_HASH:
                    return self.respond(503, LOCKED_PAGE, "text/html; charset=utf-8")
                return self.respond(200, LOGIN_PAGE, "text/html; charset=utf-8")

            session = self.require_auth()
            if not session:
                return

            if path == "/":
                return self.respond(200, PAGE, "text/html; charset=utf-8")
            if path == "/api/session":
                return self.respond(200, {"csrf": session[1]["csrf"]})
            if path == "/api/settings":
                return self.respond(200, load_settings())
            if path == "/api/clients":
                return self.respond(200, list_clients())
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[:2] == ["api", "clients"]:
                row = db().execute("select * from clients where id=?", (parts[2],)).fetchone()
                if not row:
                    return self.respond(404, {"error": "client not found"})
                if parts[3] == "config":
                    return self.respond(200, {"name": row["name"], "config": row["config"]})
                if parts[3] == "qr":
                    return self.respond(200, qr_svg(row["config"]), "image/svg+xml")
                if parts[3] == "download":
                    filename = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in row["name"])
                    return self.respond(
                        200,
                        row["config"],
                        "application/x-wireguard-profile",
                        {"content-disposition": f'attachment; filename="{filename}.conf"'},
                    )
            self.respond(404, {"error": "not found"})
        except Exception as exc:
            self.handle_error(exc)

    def do_POST(self):
        if self.rate_limited():
            return self.respond(429, {"error": "rate limit exceeded"})
        try:
            path = urlparse(self.path).path
            if path == "/login":
                fields = self.read_form()
                password = fields.get("password", "")
                if APP_PASSWORD_HASH and verify_password(password, APP_PASSWORD_HASH):
                    _, _, cookie = self.create_session()
                    return self.respond(302, "", extra_headers={"set-cookie": cookie, "location": "/"})
                time.sleep(1)
                return self.respond(403, LOGIN_PAGE, "text/html; charset=utf-8")

            session = self.require_auth()
            if not session:
                return
            if not self.require_csrf(session):
                return self.respond(403, {"error": "invalid csrf token"})

            if path == "/logout":
                SESSIONS.pop(session[0], None)
                return self.respond(
                    200,
                    {"ok": True},
                    extra_headers={"set-cookie": "mwg_session=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/"},
                )

            payload = self.read_json()
            if path == "/api/settings":
                save_settings(payload)
                return self.respond(200, load_settings())
            if path == "/api/discover":
                return self.respond(200, discover_router_settings())
            if path == "/api/bootstrap":
                return self.respond(200, bootstrap_router())
            if path == "/api/clients":
                name = str(payload.get("name", "")).strip()
                validate_client_name(name)
                settings = load_settings()
                address = next_client_address(settings)
                comment, config = build_client_config(name, address)
                client_id = str(uuid.uuid4())
                conn = db()
                conn.execute(
                    "insert into clients(id, name, address, comment, config) values(?, ?, ?, ?, ?)",
                    (client_id, name, address, comment, config),
                )
                conn.commit()
                return self.respond(201, {"id": client_id, "name": name, "address": address})
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[:2] == ["api", "clients"]:
                if parts[3] == "disable":
                    return self.respond(200, set_client_disabled(parts[2], True))
                if parts[3] == "enable":
                    return self.respond(200, set_client_disabled(parts[2], False))
                if parts[3] == "recreate-config":
                    return self.respond(200, recreate_client_config(parts[2]))
            self.respond(404, {"error": "not found"})
        except Exception as exc:
            self.handle_error(exc)

    def do_DELETE(self):
        if self.rate_limited():
            return self.respond(429, {"error": "rate limit exceeded"})
        try:
            session = self.require_auth()
            if not session:
                return
            if not self.require_csrf(session):
                return self.respond(403, {"error": "invalid csrf token"})
            path = urlparse(self.path).path
            parts = path.strip("/").split("/")
            if len(parts) == 3 and parts[:2] == ["api", "clients"]:
                return self.respond(200, delete_client(parts[2]))
            self.respond(404, {"error": "not found"})
        except Exception as exc:
            self.handle_error(exc)

    def log_message(self, fmt, *args):
        print(f"{self.client_ip()} - {fmt % args}")


def main():
    db()
    if not APP_PASSWORD_HASH:
        print("APP_PASSWORD_HASH or APP_PASSWORD is required; Web UI will stay locked.")
    print(f"Listening on http://{APP_HOST}:{APP_PORT}")
    ThreadingHTTPServer((APP_HOST, APP_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
