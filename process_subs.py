import os
import re
import json
import time
import html
import socket
import base64
import asyncio
import hashlib
import ipaddress
import urllib.request
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote, quote
import aiohttp

XRAY_BIN = os.environ.get("XRAY_PATH", "./xray")
DB_FILE = "pool_db.json"
CIDR_FILE = "whitelist_cidr.txt"

ALLOWED_SCHEMES = ("vless://", "trojan://", "vmess://", "ss://") #ss:// иногда может не работать
MAX_FAILS = 3          # Сколько циклов подряд прощаем падение ключа перед удалением
CONCURRENCY = 50       # Сколько параллельных процессов Xray запускать
MIN_SPEED_KBPS = 10   # Минимальная скорость скачивания тестового куска (КБ/с)


def load_cidrs(filepath):
    networks = []
    if not os.path.exists(filepath):
        print(f"WARNING: {filepath} не найден, белый фильтр будет пустым.")
        return networks
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                networks.append(ipaddress.ip_network(line, strict=False))
            except ValueError as e:
                print(f"Ошибка в CIDR '{line}': {e}")
    print(f"Загружено {len(networks)} белых подсетей из {filepath}")
    return networks


def is_ip_whitelisted(ip_str, networks):
    if not ip_str or not networks:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in networks)
    except ValueError:
        return False


def try_b64_decode(data: str) -> str:
    cleaned = "".join(data.split())
    if re.fullmatch(r'^[A-Za-z0-9+/]+={0,2}$', cleaned) and len(cleaned) % 4 == 0:
        try:
            decoded = base64.b64decode(cleaned).decode("utf-8")
            if "://" in decoded:
                return decoded
        except Exception:
            pass
    return data


def clean_and_normalize_uri(raw_line: str):
    line = html.unescape(raw_line).strip()
    line = re.sub(r'<[^>]+>.*$', '', line).strip()

    if not line.startswith(ALLOWED_SCHEMES):
        return None

    if "00000000-0000-0001-0000-000000000000" in line:
        return None

    if line.startswith("vmess://"):
        try:
            b64_part = line[8:].split("#", 1)[0]
            b64_part += "=" * ((4 - len(b64_part) % 4) % 4)
            cfg = json.loads(base64.b64decode(b64_part).decode("utf-8", errors="ignore"))
            host = cfg.get("add", "").strip()
            port = int(cfg.get("port", 0))
            uuid = cfg.get("id", "").strip()
            if not host or not port or not uuid or uuid.startswith("00000000"):
                return None
            cfg["ps"] = "node"
            clean_b64 = base64.b64encode(json.dumps(cfg, separators=(",", ":")).encode("utf-8")).decode("utf-8")
            dedup_key = f"vmess|{host}:{port}|{uuid}|{cfg.get('net','')}|{cfg.get('path','')}|{cfg.get('sni','')}"
            return f"vmess://{clean_b64}", hashlib.sha1(dedup_key.encode()).hexdigest(), host, port
        except Exception:
            return None

    try:
        parsed = urlparse(line)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        port = parsed.port
        user = parsed.username or ""

        if not host or not port or not user:
            return None

        qs = parse_qs(parsed.query, keep_blank_values=False)
        params = {k: v[0] for k, v in qs.items()}

        params.pop("Telegram", None)

        if params.get("type") == "raw":
            params["type"] = "tcp"

        if scheme in ("vless", "trojan"):
            if params.get("fp") not in ("chrome", "firefox", "safari", "ios", "android", "edge", "random"):
                params["fp"] = "chrome"

        dedup_parts = [
            scheme,
            host.lower(),
            str(port),
            user,
            params.get("type", "tcp"),
            params.get("security", "none"),
            params.get("sni", ""),
            params.get("host", ""),
            params.get("path", ""),
            params.get("serviceName", ""),
            params.get("pbk", ""),
            params.get("sid", ""),
        ]
        dedup_hash = hashlib.sha1("|".join(dedup_parts).encode("utf-8")).hexdigest()

        new_query = urlencode(sorted(params.items()))
        clean_uri = urlunparse((scheme, f"{user}@{host}:{port}", parsed.path or "", "", new_query, ""))
        return clean_uri, dedup_hash, host, port
    except Exception:
        return None


def fetch_all_sources():
    entries = []
    for line in os.environ.get("SUB_URLS", "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        name, url = line.split(":", 1)
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        entries.append((name.strip(), url))

    fetched = {}
    for name, url in entries:
        for attempt in range(3):
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0"}
                )
                with urllib.request.urlopen(req, timeout=25) as resp:
                    raw_text = resp.read().decode("utf-8", errors="ignore").strip()
                decoded = try_b64_decode(raw_text)
                count = 0
                for raw_line in decoded.splitlines():
                    res = clean_and_normalize_uri(raw_line)
                    if res:
                        clean_uri, h, host, port = res
                        if h not in fetched:
                            fetched[h] = {
                                "uri": clean_uri,
                                "host": host,
                                "port": port,
                                "sources": [name]
                            }
                            count += 1
                        elif name not in fetched[h]["sources"]:
                            fetched[h]["sources"].append(name)
                print(f"OK [{name}]: добавлено {count} уникальных узлов")
                break
            except Exception as e:
                print(f"WARNING [{name}] попытка {attempt+1}: {e}")
                time.sleep(2)
    return fetched


def build_xray_outbound(uri: str):
    parsed = urlparse(uri)
    scheme = parsed.scheme.lower()

    if scheme == "vmess":
        b64_part = uri[8:].split("#", 1)[0]
        b64_part += "=" * ((4 - len(b64_part) % 4) % 4)
        c = json.loads(base64.b64decode(b64_part).decode("utf-8"))
        net = c.get("net", "tcp")
        tls = c.get("tls", "")
        stream = {"network": net}
        if tls == "tls":
            stream["security"] = "tls"
            stream["tlsSettings"] = {"serverName": c.get("sni") or c.get("host") or c.get("add"), "allowInsecure": True}
        if net == "ws":
            stream["wsSettings"] = {"path": c.get("path", "/"), "headers": {"Host": c.get("host", "")}}
        return {
            "protocol": "vmess",
            "settings": {"vnext": [{"address": c["add"], "port": int(c["port"]), "users": [{"id": c["id"], "alterId": int(c.get("aid", 0)), "security": "auto"}]}]},
            "streamSettings": stream
        }

    if scheme == "ss":
        userinfo = unquote(parsed.username or "")
        if ":" not in userinfo:
            userinfo += "=" * ((4 - len(userinfo) % 4) % 4)
            userinfo = base64.b64decode(userinfo).decode("utf-8", errors="ignore")
        method, password = userinfo.split(":", 1)
        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{"address": parsed.hostname, "port": parsed.port, "method": method, "password": password}]}
        }

    qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    net = qs.get("type", "tcp")
    sec = qs.get("security", "none")

    stream = {"network": net, "security": sec}
    if sec == "tls":
        stream["tlsSettings"] = {
            "serverName": qs.get("sni", parsed.hostname),
            "allowInsecure": True,
            "fingerprint": qs.get("fp", "chrome")
        }
    elif sec == "reality":
        stream["realitySettings"] = {
            "serverName": qs.get("sni", ""),
            "fingerprint": qs.get("fp", "chrome"),
            "publicKey": qs.get("pbk", ""),
            "shortId": qs.get("sid", ""),
            "spiderX": qs.get("spx", "/")
        }

    if net == "ws":
        stream["wsSettings"] = {"path": qs.get("path", "/"), "headers": {"Host": qs.get("host", qs.get("sni", ""))}}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": qs.get("serviceName", ""), "multiMode": qs.get("mode") == "multi"}
    elif net == "xhttp":
        stream["xhttpSettings"] = {"path": qs.get("path", "/"), "host": qs.get("host", ""), "mode": qs.get("mode", "auto")}

    if scheme == "vless":
        user_obj = {"id": parsed.username, "encryption": qs.get("encryption", "none")}
        if qs.get("flow"):
            user_obj["flow"] = qs["flow"]
        return {
            "protocol": "vless",
            "settings": {"vnext": [{"address": parsed.hostname, "port": parsed.port, "users": [user_obj]}]},
            "streamSettings": stream
        }

    if scheme == "trojan":
        return {
            "protocol": "trojan",
            "settings": {"servers": [{"address": parsed.hostname, "port": parsed.port, "password": unquote(parsed.username)}]},
            "streamSettings": stream
        }

    return None


async def resolve_and_tcp_check(host: str, port: int, timeout: float = 2.5):
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM),
            timeout=timeout
        )
        if not infos:
            return None, False
        ip = infos[0][4][0]
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return ip, True
    except Exception:
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, port, family=socket.AF_INET),
                timeout=1.5
            )
            return (infos[0][4][0] if infos else None), False
        except Exception:
            return None, False


async def test_node_with_xray(node_hash: str, node: dict, local_port: int):
    outbound = build_xray_outbound(node["uri"])
    if not outbound:
        return False, None, 0

    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": local_port, "listen": "127.0.0.1", "protocol": "http"}],
        "outbounds": [outbound]
    }
    cfg_path = f"/tmp/xray_{local_port}.json"
    with open(cfg_path, "w") as f:
        json.dump(config, f)

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            XRAY_BIN, "run", "-c", cfg_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await asyncio.sleep(0.35)

        proxy_url = f"http://127.0.0.1:{local_port}"
        timeout = aiohttp.ClientTimeout(total=7)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            trace_url = "https://" + "cloudflare.com/cdn-cgi/trace"
            async with session.get(trace_url, proxy=proxy_url) as resp:
                if resp.status != 200:
                    return False, None, 0
                trace_text = await resp.text()
                loc_match = re.search(r'^loc=([A-Z]{2})', trace_text, re.M)
                exit_loc = loc_match.group(1) if loc_match else "??"

            t0 = time.monotonic()
            speed_url = "https://" + "speed.cloudflare.com/__down?bytes=250000"
            async with session.get(speed_url, proxy=proxy_url) as resp:
                data = await resp.read()
                elapsed = max(time.monotonic() - t0, 0.05)
                speed_kbps = int((len(data) / 1024) / elapsed)
                if len(data) < 200000 or speed_kbps < MIN_SPEED_KBPS:
                    return False, exit_loc, speed_kbps

        return True, exit_loc, speed_kbps
    except Exception:
        return False, None, 0
    finally:
        if proc:
            try:
                proc.terminate()
                await proc.wait()
            except Exception:
                pass
        if os.path.exists(cfg_path):
            os.remove(cfg_path)


async def main():
    cidrs = load_cidrs(CIDR_FILE)

    db = {}
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r", encoding="utf-8") as f:
                db = json.load(f)
            print(f"Загружено {len(db)} узлов из накопительной базы {DB_FILE}")
        except Exception as e:
            print(f"Ошибка чтения {DB_FILE}: {e}")

    fresh = fetch_all_sources()
    for h, item in fresh.items():
        if h not in db:
            db[h] = {
                "uri": item["uri"],
                "host": item["host"],
                "port": item["port"],
                "sources": item["sources"],
                "uptime": 0,
                "fails": 0,
                "ip": None,
                "exit_loc": "??",
                "speed_kbps": 0
            }
        else:
            db[h]["uri"] = item["uri"]
            db[h]["sources"] = list(set(db[h].get("sources", []) + item["sources"]))

    print(f"Всего уникальных узлов для проверки: {len(db)}")

    sem_tcp = asyncio.Semaphore(100)
    async def tcp_task(h, node):
        async with sem_tcp:
            ip, ok = await resolve_and_tcp_check(node["host"], node["port"])
            return h, ip, ok

    tcp_results = await asyncio.gather(*(tcp_task(h, n) for h, n in db.items()))
    tcp_alive_hashes = []
    for h, ip, ok in tcp_results:
        if ip:
            db[h]["ip"] = ip
        if ok:
            tcp_alive_hashes.append(h)

    print(f"Прошли TCP-чек: {len(tcp_alive_hashes)} из {len(db)}")

    queue = asyncio.Queue()
    for h in tcp_alive_hashes:
        queue.put_nowait(h)

    xray_passed = {}

    async def worker(worker_id):
        local_port = 30000 + worker_id
        while not queue.empty():
            try:
                h = queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            ok, loc, speed = await test_node_with_xray(h, db[h], local_port)
            if ok:
                xray_passed[h] = (loc, speed)
            queue.task_done()

    workers = [asyncio.create_task(worker(i)) for i in range(CONCURRENCY)]
    await asyncio.gather(*workers)
    print(f"Прошли реальный Xray-тест (> {MIN_SPEED_KBPS} КБ/с): {len(xray_passed)}")

    updated_db = {}
    for h, node in db.items():
        if h in xray_passed:
            loc, speed = xray_passed[h]
            node["uptime"] = node.get("uptime", 0) + 1
            node["fails"] = 0
            node["exit_loc"] = loc
            node["speed_kbps"] = speed
            updated_db[h] = node
        else:
            fails = node.get("fails", 0) + 1
            if fails < MAX_FAILS:
                node["fails"] = fails
                updated_db[h] = node

    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(updated_db, f, ensure_ascii=False, indent=2)
    print(f"Сохранено в накопительную базу: {len(updated_db)} узлов")

    alive_nodes = [n for h, n in updated_db.items() if h in xray_passed]
    alive_nodes.sort(key=lambda x: (x["uptime"], x["speed_kbps"]), reverse=True)

    whitelist_lines = []
    all_alive_lines = []
    unverified_wl_lines = []

    for idx, n in enumerate(alive_nodes, 1):
        in_wl = is_ip_whitelisted(n.get("ip"), cidrs)
        loc = n.get("exit_loc", "??")
        up = n.get("uptime", 1)
        spd = round(n.get("speed_kbps", 0) / 1024, 1)
        ip_tag = n.get("ip") or n["host"]

        tag = f"{'⚪' if in_wl else '🌐'} [{loc}] #{idx} | Up:{up}h | {spd}MB/s | {ip_tag}"
        full_uri = f"{n['uri']}#{quote(tag)}"

        all_alive_lines.append(full_uri)
        if in_wl:
            whitelist_lines.append(full_uri)

    for h, n in updated_db.items():
        if h not in xray_passed and is_ip_whitelisted(n.get("ip"), cidrs):
            tag = f"🟡 [UNVERIFIED-WL] {n.get('ip')} | Fails:{n.get('fails')}"
            unverified_wl_lines.append(f"{n['uri']}#{quote(tag)}")

    def save_b64(filename, lines):
        # Добавляем явный завершающий перенос строки внутри кодируемого текста
        # чтобы v2rayNG корректно разделял профили после декодирования Base64
        content = chr(10).join(lines) + (chr(10) if lines else "")
        b64 = base64.b64encode(content.encode("utf-8")).decode("utf-8")
        with open(filename, "w", encoding="utf-8") as f:
            f.write(b64)
        print(f"Записано {len(lines)} ключей -> {filename}")

    save_b64("whitelist.txt", whitelist_lines)
    save_b64("all_alive.txt", all_alive_lines)
    save_b64("whitelist_unverified.txt", unverified_wl_lines)


if __name__ == "__main__":
    asyncio.run(main())
