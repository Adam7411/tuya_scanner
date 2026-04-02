#!/usr/bin/env python3
"""TinyTuya Scanner — HA Addon Backend"""

import ipaddress
import json, logging, os, re, subprocess, sys, threading, time
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [TuyaScanner] %(levelname)s: %(message)s"
)
log = logging.getLogger(__name__)

SCAN_DURATION = int(os.environ.get("SCAN_DURATION", 18))
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", 3600))
DATA_FILE = os.environ.get("DATA_FILE", "/data/devices.json")
WIZARD_FILE = os.environ.get("WIZARD_FILE", "/data/wizard_devices.json")
WWW_DIR = "/var/www"
PORT = 7080

app = Flask(__name__, static_folder=WWW_DIR)
# In HA Ingress/browser contexts preflight requests are common.
# Keep CORS permissive for addon-local API endpoints.
CORS(
    app,
    resources={r"/api/*": {"origins": "*"}},
    supports_credentials=False,
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)


@app.after_request
def add_headers(response):
    if request.path.startswith("/api/"):
        response.headers["Content-Type"] = "application/json"
        origin = request.headers.get("Origin")
        response.headers["Access-Control-Allow-Origin"] = origin or "*"
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, Authorization, X-Requested-With"
        )
    return response


state = {
    "scanning": False,
    "devices": [],
    "last_scan": None,
    "log": [],
    "progress": 0,
    "wizard_running": False,
    "wizard_log": [],
    "wizard_devices": [],
    "last_force_cidrs": [],
}

# ── persistence ───────────────────────────────────────────────


def _load():
    log.info("DATA_FILE = %s  exists = %s", DATA_FILE, os.path.exists(DATA_FILE))
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE) as f:
                saved = json.load(f)
            state["devices"] = saved.get("devices", [])
            state["last_scan"] = saved.get("last_scan")
            log.info("Loaded %d devices", len(state["devices"]))
        except Exception as e:
            log.warning("Read error: %s", e)
    if os.path.exists(WIZARD_FILE):
        try:
            with open(WIZARD_FILE) as f:
                state["wizard_devices"] = json.load(f)
            log.info("Loaded %d devices from wizard cache", len(state["wizard_devices"]))
        except:
            pass


def _save():
    try:
        os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
        with open(DATA_FILE, "w") as f:
            json.dump(
                {"devices": state["devices"], "last_scan": state["last_scan"]},
                f,
                indent=2,
            )
        log.info("Saved %d devices to %s", len(state["devices"]), DATA_FILE)
    except Exception as e:
        log.warning("Write error: %s", e)


def _log(msg, level="info"):
    state["log"].append(
        {"t": datetime.now().strftime("%H:%M:%S"), "msg": msg, "level": level}
    )
    state["log"] = state["log"][-100:]
    getattr(log, {"found": "info", "warn": "warning"}.get(level, level))(msg)


def _wlog(msg, level="info"):
    state["wizard_log"].append(
        {"t": datetime.now().strftime("%H:%M:%S"), "msg": msg, "level": level}
    )
    state["wizard_log"] = state["wizard_log"][-200:]
    log.info("[Wizard] %s", msg)


# ── parser ────────────────────────────────────────────────────

RE_DEV = re.compile(r"(Unknown|Known)\s+v([\d.]+)\s+Device\s+Product ID\s*=\s*(\S+)")
RE_ADDR = re.compile(
    r"Address\s*=\s*([\d.]+)\s+Device ID\s*=\s*(\S+)\s+\(\w+:\d+\)\s+"
    r"Local Key\s*=\s*(\S*)\s+Version\s*=\s*([\d.]+)(?:.*?MAC\s*=\s*(\S*))?"
)


def _parse(lines):
    devices, last = {}, {}
    for line in lines:
        line = line.strip()
        m1 = RE_DEV.search(line)
        if m1:
            last = {"known": m1.group(1) == "Known", "productKey": m1.group(3)}
            continue
        m2 = RE_ADDR.search(line)
        if m2:
            gwId = m2.group(2)
            devices[gwId] = {
                "ip": m2.group(1),
                "gwId": gwId,
                "id": gwId,
                "localKey": (m2.group(3) or "").strip(),
                "version": m2.group(4),
                "mac": (m2.group(5) or "").strip(),
                "productKey": last.get("productKey", ""),
                "known": last.get("known", False),
            }
    return list(devices.values())


def _pick_product_key(payload):
    """Normalize product id/key from different TinyTuya/Tuya payload variants."""
    return (
        payload.get("productKey")
        or payload.get("product_id")
        or payload.get("productId")
        or payload.get("pid")
        or ""
    )


# ── scan ──────────────────────────────────────────────────────


def run_scan(duration=None, force_cidrs=None):
    if state["scanning"]:
        return
    duration = duration or SCAN_DURATION
    force_cidrs = force_cidrs or []
    state["last_force_cidrs"] = force_cidrs
    state.update(scanning=True, log=[], progress=0)
    if force_cidrs:
        _log(f"Starting scan ({duration}s, force={','.join(force_cidrs)}) ...", "info")
    else:
        _log(f"Starting scan ({duration}s) ...", "info")

    start = time.time()

    def tick():
        while state["scanning"]:
            state["progress"] = min(
                90, int(100 * (time.time() - start) / (duration + 2))
            )
            time.sleep(1)

    threading.Thread(target=tick, daemon=True).start()

    try:
        cmd = [sys.executable, "-m", "tinytuya", "scan", str(duration)]
        if force_cidrs:
            cmd += ["-force"] + force_cidrs

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        raw = proc.stdout.read()
        proc.wait()
        lines = re.split(r"[\r\n]+", raw.decode("utf-8", errors="ignore"))
        for line in lines:
            s = line.strip()
            if "Address" in s and "Device ID" in s:
                _log(s, "found")
            elif "Found" in s or "Complete" in s:
                _log(s, "info")

        # Połącz wyniki skanu z danymi z wizarda (nazwa, klucz, etc.)
        scanned = _parse(lines)

        # Pobierz dane z wizarda - indeksowane po device id
        wizard_data = {}
        for w in state.get("wizard_devices", []):
            dev_id = w.get("id") or w.get("gwId") or w.get("deviceId", "")
            if dev_id:
                wizard_data[dev_id] = w
                log.info(
                    "Wizard device: id=%s, key=%s",
                    dev_id,
                    w.get("key", "")[:10] if w.get("key") else "None",
                )

        # Poprzednio zapisane urządzenia (fallback dla MAC/nazwy/itp.)
        prev_by_id = {}
        for p in state.get("devices", []):
            pid = p.get("id") or p.get("gwId", "")
            if pid:
                prev_by_id[pid] = p

        # Scal dane - skaner nadaje IP/wersję/MAC, wizard nadaje nazwę/klucz
        merged = []

        # Najpierw dodaj urządzenia ze skanu z danymi z wizarda
        scanned_ids = set()
        for d in scanned:
            dev_id = d.get("id") or d.get("gwId", "")
            scanned_ids.add(dev_id)
            w = wizard_data.get(dev_id, {})
            p = prev_by_id.get(dev_id, {})

            log.info(
                "Merging: scan_id=%s, wizard_key=%s",
                dev_id,
                w.get("key", "")[:10] if w.get("key") else "None",
            )

            d["name"] = w.get("name", "")
            d["productName"] = (
                w.get("productName")
                or w.get("product_name")
                or w.get("name", "")
            )
            d["productKey"] = _pick_product_key(w) or d.get("productKey", "")
            d["localKey"] = d.get("localKey") or w.get("key", "")
            d["mac"] = d.get("mac") or w.get("mac", "") or p.get("mac", "")
            d["online"] = True
            d["status"] = "online"

            if not d.get("name"):
                d["name"] = w.get("productName", p.get("name", f"Device {dev_id[:8]}"))

            merged.append(d)

        # Dodaj urządzenia z wizarda których nie znaleziono w sieci
        for wdev in state.get("wizard_devices", []):
            wid = wdev.get("id") or wdev.get("gwId") or wdev.get("deviceId", "")
            if wid and wid not in scanned_ids:
                p = prev_by_id.get(wid, {})
                merged.append(
                    {
                        "ip": p.get("ip", ""),
                        "gwId": wid,
                        "id": wid,
                        "name": wdev.get(
                            "name", wdev.get("productName", p.get("name", f"Device {wid[:8]}"))
                        ),
                        "productName": wdev.get("productName", wdev.get("product_name", "")),
                        "productKey": _pick_product_key(wdev),
                        "localKey": wdev.get("key", p.get("localKey", "")),
                        "version": p.get("version", ""),
                        "mac": wdev.get("mac", "") or p.get("mac", ""),
                        "online": False,
                        "status": "cloud-only",
                    }
                )

        # Dla urządzeń nieskanowanych, ale obecnych wcześniej lokalnie, oznacz jako offline
        for d in merged:
            if not d.get("online"):
                if d.get("ip"):
                    d["status"] = "offline"
                else:
                    d["status"] = "cloud-only"

        state["devices"] = merged
        state["last_scan"] = datetime.now().isoformat()
        _save()
        v33 = sum(1 for d in scanned if str(d.get("version", "")).startswith("3.3"))
        v34 = sum(1 for d in scanned if str(d.get("version", "")).startswith("3.4"))
        _log(f"Completed — {len(scanned)} devices (v3.3:{v33} v3.4:{v34})", "info")
    except Exception as e:
        _log(f"Error: {e}", "warn")
        log.exception("Details:")
    finally:
        state["scanning"] = False
        state["progress"] = 100


# ── wizard ────────────────────────────────────────────────────


def run_wizard(api_region, api_key, api_secret):
    if state["wizard_running"]:
        return
    state["wizard_running"] = True
    state["wizard_log"] = []
    _wlog("Starting tinytuya wizard ...", "info")
    _wlog(f"Region: {api_region}  |  API Key: {api_key[:8]}…", "info")

    try:
        cmd = [
            sys.executable,
            "-m",
            "tinytuya",
            "wizard",
            "-region",
            api_region,
            "-key",
            api_key,
            "-secret",
            api_secret,
            "-yes",
            "-nocolor",
            "-no-poll",
        ]

        _wlog("Launching TinyTuya Wizard...", "info")

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )

        import platform

        if platform.system() == "Windows":
            # Windows - czytaj po zakończeniu
            output = proc.stdout.read()
            for line in output.decode("utf-8", errors="ignore").splitlines():
                s = line.strip()
                if s:
                    _wlog(s, "info")
                    if s.startswith("{"):
                        try:
                            data = json.loads(s)
                            if "name" in data:
                                _wlog(f"📱 {data.get('name', 'Unknown')}", "found")
                        except:
                            pass
        else:
            # Linux - czytaj w czasie rzeczywistym
            import select

            while True:
                ready, _, _ = select.select([proc.stdout], [], [], 0.3)
                if ready:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    s = line.decode("utf-8", errors="ignore").strip()
                    if s:
                        _wlog(s, "info")
                        if s.startswith("{"):
                            try:
                                data = json.loads(s)
                                if "name" in data:
                                    _wlog(f"📱 {data.get('name', 'Unknown')}", "found")
                            except:
                                pass
                if proc.poll() is not None:
                    break

            # Reszta outputu
            remaining = proc.stdout.read()
            if remaining:
                for line in remaining.decode("utf-8", errors="ignore").splitlines():
                    s = line.strip()
                    if s:
                        _wlog(s, "info")

        proc.wait()

        # Spróbuj wczytać devices.json który wizard tworzy
        devices = []
        for path in ["devices.json", "/data/devices.json", "/tmp/devices.json"]:
            if os.path.exists(path):
                try:
                    with open(path) as f:
                        data = json.load(f)
                    if isinstance(data, list):
                        devices = data
                        _wlog(f"Loaded {len(devices)} devices from {path}", "found")
                        break
                except:
                    pass

        if devices:
            state["wizard_devices"] = devices
            try:
                with open(WIZARD_FILE, "w") as f:
                    json.dump(devices, f, indent=2)
            except:
                pass
            _wlog(f"Done — {len(devices)} devices with keys!", "found")
            # Automatycznie uruchom skan po udanym wizardzie
            _wlog("Starting network scan...", "info")
            run_scan()
        else:
            _wlog("Wizard finished. Check logs above.", "info")

    except Exception as e:
        _wlog(f"Wizard error: {e}", "warn")
        log.exception("Wizard error:")
    finally:
        state["wizard_running"] = False


# ── auto-scan ─────────────────────────────────────────────────


def auto_scan_loop():
    time.sleep(15)
    while True:
        run_scan()
        time.sleep(SCAN_INTERVAL)


# ── Flask ─────────────────────────────────────────────────────


@app.route("/")
def index():
    return send_from_directory(WWW_DIR, "index.html")


@app.route("/favicon.ico")
def favicon():
    return "", 204


# API routes - must be BEFORE the catch-all static route
@app.route("/api/status")
def api_status():
    devs = state["devices"]
    log.info(
        "API /api/status called - devices: %d, scanning: %s",
        len(devs),
        state["scanning"],
    )
    result = {
        "scanning": state["scanning"],
        "devices": devs,
        "last_scan": state["last_scan"],
        "log": state["log"][-40:],
        "progress": state["progress"],
        "scan_interval": SCAN_INTERVAL,
        "wizard_running": state["wizard_running"],
        "wizard_log": state["wizard_log"][-40:],
        "wizard_devices": state["wizard_devices"],
        "last_force_cidrs": state.get("last_force_cidrs", []),
        "count": {
            "total": len(devs),
            "v33": sum(1 for d in devs if str(d.get("version", "")).startswith("3.3")),
            "v34": sum(1 for d in devs if str(d.get("version", "")).startswith("3.4")),
            "with_key": sum(1 for d in devs if d.get("localKey")),
            "with_mac": sum(1 for d in devs if d.get("mac")),
            "with_product_id": sum(1 for d in devs if d.get("productKey")),
            "online": sum(1 for d in devs if d.get("status") == "online"),
            "offline": sum(1 for d in devs if d.get("status") == "offline"),
            "cloud_only": sum(1 for d in devs if d.get("status") == "cloud-only"),
        },
    }
    log.info(
        "API /api/status returning: scanning=%s, total=%d", state["scanning"], len(devs)
    )
    return jsonify(result)
    return jsonify(
        {
            "scanning": state["scanning"],
            "devices": devs,
            "last_scan": state["last_scan"],
            "log": state["log"][-40:],
            "progress": state["progress"],
            "scan_interval": SCAN_INTERVAL,
            "wizard_running": state["wizard_running"],
            "wizard_log": state["wizard_log"][-40:],
            "wizard_devices": state["wizard_devices"],
            "count": {
                "total": len(devs),
                "v33": sum(
                    1 for d in devs if str(d.get("version", "")).startswith("3.3")
                ),
                "v34": sum(
                    1 for d in devs if str(d.get("version", "")).startswith("3.4")
                ),
                "with_key": sum(1 for d in devs if d.get("localKey")),
            },
        }
    )


@app.route("/api/scan", methods=["POST", "OPTIONS"])
def api_scan():
    if request.method == "OPTIONS":
        return ("", 204)
    log.info("API /api/scan called")
    if state["scanning"]:
        return jsonify({"ok": False, "msg": "Scan already running"}), 409
    dur = SCAN_DURATION
    force_cidrs = []
    if request.is_json and request.json:
        dur = int(request.json.get("duration", SCAN_DURATION))
        raw_force = request.json.get("forceCidrs", "")
        if isinstance(raw_force, str):
            force_cidrs = [c.strip() for c in raw_force.split(",") if c.strip()]
        elif isinstance(raw_force, list):
            force_cidrs = [str(c).strip() for c in raw_force if str(c).strip()]
    valid_cidrs = []
    for c in force_cidrs:
        try:
            ipaddress.ip_network(c, strict=False)
            valid_cidrs.append(c)
        except Exception:
            _log(f"Skipping invalid CIDR: {c}", "warn")
    log.info("Starting scan with duration: %s", dur)
    threading.Thread(target=run_scan, args=(dur, valid_cidrs), daemon=True).start()
    return jsonify(
        {
            "ok": True,
            "msg": f"Scan started ({dur}s)",
            "forceCidrs": valid_cidrs,
        }
    )


@app.route("/api/device/<dev_id>/dps", methods=["GET"])
def api_device_dps(dev_id):
    try:
        dev = next(
            (
                d
                for d in state["devices"]
                if (d.get("id") == dev_id or d.get("gwId") == dev_id)
            ),
            None,
        )
        if not dev:
            return jsonify({"ok": False, "msg": "Device not found"}), 404
        if not dev.get("ip"):
            return jsonify({"ok": False, "msg": "Device is not online (missing IP)"}), 400
        if not dev.get("localKey"):
            return jsonify({"ok": False, "msg": "Missing Local Key for device"}), 400

        import tinytuya

        tdev = tinytuya.Device(
            dev_id=dev.get("id") or dev.get("gwId"),
            address=dev.get("ip"),
            local_key=dev.get("localKey"),
            version=float(dev.get("version") or 3.3),
            connection_timeout=4,
            connection_retry_limit=2,
            connection_retry_delay=1,
        )
        payload = tdev.status() or {}
        return jsonify(
            {
                "ok": True,
                "device": {
                    "id": dev.get("id") or dev.get("gwId"),
                    "name": dev.get("name", ""),
                    "ip": dev.get("ip", ""),
                    "version": dev.get("version", ""),
                },
                "payload": payload,
                "dps": payload.get("dps", {}) if isinstance(payload, dict) else {},
            }
        )
    except Exception as e:
        log.exception("api_device_dps error")
        return jsonify({"ok": False, "msg": str(e)}), 500


@app.route("/api/wizard", methods=["POST", "OPTIONS"])
def api_wizard():
    if request.method == "OPTIONS":
        return ("", 204)
    log.info("API /api/wizard called")
    if state["wizard_running"]:
        return jsonify({"ok": False, "msg": "Wizard already running"}), 409
    data = request.json or {}
    region = data.get("region", "eu")
    key = data.get("apiKey", "")
    secret = data.get("apiSecret", "")
    if not key or not secret:
        return jsonify({"ok": False, "msg": "Required: apiKey and apiSecret"}), 400
    log.info("Starting wizard with region: %s, key: %s***", region, key[:8])
    threading.Thread(target=run_wizard, args=(region, key, secret), daemon=True).start()
    return jsonify({"ok": True, "msg": "Wizard uruchomiony"})


@app.route("/api/devices")
def api_devices():
    return jsonify(state["devices"])


# Catch-all for static files - must be AFTER API routes
@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(WWW_DIR, filename)


if __name__ == "__main__":
    _load()
    threading.Thread(target=auto_scan_loop, daemon=True).start()
    log.info("Flask started on port %d", PORT)
    app.run(host="0.0.0.0", port=PORT, threaded=True)
