#!/usr/bin/env python3
"""Red Flag Desk - local event server.

Run:  python server.py
Then open the address it prints on any phone or laptop on the same Wi-Fi / hotspot.
Needs only Python 3.8+ (no installs). Everything is saved to event.json next to this file.
"""
import hashlib
import json
import os
import secrets
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "event.json")
SEED = os.path.join(HERE, "seed.json")
INDEX = os.path.join(HERE, "index.html")
PORT = int(os.environ.get("PORT", "8000"))
LOCK = threading.RLock()
MAX_TEAMS = 200


def now_ms():
    return int(time.time() * 1000)


def fresh_state():
    return dict(phase="setup", stage=0, window=0, allocOpen=False, phaseAt=0,
                bulletins=[], reveal=0, endedR1=False, endedR2=False)


def load():
    if os.path.exists(DATA):
        with open(DATA, encoding="utf-8") as f:
            return json.load(f)
    with open(SEED, encoding="utf-8") as f:
        seed = json.load(f)
    return dict(v=1, config=seed["config"], profiles=seed["profiles"], vault=seed["vault"],
                state=fresh_state(), released={}, teams={}, locks={}, marks={}, intel={},
                orgPin=None, orgTokens=[])


DB = load()
if os.environ.get("ORG_PIN"):
    DB["orgPin"] = os.environ["ORG_PIN"]
if not DB.get("orgPin"):
    DB["orgPin"] = f"{secrets.randbelow(10 ** 6):06d}"
DB.setdefault("orgTokens", [])


def save():
    DB["v"] = DB.get("v", 0) + 1
    tmp = DATA + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(DB, f, ensure_ascii=False)
    os.replace(tmp, DATA)


def order():
    return DB["config"].get("order") or [k for k in DB["vault"] if k != "bulletins"]


def pin_hash(pin, salt):
    return hashlib.sha256((salt + ":" + str(pin)).encode()).hexdigest()


class Err(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


def clean_text(v, n):
    return str(v or "").strip()[:n]


def team_public(t):
    return {k: v for k, v in t.items() if k not in ("pinHash", "salt", "tokens")}


# ---------------- scoring ----------------
def locked_flags(tid):
    lk = DB["locks"].get(tid, {})
    seen, out = set(), []
    for w in range(3):
        for f in lk.get(f"w{w}", []):
            if f["id"] in seen:
                continue
            seen.add(f["id"])
            win = w
            if tid.startswith("desk-") and isinstance(f.get("win"), int):
                win = min(w, f["win"])
            out.append(dict(f, lockWin=win))
    return out


def key_index():
    k = {}
    for cid in order():
        for f in DB["vault"].get(cid, {}).get("key", []):
            k[f["id"]] = dict(f, cid=cid)
    return k


def final_portfolio(tid):
    lk = DB["locks"].get(tid, {})
    if "portfolio" in lk:
        return lk["portfolio"]
    t = DB["teams"].get(tid, {})
    return dict(alloc=t.get("alloc", {}), rationale=t.get("rationale", {}))


def score_team(tid):
    c = DB["config"]
    mk = DB["marks"].get(tid, {})
    K = key_index()
    best, falses, unmarked = {}, 0, 0
    flags = locked_flags(tid)
    for f in flags:
        m = mk.get("flags", {}).get(f["id"])
        if not m:
            unmarked += 1
            continue
        if m == "false":
            falses += 1
            continue
        if m in K:
            mult = c["windowMult"][f["lockWin"]] if f["lockWin"] < len(c["windowMult"]) else 1
            p = c["points"].get(K[m]["diff"], 0) * mult
            best[m] = max(best.get(m, 0), p)
    intel = len(mk.get("intel", []))
    raw = sum(best.values()) + falses * c["falseAlarm"] - intel * c["intelCost"]
    forensic = max(0.0, min(40.0, raw / (c.get("fullMarksRaw") or 1) * 40))
    R = {cid: float(DB["vault"].get(cid, {}).get("outcome", {}).get("ret", 0)) for cid in order()}
    vals = list(R.values()) + [0.0]
    rmax, rmin = max(vals), min(vals)
    alloc = final_portfolio(tid).get("alloc", {})
    ret = sum(float(alloc.get(cid, 0) or 0) / 100 * R[cid] for cid in order())
    portfolio = 30 * (ret - rmin) / (rmax - rmin) if rmax > rmin else 0.0
    js = [j for j in mk.get("judges", []) if isinstance(j, (int, float))]
    rationale = max(0.0, min(30.0, sum(js) / len(js))) if js else 0.0
    return dict(raw=raw, correct=len(best), falses=falses, unmarked=unmarked, intel=intel,
                forensic=forensic, ret=ret, portfolio=portfolio, rationale=rationale,
                judged=len(js), total=forensic + portfolio + rationale, flags=len(flags))


def leaderboard():
    rows = [dict(tid=tid, name=t.get("name", "Team"), **score_team(tid)) for tid, t in DB["teams"].items()]
    rows.sort(key=lambda r: -r["total"])
    return rows


# ---------------- payloads ----------------
def public_payload():
    return dict(config=DB["config"], state=DB["state"], profiles=DB["profiles"], released=DB["released"])


def org_payload():
    return dict(vault=DB["vault"], teams={k: team_public(t) for k, t in DB["teams"].items()},
                locks=DB["locks"], marks=DB["marks"], board=leaderboard(), orgPin=DB["orgPin"],
                lan=[f"http://{ip}:{PORT}" for ip in cached_ips()])


_IPS = {"at": 0, "ips": []}


def cached_ips():
    if time.time() - _IPS["at"] > 60:
        _IPS["ips"], _IPS["at"] = lan_ips(), time.time()
    return _IPS["ips"]


def find_team_by_token(tok):
    if not tok:
        return None
    for tid, t in DB["teams"].items():
        if tok in t.get("tokens", []):
            return tid
    return None


# ---------------- team actions ----------------
def add_flag(tid, body, admin):
    s = DB["state"]
    if not admin and not (s["phase"] == "r1" and not s.get("endedR1")):
        raise Err("Flags can only be added during Round 1.")
    t = DB["teams"][tid]
    company = body.get("company")
    if company not in order():
        raise Err("Pick a company.")
    issue = clean_text(body.get("issue"), 160)
    if not issue:
        raise Err("Describe the issue.")
    if len(t.get("flags", [])) >= 80:
        raise Err("Too many flags for one team.")
    fl = dict(id=secrets.token_hex(4), company=company, issue=issue,
              evidence=clean_text(body.get("evidence"), 500), window=s.get("window", 0), at=now_ms())
    if admin and tid.startswith("desk-") and isinstance(body.get("win"), int) and 0 <= body["win"] <= 2:
        fl["win"] = body["win"]
    t.setdefault("flags", []).append(fl)


def del_flag(tid, fid, admin):
    s = DB["state"]
    t = DB["teams"][tid]
    f = next((x for x in t.get("flags", []) if x["id"] == fid), None)
    if not f:
        return
    if not admin:
        if s["phase"] != "r1" or s.get("endedR1") or f.get("window", 0) < s.get("window", 0):
            raise Err("That flag is already locked in.")
    t["flags"] = [x for x in t["flags"] if x["id"] != fid]


def set_alloc(tid, body, admin):
    s = DB["state"]
    if not admin and not (s["phase"] == "r2" and s.get("allocOpen")):
        raise Err("The allocation window is closed.")
    alloc, rat, total = {}, {}, 0
    for cid in order():
        try:
            a = int(round(float((body.get("alloc") or {}).get(cid, 0) or 0)))
        except (TypeError, ValueError):
            a = 0
        a = max(0, min(100, a))
        alloc[cid] = a
        total += a
        rat[cid] = clean_text((body.get("rationale") or {}).get(cid), 500)
    if total > 100:
        raise Err("Allocations add up to more than 100%.")
    t = DB["teams"][tid]
    t["alloc"], t["rationale"], t["allocAt"] = alloc, rat, now_ms()


def team_action(tid, body):
    act = body.get("act")
    t = DB["teams"][tid]
    if act == "flag":
        add_flag(tid, body, False)
    elif act == "delflag":
        del_flag(tid, body.get("fid"), False)
    elif act == "intel":
        s = DB["state"]
        if not (s["phase"] == "r1" and not s.get("endedR1")):
            raise Err("The intel desk is open during Round 1 only.")
        cid = body.get("company")
        if cid not in order():
            raise Err("Pick a company.")
        if cid not in t.setdefault("intelReq", []):
            t["intelReq"].append(cid)
    elif act == "alloc":
        set_alloc(tid, body, False)
    else:
        raise Err("Unknown action.")


# ---------------- organiser actions ----------------
def snapshot(w):
    for tid, t in DB["teams"].items():
        lk = DB["locks"].setdefault(tid, {})
        lk["name"] = t.get("name")
        lk[f"w{w}"] = json.loads(json.dumps(t.get("flags", [])))


def release(n):
    comps = {}
    for cid in order():
        v = DB["vault"].get(cid, {}).get("statements", {})
        if n == 1:
            comps[cid] = dict(pl=v.get("pl", []), bs=v.get("bs", []))
        elif n == 2:
            comps[cid] = dict(cf=v.get("cf", []))
        else:
            comps[cid] = dict(notes=v.get("notes", []), auditor=v.get("auditor", ""))
    DB["released"][f"s{n}"] = dict(companies=comps, at=now_ms())


def do_step(k):
    s = DB["state"]
    t = now_ms()
    if k == "briefing" and s["phase"] == "setup":
        s.update(phase="briefing", phaseAt=t)
    elif k == "r1" and s["stage"] == 0:
        release(1)
        s.update(phase="r1", stage=1, window=0, phaseAt=t, endedR1=False)
    elif k == "rel2" and s["stage"] == 1:
        snapshot(0); release(2); s.update(stage=2, window=1)
    elif k == "rel3" and s["stage"] == 2:
        snapshot(1); release(3); s.update(stage=3, window=2)
    elif k == "endr1" and s["stage"] == 3 and not s.get("endedR1"):
        snapshot(2); s.update(endedR1=True, phase="break", phaseAt=t)
    elif k == "r2" and s.get("endedR1") and s["phase"] == "break":
        s.update(phase="r2", phaseAt=t, allocOpen=True)
    elif k == "endr2" and s["phase"] == "r2":
        for tid, tm in DB["teams"].items():
            lk = DB["locks"].setdefault(tid, {})
            lk["name"] = tm.get("name")
            lk["portfolio"] = dict(alloc=dict(tm.get("alloc", {})), rationale=dict(tm.get("rationale", {})))
        s.update(endedR2=True, allocOpen=False, phase="reveal", phaseAt=t, reveal=0)
    elif k == "rv1" and s.get("endedR2") and s.get("reveal", 0) == 0:
        flags, traps = {}, {}
        for cid in order():
            vc = DB["vault"].get(cid, {})
            flags[cid] = [dict(title=f["title"], evidence=f["evidence"], diff=f["diff"], stage=f["stage"]) for f in vc.get("key", [])]
            traps[cid] = vc.get("traps", [])
        DB["released"]["reveal"] = dict(flags=flags, traps=traps)
        s["reveal"] = 1
    elif k == "rv2" and s.get("reveal") == 1:
        DB["released"]["reveal"]["outcomes"] = {cid: DB["vault"].get(cid, {}).get("outcome", dict(ret=0, story="")) for cid in order()}
        s["reveal"] = 2
    elif k == "rv3" and s.get("reveal") == 2:
        DB["released"]["reveal"]["board"] = [
            dict(name=r["name"], forensic=r["forensic"], portfolio=r["portfolio"], rationale=r["rationale"], total=r["total"], ret=r["ret"])
            for r in leaderboard()]
        s.update(reveal=3, phase="done")
    else:
        raise Err("That step isn't available right now. Refresh and check the run sheet.")


def org_action(body):
    act = body.get("act")
    s = DB["state"]
    tid = body.get("tid")
    if tid is not None and act not in ("add_team",) and tid not in DB["teams"]:
        raise Err("Team not found.")
    if act == "step":
        do_step(body.get("k"))
    elif act == "alloc_open":
        if s["phase"] != "r2":
            raise Err("Only in Round 2.")
        s["allocOpen"] = True
    elif act == "alloc_close":
        s["allocOpen"] = False
    elif act == "announce":
        b = next((x for x in DB["vault"].get("bulletins", {}).get("items", []) if x["id"] == body.get("b")), None)
        if not b:
            raise Err("Bulletin not found.")
        if not any(x["id"] == b["id"] for x in s["bulletins"]):
            s["bulletins"].append(dict(id=b["id"], company=b["company"], text=b["text"], at=now_ms()))
    elif act == "retract":
        s["bulletins"] = [x for x in s["bulletins"] if x["id"] != body.get("b")]
    elif act in ("deliver", "sell"):
        cid = body.get("company")
        intel = DB["vault"].get(cid, {}).get("intel")
        if not intel:
            raise Err("No clue for that company.")
        mk = DB["marks"].setdefault(tid, {})
        if cid not in mk.setdefault("intel", []):
            mk["intel"].append(cid)
        if act == "deliver":
            items = DB["intel"].setdefault(tid, [])
            if not any(i["cid"] == cid for i in items):
                items.append(dict(cid=cid, title=intel["title"], text=intel["text"]))
        return dict(clue=intel)
    elif act == "unsell":
        mk = DB["marks"].setdefault(tid, {})
        mk["intel"] = [c for c in mk.get("intel", []) if c != body.get("company")]
        DB["intel"][tid] = [i for i in DB["intel"].get(tid, []) if i["cid"] != body.get("company")]
    elif act == "mark":
        mk = DB["marks"].setdefault(tid, {}).setdefault("flags", {})
        v = body.get("value")
        if v:
            mk[body.get("fid")] = v
        else:
            mk.pop(body.get("fid"), None)
    elif act == "judge":
        mk = DB["marks"].setdefault(tid, {})
        j = (mk.get("judges") or [None, None]) + [None, None]
        j = j[:2]
        v = body.get("value")
        j[int(body.get("j", 0)) % 2] = None if v in (None, "") else max(0.0, min(30.0, float(v)))
        mk["judges"] = j
    elif act == "add_team":
        name = clean_text(body.get("name"), 40)
        if not name:
            raise Err("Enter a team name.")
        if len(DB["teams"]) >= MAX_TEAMS:
            raise Err("Too many teams.")
        nid = "desk-" + secrets.token_hex(3)
        DB["teams"][nid] = dict(name=name, members=clean_text(body.get("members"), 160), flags=[], alloc={}, rationale={}, intelReq=[], at=now_ms(), tokens=[])
        return dict(tid=nid)
    elif act == "del_team":
        for coll in ("teams", "locks", "marks", "intel"):
            DB[coll].pop(tid, None)
    elif act == "team_pin":
        pin = clean_text(body.get("pin"), 12)
        if len(pin) < 4:
            raise Err("PIN must be at least 4 characters.")
        t = DB["teams"][tid]
        t["salt"] = secrets.token_hex(8)
        t["pinHash"] = pin_hash(pin, t["salt"])
        t["tokens"] = []
    elif act == "flag":
        add_flag(tid, body, True)
    elif act == "delflag":
        del_flag(tid, body.get("fid"), True)
    elif act == "alloc":
        set_alloc(tid, body, True)
    elif act == "reset":
        DB["released"], DB["locks"], DB["marks"], DB["intel"] = {}, {}, {}, {}
        if body.get("all"):
            DB["teams"] = {}
        else:
            for t in DB["teams"].values():
                t.update(flags=[], alloc={}, rationale={}, intelReq=[])
                t.pop("allocAt", None)
        DB["state"] = fresh_state()
    elif act == "save_doc":
        path, val = body.get("path", ""), body.get("value")
        if not isinstance(val, dict):
            raise Err("The top level must be an object.")
        if path == "config":
            DB["config"] = val
        elif path == "profiles":
            DB["profiles"] = val
        elif path.startswith("vault/") and path[6:]:
            DB["vault"][path[6:]] = val
        else:
            raise Err("Unknown document.")
    elif act == "set_org_pin":
        pin = clean_text(body.get("pin"), 20)
        if len(pin) < 4:
            raise Err("PIN must be at least 4 characters.")
        DB["orgPin"] = pin
    else:
        raise Err("Unknown action.")
    return {}


# ---------------- HTTP ----------------
class Handler(BaseHTTPRequestHandler):
    server_version = "RedFlagDesk/1.0"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body=b"", ctype="application/json; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 400_000:
            raise Err("Request too large.", 413)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            v = json.loads(raw.decode("utf-8"))
        except Exception:
            raise Err("Bad request.")
        if not isinstance(v, dict):
            raise Err("Bad request.")
        return v

    def _is_org(self):
        tok = self.headers.get("X-Org")
        return bool(tok) and tok in DB["orgTokens"]

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            with open(INDEX, "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if u.path == "/api/sync":
            q = parse_qs(u.query)
            with LOCK:
                org = self._is_org()
                tid = find_team_by_token(self.headers.get("X-Team"))
                have = q.get("v", [""])[0]
                if have == str(DB["v"]):
                    return self._send(204)
                out = dict(v=DB["v"], now=now_ms(), role="org" if org else ("team" if tid else "public"), **public_payload())
                if org:
                    out["org"] = org_payload()
                if tid:
                    out["team"] = dict(tid=tid, **team_public(DB["teams"][tid]))
                    out["intel"] = DB["intel"].get(tid, [])
                return self._json(200, out)
        self._send(404, b'{"error":"Not found"}')

    def do_POST(self):
        u = urlparse(self.path)
        try:
            body = self._body()
            with LOCK:
                if u.path == "/api/org/login":
                    if str(body.get("pin", "")).strip() != DB["orgPin"]:
                        time.sleep(0.6)
                        raise Err("Wrong organiser PIN.", 403)
                    tok = secrets.token_urlsafe(18)
                    DB["orgTokens"] = (DB["orgTokens"] + [tok])[-30:]
                    save()
                    return self._json(200, dict(token=tok))
                if u.path == "/api/org/do":
                    if not self._is_org():
                        raise Err("Organiser login needed.", 401)
                    res = org_action(body) or {}
                    save()
                    return self._json(200, dict(ok=True, **res))
                if u.path == "/api/team/register":
                    name = clean_text(body.get("name"), 40)
                    pin = clean_text(body.get("pin"), 12)
                    if not name:
                        raise Err("Give your team a name.")
                    if len(pin) < 4:
                        raise Err("Choose a PIN of at least 4 digits.")
                    if any(t.get("name", "").lower() == name.lower() for t in DB["teams"].values()):
                        raise Err("That team name is taken. Log in instead, or pick another name.")
                    if len(DB["teams"]) >= MAX_TEAMS:
                        raise Err("Registration is full.")
                    tid = "t-" + secrets.token_hex(3)
                    salt = secrets.token_hex(8)
                    tok = secrets.token_urlsafe(18)
                    DB["teams"][tid] = dict(name=name, members=clean_text(body.get("members"), 160), flags=[], alloc={},
                                            rationale={}, intelReq=[], at=now_ms(), salt=salt,
                                            pinHash=pin_hash(pin, salt), tokens=[tok])
                    save()
                    return self._json(200, dict(token=tok))
                if u.path == "/api/team/login":
                    name = clean_text(body.get("name"), 40).lower()
                    pin = clean_text(body.get("pin"), 12)
                    for tid, t in DB["teams"].items():
                        if t.get("name", "").lower() == name and t.get("pinHash") and t["pinHash"] == pin_hash(pin, t["salt"]):
                            tok = secrets.token_urlsafe(18)
                            t["tokens"] = (t.get("tokens", []) + [tok])[-8:]
                            save()
                            return self._json(200, dict(token=tok))
                    time.sleep(0.6)
                    raise Err("Team name or PIN is wrong.", 403)
                if u.path == "/api/team/do":
                    tid = find_team_by_token(self.headers.get("X-Team"))
                    if not tid:
                        raise Err("Please log in to your team again.", 401)
                    team_action(tid, body)
                    save()
                    return self._json(200, dict(ok=True))
            raise Err("Not found.", 404)
        except Err as e:
            self._json(e.code, dict(error=str(e)))
        except Exception as e:  # keep the event running whatever happens
            print("Error:", repr(e), file=sys.stderr)
            self._json(500, dict(error="Something went wrong on the server."))


def lan_ips():
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if not ip.startswith("127."):
                ips.add(ip)
    except Exception:
        pass
    return sorted(ips)


def main():
    with LOCK:
        save()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    srv.daemon_threads = True
    line = "=" * 58
    print(line)
    print("  RED FLAG DESK is running")
    print(line)
    print(f"  On this laptop:     http://localhost:{PORT}")
    for ip in lan_ips():
        print(f"  Everyone else:      http://{ip}:{PORT}")
    print(f"  Organiser PIN:      {DB['orgPin']}")
    print("  Data is saved in event.json. Press Ctrl+C to stop.")
    print(line)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped. Your data is in event.json.")


if __name__ == "__main__":
    main()
