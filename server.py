
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
