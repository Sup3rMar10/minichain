"""MiniChain API. Local only: meant for 127.0.0.1:8001, talks to nobody."""
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from typing import Literal, Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import db
from engine import net
from engine.chain import merkle_proof, txid, verify_proof

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "web")
COOKIE = "mc_session"
TTL = 8 * 3600
MAX_BODY = 16 * 1024
MAX_WORK = 600       # ticks * rate * trials: rough cap on blocks mined per request
ORIGINS = ["http://localhost:8001", "http://127.0.0.1:8001"]
HASH = "^[0-9a-f]{64}$"
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; "
       "form-action 'self'; frame-ancestors 'none'")

with open(os.path.join(HERE, "fixtures", "scenarios.json"), encoding="utf-8") as fh:
    SCENARIOS = json.load(fh)

ph = PasswordHasher()
DUMMY = ph.hash("not-a-real-password")
db.init()

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1"])
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_credentials=True,
                   allow_methods=["GET", "POST"], allow_headers=["Content-Type", "X-CSRF-Token"])


@app.middleware("http")
async def harden(request: Request, call_next):
    size = request.headers.get("content-length", "0")
    if size.isascii() and size.isdigit() and int(size) > MAX_BODY:
        return JSONResponse({"detail": "payload too large"}, status_code=413)
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


class Creds(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{3,32}$")
    password: str = Field(min_length=10, max_length=128)


class RunIn(BaseModel):
    scenario: Literal["honest", "partition", "double_spend", "selfish_mining"]
    seed: int = Field(1, ge=0, le=2**31 - 1)
    ticks: Optional[int] = Field(None, ge=50, le=800)
    miners: Optional[int] = Field(None, ge=3, le=8)
    rate: Optional[float] = Field(None, ge=0.02, le=0.2)
    latency: Optional[int] = Field(None, ge=1, le=8)
    share: Optional[float] = Field(None, ge=0.05, le=0.6)
    z: Optional[int] = Field(None, ge=1, le=8)
    partition_len: Optional[int] = Field(None, ge=5, le=300)
    trials: Optional[int] = Field(None, ge=1, le=10)


# ---- auth plumbing -------------------------------------------------------

_hits = defaultdict(deque)


def throttle(key, limit, window=60):
    q, now = _hits[key], time.monotonic()
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(429, "too many requests, wait a minute", headers={"Retry-After": str(window)})
    q.append(now)


def ip_of(request: Request):
    return request.client.host if request.client else "?"


def digest(tok):
    return hashlib.sha256(tok.encode()).hexdigest()


def open_session(c, uid, response):
    tok, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    c.execute("DELETE FROM sessions WHERE expires_at < ?", (int(time.time()),))
    c.execute("INSERT INTO sessions(token_hash, user_id, csrf, expires_at) VALUES(?,?,?,?)",
              (digest(tok), uid, csrf, int(time.time()) + TTL))
    # No Secure flag on purpose: this only ever runs on plain-http localhost.
    response.set_cookie(COOKIE, tok, max_age=TTL, httponly=True, samesite="strict", path="/")
    return csrf


def current(request: Request):
    tok, row = request.cookies.get(COOKIE), None
    if tok:
        with db.conn() as c:
            row = c.execute("SELECT u.id, u.username, s.csrf, s.expires_at FROM sessions s "
                            "JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?", (digest(tok),)).fetchone()
    if not row or row["expires_at"] < time.time():
        raise HTTPException(401, "not logged in")
    return dict(row)


def mutating(request: Request, user=Depends(current)):
    sent = request.headers.get("x-csrf-token", "")
    if not hmac.compare_digest(sent.encode(), user["csrf"].encode()):
        raise HTTPException(403, "bad CSRF token")
    origin = request.headers.get("origin")
    if origin and origin not in ORIGINS:
        raise HTTPException(403, "bad origin")
    return user


@app.post("/api/register")
def register(body: Creds, request: Request, response: Response):
    throttle("auth:" + ip_of(request), 8)
    with db.conn() as c:
        try:
            uid = c.execute("INSERT INTO users(username, pw_hash, created_at) VALUES(?,?,?)",
                            (body.username, ph.hash(body.password), db.now())).lastrowid
        except sqlite3.IntegrityError:
            raise HTTPException(409, "username taken")
        csrf = open_session(c, uid, response)
    return {"username": body.username, "csrf": csrf}


@app.post("/api/login")
def login(body: Creds, request: Request, response: Response):
    throttle("auth:" + ip_of(request), 8)
    with db.conn() as c:
        u = c.execute("SELECT id, pw_hash FROM users WHERE username = ?", (body.username,)).fetchone()
        try:
            ph.verify(u["pw_hash"] if u else DUMMY, body.password)
            ok = u is not None
        except (VerificationError, InvalidHashError):
            ok = False
        if not ok:
            raise HTTPException(401, "wrong username or password")
        csrf = open_session(c, u["id"], response)
    return {"username": body.username, "csrf": csrf}


@app.post("/api/logout")
def logout(request: Request, response: Response, user=Depends(mutating)):
    with db.conn() as c:
        c.execute("DELETE FROM sessions WHERE token_hash = ?", (digest(request.cookies[COOKIE]),))
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.get("/api/me")
def me(user=Depends(current)):
    return {"username": user["username"], "csrf": user["csrf"]}


# ---- runs ----------------------------------------------------------------

@app.get("/api/scenarios")
def scenarios(user=Depends(current)):
    return {k: {"title": v["title"], "description": v["description"], "defaults": {**net.FULL, **v["defaults"]}}
            for k, v in SCENARIOS.items()}


@app.post("/api/runs")
def create_run(body: RunIn, user=Depends(mutating)):
    throttle(f"run:{user['id']}", 10)
    p = {**net.FULL, **SCENARIOS[body.scenario]["defaults"],
         **body.model_dump(exclude={"scenario", "seed"}, exclude_none=True)}
    if p["ticks"] * p["rate"] * p["trials"] > MAX_WORK:
        raise HTTPException(422, "too much work: lower ticks, rate or trials")
    result = net.run_scenario(body.scenario, body.seed, p)
    with db.conn() as c:
        rid = db.save_run(c, user["id"], body.scenario, body.seed, p, result)
    return {"id": rid, "summary": result["summary"]}


def own_run(c, rid, uid):
    r = c.execute("SELECT id, scenario, seed, params, summary, created_at FROM runs WHERE id = ? AND user_id = ?",
                  (rid, uid)).fetchone()
    if not r:
        raise HTTPException(404, "run not found")
    return r


@app.get("/api/runs")
def runs(user=Depends(current)):
    with db.conn() as c:
        rows = c.execute("SELECT id, scenario, seed, summary, created_at FROM runs WHERE user_id = ? "
                         "ORDER BY id DESC LIMIT 30", (user["id"],)).fetchall()
    return [{**dict(r), "summary": json.loads(r["summary"])} for r in rows]


@app.get("/api/runs/{rid}")
def run_detail(rid: int, user=Depends(current)):
    with db.conn() as c:
        r = own_run(c, rid, user["id"])
    return {**dict(r), "params": json.loads(r["params"]), "summary": json.loads(r["summary"])}


@app.get("/api/runs/{rid}/blocks")
def run_blocks(rid: int, user=Depends(current)):
    with db.conn() as c:
        own_run(c, rid, user["id"])
        rows = c.execute("SELECT hash, parent, height, miner, tick, status, ntx, known_by FROM blocks "
                         "WHERE run_id = ? ORDER BY height, tick", (rid,)).fetchall()
    return [dict(r) for r in rows]


def block_row(c, rid, bh):
    row = c.execute("SELECT hash, parent, height, miner, tick, status, ntx, known_by, root, txs FROM blocks "
                    "WHERE run_id = ? AND hash = ?", (rid, bh)).fetchone()
    if not row:
        raise HTTPException(404, "block not found")
    return row


@app.get("/api/runs/{rid}/blocks/{bh}")
def block_detail(rid: int, bh: str = Path(..., pattern=HASH), user=Depends(current)):
    with db.conn() as c:
        own_run(c, rid, user["id"])
        row = block_row(c, rid, bh)
    txs = json.loads(row["txs"])
    return {**dict(row), "txs": [{**t, "id": txid(t)} for t in txs]}


@app.get("/api/runs/{rid}/blocks/{bh}/proof")
def block_proof(rid: int, bh: str = Path(..., pattern=HASH), index: int = Query(..., ge=0, le=64),
                user=Depends(current)):
    with db.conn() as c:
        own_run(c, rid, user["id"])
        row = block_row(c, rid, bh)
    ids = [txid(t) for t in json.loads(row["txs"])]
    if index >= len(ids):
        raise HTTPException(404, "no such transaction index")
    proof = merkle_proof(ids, index)
    return {"txid": ids[index], "root": row["root"], "proof": proof, "valid": verify_proof(ids[index], proof, row["root"])}


@app.get("/api/runs/{rid}/events")
def run_events(rid: int, limit: int = Query(120, ge=1, le=500), user=Depends(current)):
    with db.conn() as c:
        own_run(c, rid, user["id"])
        rows = c.execute("SELECT tick, kind, node, detail FROM events WHERE run_id = ? AND kind != 'mined' "
                         "ORDER BY tick, id LIMIT ?", (rid, limit)).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/runs/{rid}/reorgs")
def run_reorgs(rid: int, user=Depends(current)):
    with db.conn() as c:
        own_run(c, rid, user["id"])
        rows = c.execute("SELECT depth, COUNT(*) AS n FROM reorgs WHERE run_id = ? GROUP BY depth ORDER BY depth",
                         (rid,)).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/nakamoto")
def nakamoto(z: int = Query(..., ge=1, le=12), user=Depends(current)):
    return [{"q": q / 100, "p": round(net.nakamoto(q / 100, z), 4)} for q in range(5, 61, 5)]


def cell(v):
    return re.sub(r"[|\r\n]+", " ", str(v)).replace("<", "&lt;").replace(">", "&gt;").replace("`", "'")


@app.get("/api/runs/{rid}/report.md")
def report(rid: int, user=Depends(current)):
    with db.conn() as c:
        r = own_run(c, rid, user["id"])
        events = c.execute("SELECT tick, kind, node, detail FROM events WHERE run_id = ? AND kind != 'mined' "
                           "ORDER BY tick, id LIMIT 40", (rid,)).fetchall()
    s, p = json.loads(r["summary"]), json.loads(r["params"])
    out = [f"# MiniChain report: run {rid} ({cell(r['scenario'])})", "", f"- Seed: {r['seed']}",
           f"- Created: {r['created_at']}", f"- Parameters: `{cell(json.dumps(p))}`", "", "## Summary", ""]
    out += [f"- {cell(k.replace('_', ' '))}: {cell(v)}" for k, v in s.items() if not isinstance(v, (list, dict))]
    if "trials" in s:
        t = s["trials"]
        out.append(f"- trials: {t['n']} runs, {cell(t['metric'])} mean {t['mean']} (min {t['min']}, max {t['max']})")
    out += ["", "## Miners", "", "| Miner | Hash share | Mined | On chain | Reward share |", "|---|---|---|---|---|"]
    out += [f"| {cell(m['name'])} | {m['power_share']} | {m['blocks_mined']} | {m['blocks_canonical']} | {m['reward_share']} |"
            for m in s["miners"]]
    out += ["", "## Key events", ""]
    out += [f"- tick {e['tick']} [{cell(e['kind'])}] {cell(e['node'])}: {cell(e['detail'])}" for e in events] or ["- none"]
    out += ["", "_Toy simulation: results illustrate mechanisms, not real networks._", ""]
    return PlainTextResponse("\n".join(out), media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="minichain-run-{rid}.md"'})


# ---- frontend ------------------------------------------------------------

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(WEB, "index.html"))


app.mount("/static", StaticFiles(directory=WEB), name="static")
