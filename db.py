"""SQLite helpers shared by the API and sim.py."""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = os.environ.get("MC_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "minichain.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scenario TEXT NOT NULL, seed INTEGER NOT NULL, params TEXT NOT NULL, summary TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS blocks(
  run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE, hash TEXT NOT NULL, parent TEXT NOT NULL,
  height INTEGER NOT NULL, miner TEXT NOT NULL, tick INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('canonical','orphan','withheld')),
  ntx INTEGER NOT NULL, known_by INTEGER NOT NULL, root TEXT NOT NULL, txs TEXT NOT NULL,
  PRIMARY KEY(run_id, hash));
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  tick INTEGER NOT NULL, kind TEXT NOT NULL, node TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reorgs(
  run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE, tick INTEGER NOT NULL, node TEXT NOT NULL,
  depth INTEGER NOT NULL, old_tip TEXT NOT NULL, new_tip TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id, tick);
CREATE INDEX IF NOT EXISTS idx_blocks_run ON blocks(run_id, height);
"""


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init():
    with conn() as c:
        c.executescript(SCHEMA)


def save_run(c, uid, scenario, seed, params, res):
    rid = c.execute("INSERT INTO runs(user_id, scenario, seed, params, summary, created_at) VALUES(?,?,?,?,?,?)",
                    (uid, scenario, seed, json.dumps(params), json.dumps(res["summary"]), now())).lastrowid
    c.executemany("INSERT INTO blocks(run_id, hash, parent, height, miner, tick, status, ntx, known_by, root, txs) "
                  "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                  [(rid, b["hash"], b["parent"], b["height"], b["miner"], b["tick"], b["status"], b["ntx"],
                    b["known_by"], b["root"], json.dumps(b["txs"])) for b in res["blocks"]])
    c.executemany("INSERT INTO events(run_id, tick, kind, node, detail) VALUES(?,?,?,?,?)",
                  [(rid, e["tick"], e["kind"], e["node"], e["detail"]) for e in res["events"]])
    c.executemany("INSERT INTO reorgs(run_id, tick, node, depth, old_tip, new_tip) VALUES(?,?,?,?,?,?)",
                  [(rid, r["tick"], r["node"], r["depth"], r["old"], r["new"]) for r in res["reorgs"]])
    return rid
