"""Seed the local DB: demo user plus a spread of simulated runs across all four scenarios."""
import db
from argon2 import PasswordHasher
from engine import net
import json
import os

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "scenarios.json"), encoding="utf-8") as fh:
    SCENARIOS = json.load(fh)

# (scenario, seed, overrides)
RUNS = [
    ("honest", 1, {}),
    ("honest", 2, {"latency": 6}),
    ("partition", 3, {}),
    ("partition", 4, {"partition_len": 150}),
    ("double_spend", 5, {"share": 0.1, "trials": 6}),
    ("double_spend", 6, {"share": 0.3, "trials": 6}),
    ("double_spend", 7, {"share": 0.45, "z": 2, "trials": 6}),
    ("selfish_mining", 8, {"share": 0.25, "trials": 4}),
    ("selfish_mining", 9, {"share": 0.4, "trials": 4}),
]


def main():
    db.init()
    with db.conn() as c:
        for table in ("reorgs", "events", "blocks", "runs"):
            c.execute(f"DELETE FROM {table}")
        row = c.execute("SELECT id FROM users WHERE username = ?", ("demo",)).fetchone()
        uid = row["id"] if row else c.execute(
            "INSERT INTO users(username, pw_hash, created_at) VALUES(?,?,?)",
            ("demo", PasswordHasher().hash("demo-pass-1234"), db.now())).lastrowid
        for scenario, seed, over in RUNS:
            p = {**net.FULL, **SCENARIOS[scenario]["defaults"], **over}
            db.save_run(c, uid, scenario, seed, p, net.run_scenario(scenario, seed, p))
    print(f"Seeded {len(RUNS)} runs. Log in as demo / demo-pass-1234 (local only).")


if __name__ == "__main__":
    main()
