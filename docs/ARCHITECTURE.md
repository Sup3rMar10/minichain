# Architecture

```
 Browser: web/index.html + app.js + style.css   (textContent / SVG attributes only, CSP script-src 'self')
    |  JSON over HTTP, httpOnly SameSite=Strict cookie, X-CSRF-Token on POST
    v
 app.py  FastAPI on 127.0.0.1:8001 (Host allow-list, CORS = localhost, auth + run rate limits, argon2)
    |
    +-- engine/net.py   ticks, latency heap, partitions, strategies (Honest, DoubleSpender, Selfish)
    |        |
    |        +-- engine/chain.py   Block, Merkle tree, PoW, State, validation, Node (fork choice, mempool)
    v
 minichain.db (SQLite, parameterised queries only)  <--- sim.py seeds demo runs
```

## API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | /api/register, /api/login | none, rate limited | Create account / start session, returns CSRF token |
| POST | /api/logout | session + CSRF | End session |
| GET | /api/me | session | Current user and CSRF token |
| GET | /api/scenarios | session | Scenario titles, descriptions, default parameters |
| POST | /api/runs | session + CSRF, 10/min | Run a scenario (bounded parameters), store everything |
| GET | /api/runs, /api/runs/{id} | session | Own run history / one run with params and summary |
| GET | /api/runs/{id}/blocks | session | Every block with status canonical / orphan / withheld |
| GET | /api/runs/{id}/blocks/{hash} | session | One block with its transactions |
| GET | /api/runs/{id}/blocks/{hash}/proof?index= | session | Merkle proof for a transaction, verified server-side |
| GET | /api/runs/{id}/events, /reorgs | session | Event log / reorg depth histogram |
| GET | /api/nakamoto?z= | session | Double-spend probability vs attacker share |
| GET | /api/runs/{id}/report.md | session | Markdown report download |

## Database

```
users(id PK, username UNIQUE, pw_hash, created_at)
sessions(token_hash PK, user_id FK, csrf, expires_at)          -- only a SHA-256 of the cookie token is stored
runs(id PK, user_id FK, scenario, seed, params JSON, summary JSON, created_at)
blocks(run_id FK, hash, parent, height, miner, tick, status, ntx, known_by, root, txs JSON, PK(run_id, hash))
events(id PK, run_id FK, tick, kind, node, detail)
reorgs(run_id FK, tick, node, depth, old_tip, new_tip)
```

## Notes

- Fork choice is most cumulative work, ties keep the block seen first. Each node stores the state after every block, so a reorg is a pointer swap plus a mempool fix-up.
- Mining is real hashing at 10 leading zero bits; which miner finds the next block each tick is drawn by hash power from a seeded RNG, so runs repeat exactly.
- Partitions hold cross-group messages and release them on heal, standing in for a real sync protocol.
- The observer node `n0` defines "canonical" for summaries; `atk` is the attacker when a scenario has one.
- Signatures are HMACs over a made-up secret label. They exercise validation logic, not security.
