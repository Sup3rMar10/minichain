# MiniChain Lab
> ⛓️ A blockchain small enough to fit in your head, and just broken enough to be interesting.
## What it does
Runs a toy proof-of-work network (real Merkle trees and mining, fake keys, no sockets) and plays out forks, partitions, double spends and selfish mining.
## Run it
`pip install -r requirements.txt`, `python sim.py`, `uvicorn app:app --host 127.0.0.1 --port 8001`, then open localhost:8001 (demo / demo-pass-1234).
## Favourite scenario 🕵️
The double spend: an attacker pays a merchant, mines a secret fork, waits for the goods to ship, then publishes. The Nakamoto chart shows why z=1 is a bad idea.
## Honest disclaimer ⚠️
Never tested in production; educational MVP only. No real consensus network, signatures are HMAC stand-ins, results are one simulator's opinion. Never use it near real funds or keys. Please don't download or run it; if you do, it's entirely at your own risk.
## Things that went wrong while building this
- It was written without ever being run, so expect a typo or two on first launch.
- Mining is real hashing at tiny difficulty, so large runs are capped on purpose (see docs/THREAT_MODEL.md).

Built with too many ticks and not enough sleep. Mind the forks.
