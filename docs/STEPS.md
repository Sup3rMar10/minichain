# Build steps and interview notes

## Steps
1. Write `engine/chain.py`: canonical hashing, Merkle root and proofs, PoW target, account state with nonces, block validation, and a `Node` with heaviest-chain fork choice and a mempool.
2. Write `engine/net.py`: tick loop, latency heap, partitions that hold and release messages, wallet bots, and three strategies (honest, double spender, selfish miner).
3. Add summaries: orphan rate, reorg depth, per-miner reward share versus hash share, and the Nakamoto probability for comparison.
4. Add `db.py` and `app.py`: argon2 login, httpOnly session cookie, CSRF, localhost-only CORS and hosts, rate limits, bounded parameters, parameterised SQL.
5. Build `web/`: scenario form, summary, SVG fork tree, block detail with in-browser Merkle proof verification, event feed, Nakamoto chart, Markdown export.
6. Write `sim.py` to seed demo runs, then the docs. Nothing has been executed yet: first run is `pip install -r requirements.txt`, `python sim.py`, `uvicorn app:app --host 127.0.0.1 --port 8001`.

## Interview Q&A

**1. What does a Merkle tree give a blockchain, and how does a proof work?**
It commits to every transaction in a block with one 32-byte root in the header. To prove a transaction is included you send the sibling hash at each level (log2 n hashes); the verifier hashes upward and compares with the root, which is how light clients avoid downloading blocks. Odd levels duplicate the last node, so reject duplicate transactions or the tree has ambiguous encodings.

**2. How does proof of work pick the canonical chain?**
Nodes follow the valid chain with the most cumulative work, not simply the longest one. Work per block is roughly 2^difficulty, so a chain with fewer high-difficulty blocks can beat a longer easy one. Ties are broken by first seen, which is why propagation delay matters.

**3. What causes forks and reorgs, and how many confirmations are enough?**
Two miners find blocks before hearing of each other (natural orphans), or the network partitions, or an attacker publishes a heavier private branch. A reorg rolls back the lighter branch and returns its transactions to the mempool. Each confirmation reduces reversal odds exponentially for a minority attacker, so the answer depends on attacker share and the value at risk, not a magic number like 6.

**4. How does a 51% or double-spend attack work, and what does Nakamoto's formula say?**
Pay a merchant, mine a conflicting branch in secret, publish it after the goods ship. The attacker's catch-up is a random walk; with share q < 0.5 the success probability falls exponentially in confirmations z, and at q >= 0.5 it reaches 1. The simulator draws many trials and compares the empirical rate with the formula.

**5. What is selfish mining?**
A miner withholds found blocks and publishes just enough to orphan honest work, earning more than its hash share (profitable above about 1/3 in the original model, lower if it wins propagation races). It matters because it breaks the "honest majority is enough" intuition. Mitigations include uniform tie-breaking and faster propagation.

**6. Account model vs UTXO model, and why do nonces exist?**
Accounts keep balances in state and are simple to program; UTXOs spend whole outputs, parallelise well and are easier to reason about for privacy. Account chains need per-sender nonces so a signed transfer cannot be replayed and so ordering is deterministic; the double-spend here is two transactions sharing one nonce.

**7. Probabilistic vs deterministic finality?**
PoW finality is probabilistic: reversal gets unlikely but never impossible. BFT-style proof-of-stake protocols finalise when a supermajority signs, giving deterministic finality at the cost of liveness assumptions and stake-slashing design. Pick based on whether you can wait out a partition.

**8. What would you add for production, and what does this toy hide?**
Real p2p gossip and sync, real signatures (ECDSA/Ed25519) with replay protection, difficulty retargeting, a fee market and block size limits, persistent storage, DoS-resistant mempool rules, and checkpointing. Test with adversarial network simulators and fuzzing instead of one seeded RNG, and audit against known client bugs before trusting any numbers.
