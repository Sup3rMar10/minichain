# Threat model (local MVP)
Attackers: a hostile web page in the same browser, anything else on the LAN, a user typing silly parameters. Not in scope: deployment.
## Simulation fidelity (false confidence)
- Toy PoW, fixed difficulty, no fees, instant full-mesh gossip, one RNG: numbers illustrate mechanisms, not real networks.
- Toy signatures are HMACs with guessable labels. Never reuse any of this for real keys, wallets or consensus.
- Selfish-mining and double-spend scenarios live only inside this closed model; there is no network code to point at anything real.
## Parameter abuse / DoS
- Every parameter is range-checked; ticks x rate x trials is capped at 600, so one request mines roughly 600 blocks at most.
- Runs are rate limited to 10/min per user and execute in a worker thread, but there is no per-run timeout. Keep the caps.
- Bodies over 16 KB are rejected by Content-Length; chunked bodies are bounded only after parsing (use a proxy beyond localhost).
## XSS and injected text
- Node names, event text and tx fields all come from the engine, yet the UI treats them as untrusted: textContent and SVG setAttribute only.
- CSP is `script-src 'self'; style-src 'self'`. Markdown export escapes `< > | `` ` `` and newlines.
## Consensus-logic pitfalls modelled on purpose
- Blocks with duplicate tx ids are rejected, which closes the duplicate-leaf Merkle ambiguity that odd-length trees allow.
- Nonces give replay protection; a conflicting nonce is exactly what the double-spend scenario exploits.
## Untrusted input handling
- Parameterised SQL only; hashes in URLs must match `^[0-9a-f]{64}$`; run ids are scoped to the owning user.
- argon2 hashes, hashed session tokens, httpOnly SameSite=Strict cookie, CSRF header plus Origin check, Host and CORS locked to localhost.
- No network calls, keys, wallets or RPC anywhere.
