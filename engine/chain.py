"""Toy blockchain engine: account model, Merkle trees, low-difficulty proof of work, heaviest-chain fork choice.

Signatures here are NOT cryptography. Every simulated validator can recompute an HMAC from a made-up
secret label, which is enough to exercise nonce, balance and double-spend logic and nothing more.
"""
import hashlib
import hmac
import json

BITS = 10            # block hash needs this many leading zero bits (about 1,000 hashes per block)
REWARD = 50
MAX_TX = 20          # non-coinbase transactions per block
COINBASE = "COINBASE"


def h(s):
    return hashlib.sha256(s if isinstance(s, bytes) else s.encode()).hexdigest()


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def txid(tx):
    return h(canon({k: tx[k] for k in ("from", "to", "amount", "nonce")}))


def sign(sender, tid):
    return hmac.new(f"toy-secret::{sender}".encode(), tid.encode(), hashlib.sha256).hexdigest()


def make_tx(sender, to, amount, nonce):
    tx = {"from": sender, "to": to, "amount": amount, "nonce": nonce}
    tx["sig"] = sign(sender, txid(tx))
    return tx


# ---- Merkle tree ---------------------------------------------------------

def _up(layer):
    if len(layer) % 2:
        layer = layer + [layer[-1]]
    return [h(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]


def merkle_root(ids):
    layer = [h(i) for i in ids] or [h("")]
    while len(layer) > 1:
        layer = _up(layer)
    return layer[0]


def merkle_proof(ids, index):
    layer, proof = [h(i) for i in ids], []
    while len(layer) > 1:
        if len(layer) % 2:
            layer = layer + [layer[-1]]
        sib = index ^ 1
        proof.append({"hash": layer[sib], "left": sib < index})
        layer, index = _up(layer), index // 2
    return proof


def verify_proof(tid, proof, root):
    cur = h(tid)
    for step in proof:
        cur = h(step["hash"] + cur) if step["left"] else h(cur + step["hash"])
    return cur == root


# ---- blocks and state ----------------------------------------------------

class Block:
    __slots__ = ("header", "txs", "hash", "ids")

    def __init__(self, header, txs):
        self.header, self.txs = header, txs
        self.hash = h(canon(header))
        self.ids = [txid(t) for t in txs]


def meets_target(bhash):
    return int(bhash, 16) >> (256 - BITS) == 0


def genesis(alloc):
    return Block({"height": 0, "parent": "0" * 64, "root": merkle_root([]), "miner": "GENESIS",
                  "tick": 0, "nonce": 0, "alloc": h(canon(alloc))}, [])


class State:
    __slots__ = ("bal", "nonce")

    def __init__(self, bal=None, nonce=None):
        self.bal, self.nonce = dict(bal or {}), dict(nonce or {})

    def copy(self):
        return State(self.bal, self.nonce)


def check_tx(st, tx):
    """Return an error string, or None if tx is valid against st."""
    try:
        sender, to, amount, nonce = tx["from"], tx["to"], tx["amount"], tx["nonce"]
        sig = tx.get("sig", "")
    except (KeyError, TypeError, AttributeError):
        return "malformed"
    if not (isinstance(sender, str) and isinstance(to, str) and isinstance(amount, int) and isinstance(nonce, int)):
        return "malformed"
    if amount <= 0:
        return "malformed"
    if sender == COINBASE:
        return "reserved sender"
    if not hmac.compare_digest(str(sig), sign(sender, txid(tx))):
        return "bad signature"
    if nonce != st.nonce.get(sender, 0):
        return "bad nonce"
    if st.bal.get(sender, 0) < amount:
        return "insufficient balance"
    return None


def apply_tx(st, tx):
    st.bal[tx["from"]] -= tx["amount"]
    st.bal[tx["to"]] = st.bal.get(tx["to"], 0) + tx["amount"]
    st.nonce[tx["from"]] = tx["nonce"] + 1


def validate_block(b, parent, pstate):
    """Return (error, new_state). Checks linkage, work, Merkle root, coinbase and every transaction."""
    hd = b.header
    if hd["height"] != parent.header["height"] + 1:
        return "bad height", None
    if not meets_target(b.hash):
        return "insufficient work", None
    if not b.txs or len(b.txs) > MAX_TX + 1:
        return "bad tx count", None
    if len(set(b.ids)) != len(b.ids):
        return "duplicate tx", None  # also closes the duplicate-leaf Merkle ambiguity
    if hd["root"] != merkle_root(b.ids):
        return "bad merkle root", None
    cb = b.txs[0]
    if (cb.get("from") != COINBASE or cb.get("amount") != REWARD or cb.get("nonce") != hd["height"]
            or cb.get("to") != hd["miner"]):
        return "bad coinbase", None
    st = pstate.copy()
    st.bal[cb["to"]] = st.bal.get(cb["to"], 0) + REWARD
    for t in b.txs[1:]:
        err = check_tx(st, t)
        if err:
            return f"tx {txid(t)[:8]}: {err}", None
        apply_tx(st, t)
    return None, st


class Node:
    """One simulated full node: block tree, per-block state, mempool, heaviest-chain fork choice."""

    def __init__(self, name, gen, alloc):
        self.name = name
        self.blocks = {gen.hash: gen}
        self.states = {gen.hash: State(alloc)}
        self.work = {gen.hash: 0}
        self.index = {}       # txid -> hashes of blocks containing it
        self.orphans = {}     # missing parent hash -> blocks waiting for it
        self.mempool = {}
        self.banned = set()   # txids this node refuses (used by the attacker)
        self.tip = gen.hash

    def height(self, bh):
        return self.blocks[bh].header["height"]

    def chain(self, tip=None):
        out, cur = [], tip or self.tip
        while True:
            out.append(cur)
            blk = self.blocks[cur]
            if blk.header["height"] == 0:
                return out[::-1]
            cur = blk.header["parent"]

    def _ancestor(self, a, b):
        while a != b:
            if self.height(a) >= self.height(b):
                a = self.blocks[a].header["parent"]
            else:
                b = self.blocks[b].header["parent"]
        return a

    def confirmations(self, tid):
        for bh in self.index.get(tid, ()):
            if self._ancestor(self.tip, bh) == bh:
                return self.height(self.tip) - self.height(bh) + 1
        return 0

    def add_tx(self, tx):
        try:
            tid = txid(tx)
        except (KeyError, TypeError):
            return False
        if tid in self.mempool or tid in self.banned:
            return False
        if check_tx(self.states[self.tip], tx) in ("malformed", "bad signature", "reserved sender"):
            return False
        self.mempool[tid] = tx
        return True

    def select(self, parent):
        st, picked = self.states[parent].copy(), []
        for tx in sorted(self.mempool.values(), key=lambda t: (t["from"], t["nonce"])):
            if len(picked) == MAX_TX:
                break
            if check_tx(st, tx) is None:
                apply_tx(st, tx)
                picked.append(tx)
        return picked

    def build_block(self, tick, parent=None):
        parent = parent or self.tip
        height = self.height(parent) + 1
        txs = [{"from": COINBASE, "to": self.name, "amount": REWARD, "nonce": height, "sig": ""}] + self.select(parent)
        header = {"height": height, "parent": parent, "root": merkle_root([txid(t) for t in txs]),
                  "miner": self.name, "tick": tick, "nonce": 0}
        while not meets_target(h(canon(header))):
            header["nonce"] += 1
        return Block(dict(header), txs)

    def receive_block(self, b, tick):
        """Validate and attach b (and any orphans it unlocks). Returns reorg/reject events."""
        ev = []
        if b.hash in self.blocks:
            return ev
        if b.header["parent"] not in self.blocks:
            self.orphans.setdefault(b.header["parent"], []).append(b)
            return ev
        queue = [b]
        while queue:
            cur = queue.pop()
            if cur.hash in self.blocks:
                continue
            parent = self.blocks[cur.header["parent"]]
            err, st = validate_block(cur, parent, self.states[parent.hash])
            if err:
                ev.append({"kind": "reject", "detail": f"{cur.hash[:8]} from {cur.header['miner']}: {err}"})
                continue
            self._accept(cur, st, ev)
            queue.extend(self.orphans.pop(cur.hash, []))
        return ev

    def _accept(self, b, st, ev):
        self.blocks[b.hash], self.states[b.hash] = b, st
        self.work[b.hash] = self.work[b.header["parent"]] + 2 ** BITS
        for tid in b.ids[1:]:
            self.index.setdefault(tid, []).append(b.hash)
        if self.work[b.hash] <= self.work[self.tip]:
            return  # ties keep the block seen first
        old, self.tip = self.tip, b.hash
        anc = self._ancestor(old, b.hash)
        if b.header["parent"] != old:
            ev.append({"kind": "reorg", "depth": self.height(old) - self.height(anc), "old": old, "new": b.hash})
        self._refresh_mempool(old, b.hash, anc)

    def _refresh_mempool(self, old, new, anc):
        def path(tip):
            out = []
            while tip != anc:
                out.append(self.blocks[tip])
                tip = self.blocks[tip].header["parent"]
            return out

        gone = {tid for blk in path(new) for tid in blk.ids[1:]}
        for blk in path(old):
            for tid, tx in zip(blk.ids[1:], blk.txs[1:]):
                if tid not in gone and tid not in self.banned:
                    self.mempool.setdefault(tid, tx)
        for tid in gone:
            self.mempool.pop(tid, None)
