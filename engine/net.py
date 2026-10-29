"""Simulated network and scenarios. Time is a tick counter; messages arrive after random latency.

Mining is real but cheap (low-difficulty hashing); which miner wins each round is drawn by hash power.
Nothing here opens a socket.
"""
import heapq
import json
import math
import os
import random
from collections import Counter

from engine.chain import Node, genesis, make_tx, txid

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures")
FULL = {"ticks": 300, "miners": 5, "rate": 0.1, "latency": 3, "share": 0.3, "z": 3, "partition_len": 80, "trials": 1}
SETTLE = 25      # quiet ticks at the end so in-flight messages land
TX_RATE = 0.3    # chance per tick that a wallet bot submits a payment


def load_genesis():
    with open(os.path.join(FIXTURES, "genesis.json"), encoding="utf-8") as fh:
        d = json.load(fh)
    return d["alloc"], d["bots"]


def nakamoto(q, z):
    """Probability an attacker with hash share q ever overtakes a payment buried under z blocks."""
    p = 1 - q
    if q >= p:
        return 1.0
    lam = z * q / p
    s = 1.0
    for k in range(z + 1):
        s -= math.exp(-lam) * lam ** k / math.factorial(k) * (1 - (q / p) ** (z - k))
    return s


class Net:
    def __init__(self, seed, names, power, rate, latency, alloc, bots):
        self.rng = random.Random(seed)
        self.names, self.power, self.rate, self.latency, self.bots = names, power, rate, latency, bots
        gen = genesis(alloc)
        self.nodes = {n: Node(n, gen, alloc) for n in names}
        self.strats = {n: Honest() for n in names}
        self.ref = names[0]
        self.heap, self.seq = [], 0
        self.groups, self.held = None, []
        self.events, self.reorgs = [], []
        self.mined, self.published = {}, set()

    def log(self, tick, kind, node, detail):
        if len(self.events) < 4000:
            self.events.append({"tick": tick, "kind": kind, "node": node, "detail": detail})

    def send(self, tick, src, dst, kind, payload):
        self.seq += 1
        heapq.heappush(self.heap, (tick + self.rng.randint(1, self.latency), self.seq, src, dst, kind, payload))

    def broadcast(self, tick, src, kind, payload):
        if kind == "block":
            self.published.add(payload.hash)
        for dst in self.nodes:
            if dst != src:
                self.send(tick, src, dst, kind, payload)

    def handle(self, tick, node, events):
        for e in events:
            if e["kind"] == "reorg":
                self.reorgs.append({"tick": tick, "node": node.name, "depth": e["depth"], "old": e["old"], "new": e["new"]})
                if node.name == self.ref or e["depth"] >= 2:
                    self.log(tick, "reorg", node.name, f"rolled back {e['depth']} block(s): {e['old'][:8]} -> {e['new'][:8]}")
            elif e["kind"] == "reject":
                self.log(tick, "reject", node.name, e["detail"])

    def deliver_due(self, tick):
        while self.heap and self.heap[0][0] <= tick:
            _, _, src, dst, kind, payload = heapq.heappop(self.heap)
            if self.groups and self.groups[src] != self.groups[dst]:
                self.held.append((src, dst, kind, payload))
                continue
            node = self.nodes[dst]
            if kind == "tx":
                node.add_tx(payload)
            else:
                self.handle(tick, node, node.receive_block(payload, tick))
                self.strats[dst].on_block(self, node, payload, tick)

    def split(self, tick, groups):
        self.groups = {n: i for i, g in enumerate(groups) for n in g}
        self.log(tick, "partition", "*", "network split: " + " | ".join(",".join(g) for g in groups))

    def heal(self, tick):
        held, self.held, self.groups = self.held, [], None
        self.log(tick, "heal", "*", f"partition healed, {len(held)} held messages released")
        for src, dst, kind, payload in held:
            self.send(tick, src, dst, kind, payload)

    def bot_tx(self, tick):
        node = self.nodes[self.rng.choice(self.names)]
        st = node.states[node.tip]
        sender = self.rng.choice(self.bots)
        pending = [x for x in node.mempool.values() if x["from"] == sender]
        amount = self.rng.randint(1, 15)
        if st.bal.get(sender, 0) - sum(x["amount"] for x in pending) < amount:
            return
        to = self.rng.choice([a for a in self.bots if a != sender])
        tx = make_tx(sender, to, amount, st.nonce.get(sender, 0) + len(pending))
        if node.add_tx(tx):
            self.broadcast(tick, node.name, "tx", tx)

    def tick(self, t, mine, bots):
        self.deliver_due(t)
        if bots and self.rng.random() < TX_RATE:
            self.bot_tx(t)
        for name, strat in self.strats.items():
            strat.on_tick(self, self.nodes[name], t)
        if mine and self.rng.random() < self.rate:
            name = self.rng.choices(self.names, [self.power[n] for n in self.names])[0]
            self.strats[name].found(self, self.nodes[name], t)


class Honest:
    def found(self, net, node, t):
        b = node.build_block(t)
        net.mined[b.hash] = b
        net.handle(t, node, node.receive_block(b, t))
        net.broadcast(t, node.name, "block", b)
        net.log(t, "mined", node.name, f"h={b.header['height']} {b.hash[:8]}")

    def on_block(self, net, node, b, t):
        pass

    def on_tick(self, net, node, t):
        pass


class DoubleSpender(Honest):
    """Pays a merchant on the public chain, mines a private fork holding a conflicting payment,
    and publishes the fork once the merchant has seen z confirmations (if it is heavier by then)."""

    def __init__(self, z, start, give_up=6):
        self.z, self.start, self.give_up = z, start, give_up
        self.mode, self.private, self.base = "idle", [], None
        self.t1 = self.t2 = self.released = None

    def found(self, net, node, t):
        if self.mode != "private":
            return super().found(net, node, t)
        b = node.build_block(t, self.private[-1].hash if self.private else self.base)
        net.mined[b.hash] = b
        self.private.append(b)
        net.handle(t, node, node.receive_block(b, t))
        net.log(t, "withheld", node.name, f"private h={b.header['height']} {b.hash[:8]}")

    def on_tick(self, net, node, t):
        ref = net.nodes[net.ref]
        if self.mode == "idle" and t >= self.start:
            n = ref.states[ref.tip].nonce.get("mallory", 0)
            pay, conflict = make_tx("mallory", "merchant", 400, n), make_tx("mallory", "accomplice", 400, n)
            self.t1, self.t2 = txid(pay), txid(conflict)
            node.banned.add(self.t1)
            node.mempool[self.t2] = conflict
            self.base, self.mode = node.tip, "private"
            for dst in net.nodes:
                if dst != node.name:
                    net.send(t, node.name, dst, "tx", pay)
            net.log(t, "double_spend_start", node.name, f"paid merchant in {self.t1[:8]}, conflicting {self.t2[:8]} kept private")
        elif self.mode == "private":
            if self.released is None and ref.confirmations(self.t1) >= self.z:
                self.released = t
                net.log(t, "goods_released", net.ref, f"merchant saw {self.z} confirmation(s) of {self.t1[:8]}")
            if self.released is None or not self.private:
                return
            top = self.private[-1]
            if node.work[top.hash] > ref.work[ref.tip]:
                for b in self.private:
                    net.broadcast(t, node.name, "block", b)
                net.log(t, "attack_published", node.name, f"{len(self.private)} private block(s) released")
                self.mode = "done"
            elif ref.height(ref.tip) - top.header["height"] >= self.give_up:
                net.log(t, "attack_abandoned", node.name, "private fork fell too far behind")
                self.mode = "done"


class Selfish(Honest):
    """Simplified Eyal-Sirer selfish mining: hold blocks back, reveal just enough to stay ahead."""

    def __init__(self):
        self.priv, self.fork_h, self.pub_h, self.racing = [], 0, 0, False

    def found(self, net, node, t):
        if self.racing:
            self.racing = False  # the tie is on the network, so publishing at once wins it
            return super().found(net, node, t)
        b = node.build_block(t, self.priv[-1].hash if self.priv else node.tip)
        if not self.priv:
            self.fork_h = b.header["height"] - 1
        self.priv.append(b)
        net.mined[b.hash] = b
        net.handle(t, node, node.receive_block(b, t))
        net.log(t, "withheld", node.name, f"private h={b.header['height']} {b.hash[:8]}")

    def on_block(self, net, node, b, t):
        if b.header["miner"] == node.name:
            return
        self.pub_h = max(self.pub_h, b.header["height"])
        if not self.priv:
            return
        lead = self.fork_h + len(self.priv) - self.pub_h
        if lead < 0:
            self.priv = []
        elif lead <= 1:
            for x in self.priv:
                net.broadcast(t, node.name, "block", x)
            net.log(t, "selfish_publish", node.name, f"released {len(self.priv)} block(s), lead was {lead}")
            self.racing, self.priv = lead == 0, []
        else:
            x = self.priv.pop(0)
            self.fork_h += 1
            net.broadcast(t, node.name, "block", x)


def summarize(net, scenario, p, strat):
    ref = net.nodes[net.ref]
    canon = ref.chain()
    cset = set(canon)
    known = Counter(bh for n in net.nodes.values() for bh in n.blocks)

    def row(b, status):
        hd = b.header
        return {"hash": b.hash, "parent": hd["parent"], "height": hd["height"], "miner": hd["miner"], "tick": hd["tick"],
                "status": status, "ntx": len(b.txs), "known_by": known[b.hash], "root": hd["root"], "txs": b.txs}

    blocks = [row(ref.blocks[canon[0]], "canonical")]
    for bh, b in net.mined.items():
        blocks.append(row(b, "canonical" if bh in cset else "orphan" if bh in net.published else "withheld"))
    mined, onchain = Counter(), Counter()
    for r in blocks[1:]:
        mined[r["miner"]] += 1
        onchain[r["miner"]] += r["status"] == "canonical"
    height = len(canon) - 1
    total_power = sum(net.power.values())
    ref_reorgs = [r for r in net.reorgs if r["node"] == net.ref]
    orphans = sum(r["status"] == "orphan" for r in blocks)
    summary = {
        "nodes": len(net.names), "ticks": p["ticks"], "blocks_mined": len(net.mined), "canonical_height": height,
        "orphans": orphans, "withheld": sum(r["status"] == "withheld" for r in blocks),
        "orphan_rate": round(orphans / max(1, len(net.mined)), 3),
        "reorgs_seen_by_observer": len(ref_reorgs), "deepest_reorg": max((r["depth"] for r in ref_reorgs), default=0),
        "txs_confirmed": sum(r["ntx"] - 1 for r in blocks if r["status"] == "canonical" and r["height"] > 0),
        "miners": [{"name": n, "power_share": round(net.power[n] / total_power, 3), "blocks_mined": mined[n],
                    "blocks_canonical": onchain[n], "reward_share": round(onchain[n] / height, 3) if height else 0}
                   for n in net.names],
    }
    metric, name = summary["orphan_rate"], "orphan_rate"
    if scenario == "double_spend":
        ids = {tid for bh in canon for tid in ref.blocks[bh].ids}
        if strat.t1 is None:
            outcome = "not_attempted"
        elif strat.released is not None and strat.t2 in ids:
            outcome = "double_spent"
        elif strat.t1 in ids:
            outcome = "attack_failed"
        else:
            outcome = "inconclusive"
        summary.update({"attacker_share": p["share"], "confirmations_required": p["z"], "goods_released_tick": strat.released,
                        "outcome": outcome, "nakamoto_probability": round(nakamoto(p["share"], p["z"]), 3)})
        metric, name = float(outcome == "double_spent"), "double_spend_success_rate"
    elif scenario == "selfish_mining":
        mine = summary["miners"][-1]
        summary.update({"attacker_share": p["share"], "attacker_revenue_share": mine["reward_share"],
                        "gain_over_fair_share": round(mine["reward_share"] - mine["power_share"], 3)})
        metric, name = mine["reward_share"], "selfish_revenue_share"
    return {"summary": summary, "blocks": blocks, "events": net.events, "reorgs": net.reorgs,
            "metric": metric, "metric_name": name}


def simulate(scenario, seed, p):
    alloc, bots = load_genesis()
    k = p["miners"]
    names = [f"n{i}" for i in range(k)]
    power = {n: 1.0 for n in names}
    attack = scenario in ("double_spend", "selfish_mining")
    if attack:
        names.append("atk")
        power["atk"] = p["share"] * k / (1 - p["share"])
    net = Net(seed, names, power, p["rate"], p["latency"], alloc, bots)
    strat = None
    if scenario == "double_spend":
        strat = DoubleSpender(p["z"], max(10, p["ticks"] // 10))
    elif scenario == "selfish_mining":
        strat = Selfish()
    if strat:
        net.strats["atk"] = strat
    split_at = p["ticks"] // 3
    for t in range(1, p["ticks"] + 1):
        if scenario == "partition":
            if t == split_at:
                net.split(t, [names[:k // 2], names[k // 2:]])
            elif t == split_at + p["partition_len"]:
                net.heal(t)
        net.tick(t, True, True)
    if net.groups:
        net.heal(p["ticks"])
    for t in range(p["ticks"] + 1, p["ticks"] + SETTLE + 1):
        net.tick(t, False, False)
    return summarize(net, scenario, p, strat)


def run_scenario(scenario, seed, p):
    first, vals = None, []
    for i in range(p["trials"]):
        res = simulate(scenario, seed + i, p)
        vals.append(res["metric"])
        first = first or res
    if p["trials"] > 1:
        first["summary"]["trials"] = {"n": len(vals), "metric": first["metric_name"],
                                      "mean": round(sum(vals) / len(vals), 3), "min": min(vals), "max": max(vals)}
    return first
