"use strict";
// All server text goes in via textContent / createElement / setAttribute on SVG. Never innerHTML.
const $ = (id) => document.getElementById(id);
const NS = "http://www.w3.org/2000/svg";
const FIELDS = { ticks: "p-ticks", miners: "p-miners", rate: "p-rate", latency: "p-latency",
  share: "p-share", z: "p-z", partition_len: "p-plen", trials: "p-trials" };
let csrf = "", scenarios = {}, current = null;

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function svg(tag, attrs, text) {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  if (text !== undefined) e.textContent = text;
  return e;
}

async function api(path, { method = "GET", body } = {}) {
  const headers = {};
  if (method !== "GET") headers["X-CSRF-Token"] = csrf;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const r = await fetch(path, { method, headers, credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body) });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    if (r.status === 401 && path !== "/api/login") showAuth();
    const d = data.detail;
    throw new Error(Array.isArray(d) ? d.map((x) => x.msg).join("; ") : d || "request failed (" + r.status + ")");
  }
  return data;
}

// ---- auth ------------------------------------------------------------------

function showAuth() {
  csrf = "";
  $("auth").hidden = false;
  $("app").hidden = true;
  $("logout").hidden = true;
  $("who").textContent = "";
}

async function showApp(me) {
  csrf = me.csrf;
  $("auth").hidden = true;
  $("app").hidden = false;
  $("logout").hidden = false;
  $("who").textContent = me.username;
  try {
    await Promise.all([loadScenarios(), loadRuns()]);
  } catch (e) {
    $("run-msg").textContent = e.message;
  }
}

async function authenticate(kind) {
  const msg = $("auth-msg");
  msg.textContent = "";
  try {
    const me = await api("/api/" + kind, { method: "POST", body: { username: $("u").value.trim(), password: $("p").value } });
    $("p").value = "";
    await showApp(me);
  } catch (e) {
    msg.textContent = e.message;
  }
}

$("login-form").addEventListener("submit", (e) => { e.preventDefault(); authenticate("login"); });
$("register").addEventListener("click", () => { if ($("login-form").reportValidity()) authenticate("register"); });
$("logout").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST" }); } catch (e) { /* already logged out */ }
  showAuth();
});

// ---- running scenarios -------------------------------------------------------

async function loadScenarios() {
  scenarios = await api("/api/scenarios");
  $("scenario").replaceChildren(...Object.entries(scenarios).map(([k, v]) => new Option(v.title, k)));
  applyScenario();
}

function applyScenario() {
  const key = $("scenario").value, sc = scenarios[key];
  if (!sc) return;
  $("scenario-desc").textContent = sc.description;
  for (const [k, id] of Object.entries(FIELDS)) $(id).value = sc.defaults[k];
  for (const w of document.querySelectorAll("[data-sc]")) w.hidden = !w.dataset.sc.split(" ").includes(key);
}
$("scenario").addEventListener("change", applyScenario);

$("run-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = $("run-msg");
  const body = { scenario: $("scenario").value, seed: Number($("p-seed").value) };
  for (const [k, id] of Object.entries(FIELDS)) {
    const w = $(id).closest("[data-sc]");
    if ((!w || !w.hidden) && $(id).value !== "") body[k] = Number($(id).value);
  }
  msg.textContent = "Simulating (mining is real, so give it a few seconds)...";
  try {
    const r = await api("/api/runs", { method: "POST", body });
    msg.textContent = "";
    await Promise.all([openRun(r.id), loadRuns()]);
  } catch (err) {
    msg.textContent = err.message;
  }
});

async function loadRuns() {
  const rows = await api("/api/runs");
  $("runs").replaceChildren(...rows.map((r) => {
    const li = el("li");
    const b = el("button", "link", "#" + r.id + " " + r.scenario.replace(/_/g, " ") + " (seed " + r.seed + "): height " +
      r.summary.canonical_height + ", orphan rate " + r.summary.orphan_rate);
    b.type = "button";
    b.addEventListener("click", () => openRun(r.id).catch((err) => { $("run-msg").textContent = err.message; }));
    li.append(b);
    return li;
  }));
}

async function openRun(id) {
  const [run, blocks, events] = await Promise.all([
    api("/api/runs/" + id), api("/api/runs/" + id + "/blocks"), api("/api/runs/" + id + "/events?limit=120")]);
  current = { run, blocks };
  $("result").hidden = false;
  $("export").href = "/api/runs/" + id + "/report.md";
  renderSummary(run.summary);
  drawTree(blocks);
  renderBlockTable(blocks);
  $("detail").replaceChildren(el("p", "muted", "Select a block above."));
  $("events").replaceChildren(...events.map((ev) => {
    const li = el("li");
    li.append(el("span", "pill " + ev.kind.replace(/[^a-z_]/g, ""), ev.kind.replace(/_/g, " ")), " ",
      el("strong", "", "tick " + ev.tick), " ", el("code", "", ev.node), el("p", "", ev.detail));
    return li;
  }));
  await drawNakamoto(run);
  $("result").scrollIntoView({ block: "start" });
}

function renderSummary(s) {
  const dl = $("summary");
  dl.replaceChildren();
  for (const [k, v] of Object.entries(s)) {
    if (typeof v === "object" && v !== null) continue;
    dl.append(el("dt", "", k.replace(/_/g, " ")), el("dd", "", String(v)));
  }
  if (s.trials) {
    dl.append(el("dt", "", "trials: " + s.trials.metric.replace(/_/g, " ")),
      el("dd", "", "mean " + s.trials.mean + " over " + s.trials.n + " runs (min " + s.trials.min + ", max " + s.trials.max + ")"));
  }
  $("miners").tBodies[0].replaceChildren(...s.miners.map((m) => {
    const tr = el("tr");
    for (const v of [m.name, m.power_share, m.blocks_mined, m.blocks_canonical, m.reward_share]) tr.append(el("td", "", String(v)));
    return tr;
  }));
}

// ---- fork tree -----------------------------------------------------------------

function drawTree(blocks) {
  if (blocks.length > 400) blocks = blocks.slice(0, 400);
  const pos = new Map(), lane = new Map(), taken = new Set();
  const sorted = [...blocks].sort((a, b) => a.height - b.height || a.tick - b.tick);
  for (const b of sorted) {
    let l = 0;
    if (b.status !== "canonical") {
      const pl = lane.get(b.parent);
      l = pl > 0 ? pl : 1;
      while (taken.has(b.height + ":" + l)) l++;
    }
    taken.add(b.height + ":" + l);
    lane.set(b.hash, l);
    pos.set(b.hash, { x: 30 + b.height * 46, y: 28 + l * 46 });
  }
  const maxX = Math.max(...[...pos.values()].map((p) => p.x)) + 40;
  const maxY = Math.max(...[...pos.values()].map((p) => p.y)) + 30;
  const root = svg("svg", { width: maxX, height: maxY, viewBox: "0 0 " + maxX + " " + maxY, role: "group",
    "aria-label": "Block tree, canonical chain on the top row" });
  for (const b of sorted) {
    const p = pos.get(b.hash), q = pos.get(b.parent);
    if (q) root.append(svg("line", { x1: q.x, y1: q.y, x2: p.x, y2: p.y, class: "edge " + b.status }));
  }
  for (const b of sorted) {
    const p = pos.get(b.hash);
    const g = svg("g", { class: "node " + b.status, tabindex: "0", role: "button",
      "aria-label": "block " + b.height + " by " + b.miner + ", " + b.status });
    g.append(svg("circle", { cx: p.x, cy: p.y, r: 15 }), svg("text", { x: p.x, y: p.y + 4, "text-anchor": "middle" }, b.miner),
      svg("title", {}, "height " + b.height + " " + b.hash.slice(0, 10) + " (" + b.status + ")"));
    g.addEventListener("click", () => selectBlock(b.hash));
    g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectBlock(b.hash); } });
    root.append(g);
  }
  $("tree-wrap").replaceChildren(root);
}

function renderBlockTable(blocks) {
  $("btable").tBodies[0].replaceChildren(...blocks.slice(0, 400).map((b) => {
    const tr = el("tr");
    for (const v of [b.height, b.hash.slice(0, 12), b.parent.slice(0, 12), b.miner, b.tick, b.status, b.ntx, b.known_by]) tr.append(el("td", "", String(v)));
    return tr;
  }));
}

// ---- block detail and Merkle proofs --------------------------------------------------

async function sha(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function verifyProof(txid, proof, root) {
  let cur = await sha(txid);
  for (const step of proof) cur = await sha(step.left ? step.hash + cur : cur + step.hash);
  return cur === root;
}

async function selectBlock(hash) {
  const base = "/api/runs/" + current.run.id + "/blocks/" + hash;
  const d = $("detail");
  try {
    const b = await api(base);
    const kv = el("dl", "kv");
    for (const [k, v] of [["height", b.height], ["hash", b.hash], ["parent", b.parent], ["miner", b.miner],
      ["tick", b.tick], ["status", b.status], ["known by nodes", b.known_by], ["merkle root", b.root]]) {
      kv.append(el("dt", "", k), el("dd", "mono", String(v)));
    }
    const list = el("ul", "plain");
    b.txs.forEach((t, i) => {
      const btn = el("button", "link", "#" + i + " " + t.from + " -> " + t.to + ": " + t.amount + " (nonce " + t.nonce + ")");
      btn.type = "button";
      btn.addEventListener("click", () => showProof(base, i, b.root));
      const li = el("li");
      li.append(btn);
      list.append(li);
    });
    d.replaceChildren(kv, el("h4", "", "Transactions (click one for its Merkle proof)"), list, el("div", "", ""));
    d.lastChild.id = "proof";
  } catch (err) {
    d.replaceChildren(el("p", "msg", err.message));
  }
}

async function showProof(base, index, root) {
  const box = $("proof");
  try {
    const p = await api(base + "/proof?index=" + index);
    const ok = await verifyProof(p.txid, p.proof, root);
    const ul = el("ul", "plain mono");
    p.proof.forEach((s, i) => ul.append(el("li", "", "step " + (i + 1) + ": sibling on the " + (s.left ? "left" : "right") + " " + s.hash.slice(0, 16) + "...")));
    box.replaceChildren(el("p", ok && p.valid ? "ok" : "msg",
      "tx " + p.txid.slice(0, 16) + "... " + (ok ? "verified in your browser" : "FAILED browser check") +
      " and " + (p.valid ? "by the server" : "FAILED server check") + " against the block root."), ul);
  } catch (err) {
    box.replaceChildren(el("p", "msg", err.message));
  }
}

// ---- Nakamoto chart -------------------------------------------------------------------

async function drawNakamoto(run) {
  const sec = $("nak");
  sec.hidden = run.scenario !== "double_spend";
  if (sec.hidden) return;
  const z = run.params.z, pts = await api("/api/nakamoto?z=" + z);
  const W = 400, H = 220, L = 44, B = 30;
  const x = (q) => L + (q / 0.6) * (W - L - 10), y = (p) => H - B - p * (H - B - 10);
  const root = svg("svg", { width: W, height: H, viewBox: "0 0 " + W + " " + H, role: "img",
    "aria-label": "Probability of a successful double spend versus attacker hash share for " + z + " confirmations" });
  for (const t of [0, 0.25, 0.5, 0.75, 1]) {
    root.append(svg("line", { x1: L, x2: W - 10, y1: y(t), y2: y(t), class: "grid" }), svg("text", { x: L - 6, y: y(t) + 4, "text-anchor": "end", class: "tick" }, String(t)));
  }
  for (const q of [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6]) root.append(svg("text", { x: x(q), y: H - 10, "text-anchor": "middle", class: "tick" }, String(q)));
  root.append(svg("polyline", { points: pts.map((p) => x(p.q) + "," + y(p.p)).join(" "), class: "curve" }));
  root.append(svg("line", { x1: x(run.params.share), x2: x(run.params.share), y1: 10, y2: H - B, class: "mark" }));
  $("chart").replaceChildren(root);
}

api("/api/me").then(showApp, showAuth);
