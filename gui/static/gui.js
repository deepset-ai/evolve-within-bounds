// The GUI's page: the evolution graph, the demo terminal (live or replayed), and the scanned integrations.
// Model-written text is always inserted as text, never as HTML.
"use strict";

const $ = (selector) => document.querySelector(selector);
const SVG = "http://www.w3.org/2000/svg";

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) if (child != null) node.append(child);
  return node;
}

function svg(tag, attrs = {}, text = null) {
  const node = document.createElementNS(SVG, tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  if (text != null) node.textContent = text;
  return node;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const REDUCED_MOTION = matchMedia("(prefers-reduced-motion: reduce)").matches;
const clock = (seconds) => `${Math.floor(seconds / 60)}:${String(Math.floor(seconds % 60)).padStart(2, "0")}`; // taste-skill-ignore: minutes and seconds
const percent = (k, n) => `${Math.round((100 * k) / n)}%`;
const unit = (text) => el("span", { class: "unit", text });
// A duration in words, its units set small: "4 min 29 s".
const duration = (seconds) => {
  const [m, s] = [Math.floor(seconds / 60), Math.round(seconds % 60)];
  return m ? [String(m), unit(" min "), String(s), unit(" s")] : [String(s), unit(" s")];
};

async function post(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  const data = await response.json().catch(() => ({}));
  return { ok: response.ok, ...data };
}

// -- tabs and the Spark's status ----------------------------------------------------------------------------------

function showTab(name) {
  document.querySelectorAll(".tab-button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.id === `tab-${name}`));
  history.replaceState(null, "", `${location.search}#${name}`);
  document.body.dataset.tab = name;
  if (name === "evolution") drawChart();
}

for (const button of document.querySelectorAll(".tab-button")) {
  button.addEventListener("click", () => showTab(button.dataset.tab));
}

const spark = { live: false, busy: null };

async function refreshStatus() {
  const status = $("#status");
  try {
    const data = await (await fetch("/api/status")).json();
    spark.live = data.model && data.sandbox;
    spark.busy = data.busy;
    status.className = `status ${spark.live ? "ok" : "off"}`;
    status.textContent = spark.live ? `DGX Spark ready${data.busy ? ` · ${data.busy} running` : ""}` : "Recordings only";
    const missing = [data.model ? null : "the model server is offline", data.sandbox ? null : "the sandbox is missing"].filter(Boolean);
    status.title = spark.live ? "The DGX Spark's model server and sandbox are ready" : `On the DGX Spark, ${missing.join(" and ")}`;
  } catch {
    spark.live = false;
    status.className = "status off";
    status.textContent = "Server unreachable";
  }
  updateDemoButtons();
}

// -- 1. how the agent evolved -------------------------------------------------------------------------------------

let evolution = null;
let chartRun = 0;

async function drawChart() {
  evolution = evolution || (await (await fetch("/api/evolution")).json());
  const run = ++chartRun;
  const data = evolution;
  const chart = $("#chart");
  chart.replaceChildren();
  const [W, H, L, R, T, B] = [1000, 540, 72, 20, 34, 70];
  const [off, rr] = [9, 7]; // the two dots' offset from the version's centre, and their radius
  const versions = data.versions;
  const band = (W - L - R) / versions.length;
  const x = (i) => L + band * (i + 0.5);
  const [lo, hi] = [20, 100];
  const y = (pct) => T + (H - T - B) * (1 - (pct - lo) / (hi - lo));
  const trainPct = versions.map((v) => (100 * v.train) / data.train_pairs);
  const valPct = versions.map((v) => (100 * v.val) / data.val_pairs);

  chart.append(svg("rect", { x: L, y: T, width: band, height: H - T - B, class: "band" }));
  const focus = svg("rect", { x: L, y: T, width: band, height: H - T - B, class: "focus" });
  chart.append(focus);
  const show = (i) => {
    focus.setAttribute("x", L + band * i);
    showDetail(versions[i]);
  };
  buildDetails(data);
  const pinned = () => Math.max(0, versions.findIndex((v) => v.id === (detailPinned || data.presented.id)));
  show(pinned());
  for (let p = lo; p <= hi; p += 20) {
    chart.append(svg("line", { x1: L, y1: y(p), x2: W - R, y2: y(p), class: "grid" }));
    chart.append(svg("text", { x: L - 12, y: y(p) + 4, "text-anchor": "end" }, `${p}%`));
  }
  versions.forEach((v, i) =>
    chart.append(svg("text", { x: x(i), y: H - B + 26, "text-anchor": "middle" }, v.label)),
  );
  chart.append(svg("text", { x: L + (W - L - R) / 2, y: H - 14, "text-anchor": "middle", class: "axis-title" }, "Version written by the optimizer"));
  const ax = 18;
  chart.append(svg("text", { x: ax, y: T + (H - T - B) / 2, transform: `rotate(-90 ${ax} ${T + (H - T - B) / 2})`, "text-anchor": "middle", class: "axis-title" }, "Pairs right"));

  // What appears with each version, in order: its lineage, the best-so-far step, its two dots.
  const layers = versions.map(() => []);
  const add = (i, node) => {
    node.classList.add("appear");
    layers[i].push(node);
    chart.append(node);
    return node;
  };
  let best = trainPct[0];
  versions.forEach((v, i) => {
    const previous = best;
    best = Math.max(best, trainPct[i]);
    if (i > 0) {
      add(i, svg("line", { x1: x(i - 1) - off, y1: y(trainPct[i - 1]), x2: x(i) - off, y2: y(trainPct[i]), class: "lineage" }));
      add(i, svg("line", { x1: x(i) - band / 2, y1: y(previous), x2: x(i) - band / 2, y2: y(best), class: "best" }));
    }
    add(i, svg("line", { x1: x(i) - band / 2, y1: y(best), x2: x(i) + band / 2, y2: y(best), class: "best" }));
  });
  versions.forEach((v, i) => {
    const seed = i === 0;
    add(i, svg("circle", { cx: x(i) + off, cy: y(valPct[i]), r: rr, class: "val" }));
    add(i, svg("circle", { cx: x(i) - off, cy: y(trainPct[i]), r: seed ? rr + 3 : rr, class: seed ? "seed" : "train" }));
    if (seed) add(i, svg("text", { x: x(i) - off, y: y(trainPct[i]) + 32, "text-anchor": "middle", class: "seed-tag" }, `${Math.round(trainPct[i])}%`));
    if (v.id === data.presented.id) {
      const top = Math.min(y(trainPct[i]), y(valPct[i]));
      const bottom = Math.max(y(trainPct[i]), y(valPct[i]));
      const [hw, pad] = [26, 16];
      add(i, svg("rect", { x: x(i) - hw, y: top - pad, width: 2 * hw, height: bottom - top + 2 * pad, rx: hw, class: "halo" }));
      add(i, svg("text", { x: x(i), y: bottom + 40, "text-anchor": "middle", class: "tag" }, "the agent we present"));
    }
    const name = seed ? "Start" : `Version ${v.label}`;
    const hit = svg("rect", { x: x(i) - band / 2, y: T, width: band, height: H - T - B, fill: "transparent", class: "point", tabindex: "0", role: "button" });
    hit.setAttribute("aria-label", `${name}: ${v.train} of ${data.train_pairs} learning pairs right, ${v.val} of ${data.val_pairs} held-out`);
    hit.addEventListener("mouseenter", () => show(i));
    hit.addEventListener("mouseleave", () => show(pinned()));
    hit.addEventListener("focus", () => show(i));
    hit.addEventListener("blur", () => show(pinned()));
    const pin = () => {
      detailPinned = v.id;
      show(i);
    };
    hit.addEventListener("click", pin);
    hit.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        pin();
      }
    });
    chart.append(hit);
  });
  for (let i = 0; i < layers.length; i++) {
    if (run !== chartRun) return;
    layers[i].forEach((node) => node.classList.add("on"));
    if (!REDUCED_MOTION) await sleep(450);
  }
}

let detailPinned = null;

function buildDetails(data) {
  // Every version's panel, stacked in one place and one shown at a time: the panel is as tall as the longest of them,
  // so nothing below it moves when another version is shown.
  $("#detail").replaceChildren(...data.versions.map((v) => detailPanel(v, data)));
}

function showDetail(v) {
  for (const panel of $("#detail").children) panel.classList.toggle("shown", panel.dataset.id === v.id);
}

function detailPanel(v, data) {
  // What one version is and what the optimizer changed to make it.
  const name = v.id === "seed" ? "Start" : `Version ${v.label}`;
  const parent = data.versions.find((p) => p.id === v.parent);
  return el(
    "div",
    { class: "version", "data-id": v.id },
    el(
      "div",
      { class: "name" },
      name,
      el("span", { text: ` (${percent(v.val, data.val_pairs)} held-out)` }),
      v.id === data.presented.id ? el("span", { class: "presented badge success", text: "the agent we present" }) : null,
    ),
    el(
      "div",
      { class: "based" },
      ...(parent ? ["based on ", el("span", { class: "chip", text: parent.id === "seed" ? "Start" : `Version ${parent.label}` })] : ["written by hand"]),
    ),
    el("div", { class: "summary", text: v.summary || "" }),
    el("div", {
      class: "scores",
      text: `Learning pairs ${v.train} of ${data.train_pairs} right · held-out ${v.val} of ${data.val_pairs} · fixed twins flagged ${v.val_flagged} of the held-out`,
    }),
    v.added != null ? el("div", { class: "size" }, el("b", { text: `+${v.added}` }), " ", el("i", { text: `−${v.removed}` }), ` lines in ${v.files.length} files`) : null,
    v.files ? el("div", { class: "files", text: v.files.join(" · ") }) : null,
    v.highlights?.length ? el("div", { class: "added", text: v.highlights.map((line) => `+ ${line}`).join("\n") }) : null,
  );
}

async function fillCards() {
  evolution = evolution || (await (await fetch("/api/evolution")).json());
  const p = evolution.presented;
  $("#test-from").textContent = percent(p.test.seed, p.test_pairs);
  $("#test-to").textContent = percent(p.test.presented, p.test_pairs);
  $("#alarm-from").textContent = p.test_flagged.seed;
  $("#alarm-to").textContent = p.test_flagged.presented;
  $("#note").textContent = evolution.note;
  const picked = evolution.versions.find((v) => v.id === p.id);
  $("#legend-train").textContent = `pairs the optimizer learns from (${evolution.train_pairs})`;
  $("#legend-val").textContent = `held-out pairs it never sees (${evolution.val_pairs})`;
  $("#n-test").textContent = $("#n-test-twins").textContent = p.test_pairs;
  $("#n-picked").textContent = `${picked.val} of ${evolution.val_pairs}`;
}

$("#replay-chart").addEventListener("click", drawChart);

// -- 2. the demo, live or replayed --------------------------------------------------------------------------------

class Terminal {
  // Renders a terminal's output: the demo's styles (bold, dim, red, green, cyan) and plain text.
  constructor(pre) {
    this.pre = pre;
    this.marker = el("div", { class: "section-mark hidden" }); // the highlighted section, behind the text
    this.clear();
  }

  clear() {
    this.pre.replaceChildren(this.marker);
    this.styles = [];
    this.pending = "";
    this.plain = "";
  }

  write(text) {
    text = (this.pending + text).replace(/\r/g, "");
    this.pending = "";
    const split = text.match(/\x1b(\[[0-9;]*)?$/); // an escape sequence cut off at the end of a chunk
    if (split) {
      this.pending = split[0];
      text = text.slice(0, -split[0].length);
    }
    const nearBottom = this.pre.scrollHeight - this.pre.scrollTop - this.pre.clientHeight < 60;
    const fragment = document.createDocumentFragment();
    for (const part of text.split(/(\x1b\[[0-9;]*[A-Za-z])/)) {
      if (!part) continue;
      const code = part.match(/^\x1b\[([0-9;]*)([A-Za-z])$/);
      if (code) {
        if (code[2] === "m") this.style(code[1]);
        continue;
      }
      fragment.append(this.styles.length ? el("span", { class: this.styles.join(" "), text: part }) : part);
      this.plain += part;
    }
    this.pre.append(fragment);
    if (nearBottom) this.pre.scrollTop = this.pre.scrollHeight;
    if (viewing && !this.placing) {
      this.placing = true; // the section being viewed may have grown: move its marker once per frame
      requestAnimationFrame(() => {
        this.placing = false;
        placeSection();
      });
    }
  }

  style(codes) {
    for (const code of (codes || "0").split(";")) {
      if (code === "0" || code === "") this.styles = [];
      const name = { 1: "b", 2: "d", 31: "r", 32: "g", 36: "c" }[code];
      if (name && !this.styles.includes(name)) this.styles.push(name);
    }
  }
}

const term = new Terminal($("#term"));
const demo = { mode: null, run: 0, started: 0, timer: null, stream: null, answer: null };

function updateDemoButtons() {
  const running = demo.mode !== null;
  $("#run-live").disabled = running || !spark.live || spark.busy !== null;
  $("#run-live").title = spark.live ? "" : "The DGX Spark's model server or sandbox is not available: play the recording";
  $("#run-replay").disabled = running;
  $("#run-replay").title = running ? "A run is in progress" : "";
  $("#stop").disabled = !running;
  $("#stop").title = running ? "" : "Nothing is running";
  // The one filled button is the run that can start now: live when the Spark is ready, the recording otherwise.
  $("#run-live").classList.toggle("primary", spark.live);
  $("#run-replay").classList.toggle("primary", !spark.live);
}

function updateSteps(finished = false) {
  const headings = [...term.plain.matchAll(/=== (\d)\./g)];
  const current = finished ? 8 : headings.length ? Number(headings[headings.length - 1][1]) : 0;
  for (const item of document.querySelectorAll("#step-list li")) {
    const step = Number(item.dataset.step);
    item.classList.toggle("done", step < current);
    item.classList.toggle("current", step === current);
  }
}

function sectionRange(step) {
  // The terminal's text from the heading of `step` ("=== 4. ...") up to the next heading, or to the end.
  const walker = document.createTreeWalker($("#term"), NodeFilter.SHOW_TEXT);
  const nodes = [];
  let text = "";
  while (walker.nextNode()) {
    nodes.push([walker.currentNode, text.length]);
    text += walker.currentNode.data;
  }
  const heading = new RegExp(`(^|\\n)=== ${step}\\. `).exec(text);
  if (!heading) return null;
  const begin = heading.index + heading[1].length;
  const next = /\n=== \d\. /.exec(text.slice(begin + 1));
  let end = next ? begin + 1 + next.index + 1 : text.length;
  while (end > begin && /\s/.test(text[end - 1])) end--; // not the blank lines before the next heading
  const locate = (offset) => {
    for (let i = nodes.length - 1; i >= 0; i--) {
      if (nodes[i][1] <= offset) return [nodes[i][0], Math.min(offset - nodes[i][1], nodes[i][0].data.length)];
    }
    return [nodes[0][0], 0];
  };
  const range = new Range();
  range.setStart(...locate(begin));
  range.setEnd(...locate(end));
  return range;
}

let viewing = null; // the step whose section is highlighted

function placeSection() {
  // One block behind the section's text, the terminal's full width; returns its top.
  const marker = term.marker;
  const range = viewing ? sectionRange(viewing) : null;
  if (!range) {
    marker.classList.add("hidden");
    return null;
  }
  const pre = $("#term");
  const box = range.getBoundingClientRect();
  const top = box.top - pre.getBoundingClientRect().top + pre.scrollTop - 6;
  marker.style.top = `${top}px`;
  marker.style.height = `${box.height + 12}px`;
  marker.style.width = `${pre.scrollWidth - 12}px`;
  marker.classList.remove("hidden");
  return top;
}

function showSection(step) {
  // Scroll the terminal to a step's section and highlight it.
  viewing = step;
  const top = placeSection();
  if (top === null) return;
  $("#term").scrollTo({ top: top - 8, behavior: "smooth" });
  document.querySelectorAll("#step-list li").forEach((item) => item.classList.toggle("viewing", Number(item.dataset.step) === step));
}

window.addEventListener("resize", () => viewing && placeSection());

for (const item of document.querySelectorAll("#step-list li")) {
  item.tabIndex = 0;
  item.addEventListener("click", () => showSection(Number(item.dataset.step)));
  item.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      showSection(Number(item.dataset.step));
    }
  });
}

function startDemo(mode) {
  demo.mode = mode;
  demo.run += 1;
  demo.started = Date.now();
  term.clear();
  viewing = null;
  document.querySelectorAll("#step-list li").forEach((item) => item.classList.remove("viewing"));
  $("#approval").classList.add("hidden");
  $("#demo-note").textContent = "";
  $("#terminal-title").textContent = mode === "live" ? "live on the DGX Spark" : "the recorded run";
  $("#step-list").classList.add("running");
  updateSteps();
  clearInterval(demo.timer);
  demo.timer = setInterval(() => ($("#clock").textContent = clock((Date.now() - demo.started) / 1000)), 500);
  updateDemoButtons();
  return demo.run;
}

function finishDemo(note) {
  clearInterval(demo.timer);
  demo.mode = null;
  $("#step-list").classList.remove("running");
  $("#approval").classList.add("hidden");
  const found = /found the planted defect/.test(term.plain);
  const missed = /missed the planted defect/.test(term.plain);
  updateSteps(found || missed);
  $("#demo-note").className = `note${!note && found ? " good" : ""}`;
  $("#demo-note").textContent =
    note || (found ? "The deployed agent found the vulnerability planted in a repository it had never seen." : missed ? "The deployed agent missed the planted vulnerability this time." : "");
  updateDemoButtons();
}

// ?autoplay: attract mode for an unattended screen. The recording plays in a loop and approves itself.
const AUTOPLAY = new URLSearchParams(location.search).has("autoplay");

function askApproval() {
  // Resolves with the visitor's decision.
  $("#approval").classList.remove("hidden");
  const box = $("#approval").getBoundingClientRect();
  if (box.top < 72 || box.bottom > innerHeight) $("#approval").scrollIntoView({ block: "center", behavior: REDUCED_MOTION ? "auto" : "smooth" });
  const decision = new Promise((resolve) => (demo.answer = resolve));
  if (AUTOPLAY && demo.mode === "replay") setTimeout(() => demo.answer && $("#approve").click(), 5000);
  return decision;
}

for (const [id, approve] of [["#approve", true], ["#decline", false]]) {
  $(id).addEventListener("click", async () => {
    $("#approval").classList.add("hidden");
    if (demo.mode === "live") await post("/api/demo/answer", { approve });
    if (demo.answer) demo.answer(approve);
    demo.answer = null;
  });
}

async function runLive() {
  const started = await post("/api/demo/start", { approved_by: "GUI visitor" });
  if (!started.ok) {
    $("#demo-note").textContent = `Can't start: ${started.error}.`;
    return;
  }
  startDemo("live");
  let opened = false;
  const stream = new EventSource("/api/demo/stream");
  demo.stream = stream;
  stream.onopen = () => {
    if (opened) term.clear(); // a reconnect sends the whole run again
    opened = true;
  };
  stream.addEventListener("out", (event) => {
    term.write(JSON.parse(event.data));
    updateSteps();
  });
  stream.addEventListener("prompt", (event) => {
    if (JSON.parse(event.data).awaiting) askApproval();
    else $("#approval").classList.add("hidden");
  });
  stream.addEventListener("end", (event) => {
    stream.close();
    const code = JSON.parse(event.data).code;
    finishDemo(code ? "The run ended early. If the DGX Spark isn't ready, play the recording." : null);
    refreshStatus();
  });
}

function indexOf(haystack, needle, from = 0) {
  outer: for (let i = from; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

async function runReplay() {
  const run = startDemo("replay");
  const [log, timing] = await Promise.all([
    fetch("/recording/session.log").then((r) => r.arrayBuffer()),
    fetch("/recording/timing.log").then((r) => r.text()),
  ]);
  let data = new Uint8Array(log);
  data = data.subarray(data.indexOf(10) + 1); // the first line is the header `script` writes
  const prompt = new TextEncoder().encode("Type 'yes' to approve: ");
  const promptAt = indexOf(data, prompt);
  const promptEnd = promptAt >= 0 ? promptAt + prompt.length : -1;
  const answerEnd = promptEnd >= 0 ? data.indexOf(10, promptEnd) + 1 : -1;
  const decoder = new TextDecoder("utf-8");
  let position = 0;
  let asked = false;
  for (const line of timing.trim().split("\n")) {
    const [delay, size] = line.trim().split(/\s+/);
    // Long waits (the measurement) are shortened: at most 8 seconds, divided by the speed.
    await sleep((Math.min(parseFloat(delay), 8) * 1000) / Number($("#speed").value));
    if (run !== demo.run) return;
    let start = position;
    const end = position + parseInt(size, 10);
    if (!asked && promptEnd >= 0 && start < promptEnd && promptEnd <= end) {
      term.write(decoder.decode(data.subarray(start, promptEnd), { stream: true }));
      const approved = await askApproval();
      if (run !== demo.run) return;
      asked = true;
      term.write(approved ? "yes\n" : "no\n");
      if (!approved) {
        term.write("    not deployed\n");
        finishDemo("Declined: nothing was deployed. That's the point of the human in the loop.");
        return;
      }
    }
    if (asked) start = Math.max(start, answerEnd); // the recorded answer: the visitor's is already on screen
    if (start < end) term.write(decoder.decode(data.subarray(start, end), { stream: true }));
    updateSteps();
    position = end;
  }
  finishDemo();
  if (AUTOPLAY) setTimeout(() => demo.mode === null && runReplay(), 20000);
}

$("#run-live").addEventListener("click", runLive);
$("#run-replay").addEventListener("click", runReplay);
$("#stop").addEventListener("click", async () => {
  if (demo.mode === "live") {
    await post("/api/demo/stop");
  } else {
    demo.run += 1; // the replay loop sees a newer run and stops
    if (demo.answer) demo.answer(false);
    finishDemo("Stopped.");
  }
});

// -- 3. spot the vulnerability: a PrimeVul pair, a guess, then the agent's two verdicts ---------------------------

let pairs = [];
let pair = null; // the pair on show
let revealed = false;

async function loadPairs() {
  pairs = await (await fetch("/api/pairs")).json();
  const list = $("#pair-list");
  list.replaceChildren();
  list.classList.toggle("is-empty", !pairs.length);
  if (!pairs.length) {
    list.append(
      el(
        "li",
        { class: "empty" },
        el("p", { class: "empty-head", text: "No pair has been judged yet" }),
        el("p", { text: "Pairs appear here once the PrimeVul agent has judged them: hatch run synthetic:gui --prepare-pairs." }),
      ),
    );
    return;
  }
  for (const p of pairs) {
    const row = el(
      "button",
      { class: "integration", "data-name": p.id },
      el("span", { class: "name", text: p.project || p.id }),
      el("span", { class: "about", text: p.cwe_name.split(":")[0] }), // the weakness's name alone; the panel explains it
    );
    row.addEventListener("click", () => selectPair(p.id));
    list.append(el("li", {}, row));
  }
  const right = pairs.filter((p) => p.right).length;
  list.append(el("li", { class: "note", text: `${pairs.length} pairs chosen for short functions; the agent got ${right} of them right. On 100 held-out pairs it gets 21 right, the agent it started from 16.` }));
  selectPair(pairs[0].id);
}

function selectPair(id) {
  pair = pairs.find((p) => p.id === id);
  revealed = false;
  document.querySelectorAll("#pair-list .integration").forEach((row) => row.classList.toggle("active", row.dataset.name === id));
  $("#pair-view").classList.remove("hidden");
  $("#pair-name").textContent = pair.project ? `${pair.project}${pair.file ? ` · ${pair.file}` : ""}` : pair.id;
  $("#pair-about").textContent = `${pair.cwe_name} (${pair.cwe}).`;
  $("#pair-commit").classList.toggle("hidden", !pair.commit_url);
  if (pair.commit_url) $("#pair-commit").href = pair.commit_url;
  renderPair();
}

// Syntax highlighting by a small tokenizer per language: comments, strings, preprocessor lines and decorators,
// keywords, types, macros and calls. The language comes from the file's extension; unknown ones stay plain.
const WORDS = (list) => new Set(list.split(" "));
const LANGS = {
  c: {
    token: /\/\*[\s\S]*?\*\/|\/\/[^\n]*|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|^[ \t]*#[^\n]*|0[xX][0-9a-fA-F]+[uUlL]*|\d+(?:\.\d+)?[uUlLfF]*|[A-Za-z_]\w*|\s+|[\s\S]/gm,
    comment: (t) => t.startsWith("/*") || t.startsWith("//"),
    string: (t) => t[0] === '"' || t[0] === "'",
    directive: (t) => /^[ \t]*#/.test(t),
    keywords: WORDS("auto break case const continue default do else enum extern for goto if inline register restrict return sizeof static struct switch typedef union volatile while class namespace new delete template typename this public private protected virtual override nullptr try catch throw using"),
    types: WORDS("void char short int long float double signed unsigned bool size_t ssize_t off_t FILE"),
  },
  python: {
    token: /#[^\n]*|[rRbBuUfF]{0,2}(?:"""[\s\S]*?"""|'''[\s\S]*?'''|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')|@[A-Za-z_][\w.]*|0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?[jJ]?|[A-Za-z_]\w*|\s+|[\s\S]/gm,
    comment: (t) => t[0] === "#",
    string: (t) => /^[rRbBuUfF]{0,2}["']/.test(t),
    directive: (t) => t[0] === "@",
    keywords: WORDS("False None True and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield match case self cls"),
    types: WORDS("int str float bool list dict set tuple bytes object type Any Optional Union Callable Path Exception BaseException ValueError TypeError KeyError RuntimeError OSError"),
  },
  conf: {
    token: /#[^\n]*|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|^[ \t]*-?[ \t]*[\w.\-\[\]]+(?=[ \t]*[:=])|[\s\S]/gm,
    comment: (t) => t[0] === "#",
    string: (t) => t[0] === '"' || t[0] === "'",
    directive: () => false,
    keywords: new Set(),
    types: new Set(),
    key: true,
  },
};
const LANG_OF_EXT = { c: "c", h: "c", cc: "c", cpp: "c", cxx: "c", hpp: "c", py: "python", yaml: "conf", yml: "conf", toml: "conf", ini: "conf", cfg: "conf", sh: "conf", env: "conf" };
const langOf = (file) => LANG_OF_EXT[String(file || "").split(".").pop().toLowerCase()] || null;

function tokenize(code, lang) {
  // The code as lines of [class, text] pieces; a token that spans lines (a comment, a docstring) is split between them.
  const spec = LANGS[lang];
  if (!spec) return [];
  const lines = [[]];
  const push = (cls, text) =>
    text.split("\n").forEach((part, i) => {
      if (i) lines.push([]);
      if (part) lines[lines.length - 1].push([cls, part]);
    });
  for (const match of code.matchAll(spec.token)) {
    const t = match[0];
    let cls = "";
    if (spec.comment(t)) cls = "c-cm";
    else if (spec.string(t)) cls = "c-str";
    else if (spec.directive(t)) cls = "c-pp";
    else if (spec.key && t.trim() && /[\w\]]$/.test(t)) cls = "c-ty";
    else if (/^\d/.test(t)) cls = "c-num";
    else if (/^[A-Za-z_]/.test(t)) {
      if (spec.keywords.has(t)) cls = "c-kw";
      else if (spec.types.has(t) || /_t$/.test(t) || (/^[A-Z]/.test(t) && /[a-z]/.test(t))) cls = "c-ty";
      else if (/^[A-Z][A-Z0-9_]+$/.test(t)) cls = "c-mac";
      else if (/^\s*\(/.test(code.slice(match.index + t.length))) cls = "c-fn";
    }
    push(cls, t);
  }
  return lines;
}

function codeLine(line, pieces) {
  return pieces.length ? pieces.map(([cls, text]) => (cls ? el("span", { class: cls, text }) : text)) : [line.text];
}

// The two functions, as "A" and "B" in the pair's fixed order; after the reveal, which is which and the verdicts.
function renderPair() {
  const order = pair.first === "vulnerable" ? ["vulnerable", "patched"] : ["patched", "vulnerable"];
  $("#functions").replaceChildren(
    ...order.map((which, i) => {
      const fn = pair[which];
      const pieces = tokenize(fn.lines.map((line) => line.text).join("\n"), /^c/.test(pair.lang) ? "c" : langOf(pair.file));
      return el(
        "div",
        { class: `function${revealed ? ` ${which}` : ""}` },
        el(
          "div",
          { class: "function-head" },
          el("span", { class: "letter", text: "AB"[i] }),
          revealed ? el("span", { class: `badge ${which === "vulnerable" ? "error" : "success"}`, text: which === "vulnerable" ? "The vulnerable one" : "The patched one" }) : null,
        ),
        el(
          "div",
          { class: "code" },
          ...fn.lines.map((line, i) =>
            el(
              "div",
              { class: `${revealed && line.changed ? "hit" : ""}${revealed && fn.flagged.includes(line.n) ? " flagged" : ""}` },
              el("span", { class: "n", text: String(line.n) }),
              ...codeLine(line, pieces.length === fn.lines.length ? pieces[i] : []),
            ),
          ),
        ),
        revealed ? verdictBox(fn) : null,
      );
    }),
  );
  $("#pair-question").classList.toggle("hidden", revealed);
  $("#pair-outcome").classList.toggle("hidden", !revealed);
}

function verdictBox(fn) {
  const said = fn.verdict === null ? "gave no verdict" : fn.verdict === "vulnerable" ? "called it vulnerable" : "called it safe";
  const pointed = fn.flagged.length ? ` · pointed at line${fn.flagged.length === 1 ? "" : "s"} ${fn.flagged.join(", ")}` : "";
  return el(
    "div",
    { class: "verdict-box" },
    el("p", { class: "said" }, el("span", { text: `The agent ${said}` }), el("span", { class: `badge ${fn.right ? "success" : "error"}`, text: fn.right ? "right" : "wrong" })),
    el("p", { class: "meta" }, ...duration(fn.seconds), fn.lookups ? ` · ${fn.lookups} knowledge-base lookup${fn.lookups === 1 ? "" : "s"}` : " · no knowledge-base lookup", pointed),
    fn.rationale ? el("details", { class: "reason" }, el("summary", { text: "Its reasoning" }), el("p", { class: "why", text: plain(fn.rationale) })) : null,
  );
}

function whyWrong() {
  const [v, p] = [pair.vulnerable.verdict, pair.patched.verdict];
  if (v === "vulnerable" && p === "vulnerable") return "It called both vulnerable: it saw the risk, but not that the fix had closed it. A pair counts only when both verdicts are right.";
  if (v === "benign" && p === "benign") return "It called both safe: it missed the vulnerability.";
  if (v === "benign" && p === "vulnerable") return "It got the two the wrong way round.";
  return "One of its answers could not be read as a verdict.";
}

function reveal(guess) {
  revealed = true;
  renderPair();
  const vulnerableSide = pair.first === "vulnerable" ? "A" : "B";
  const you = guess === null ? "" : guess === vulnerableSide ? "You picked the vulnerable one. " : `You picked the patched one; ${vulnerableSide} is the vulnerable one. `;
  $("#pair-outcome").replaceChildren(
    el("p", { class: "outcome-head", text: `${you}The agent got this pair ${pair.right ? "right" : "wrong"}.` }),
    el("p", { class: "muted", text: pair.right ? "It called the vulnerable function vulnerable and the patched one safe, each judged on its own." : whyWrong() }),
    el("p", { class: "legend-note", text: "Amber marks the lines that differ between the two functions; blue the lines the agent pointed at." }),
  );
}

$("#guess-a").addEventListener("click", () => reveal("A"));
$("#guess-b").addEventListener("click", () => reveal("B"));
$("#reveal").addEventListener("click", () => reveal(null));

// -- 4. the agent's verdict on Haystack integrations ---------------------------------------------------------------

let integrations = [];

async function loadIntegrations() {
  integrations = await (await fetch("/api/integrations")).json();
  const list = $("#integrations");
  list.replaceChildren();
  list.classList.toggle("is-empty", !integrations.length);
  if (!integrations.length) {
    list.append(
      el(
        "li",
        { class: "empty" },
        el("p", { class: "empty-head", text: "No integration is on the page yet" }),
        el("p", { text: "Integrations appear here once their scans are reviewed and approved: hatch run synthetic:gui --review, then --approve NAME." }),
      ),
    );
    return;
  }
  let group = null;
  for (const integration of integrations) {
    if (integration.group && integration.group !== group) {
      group = integration.group;
      list.append(el("li", { class: "group", text: group }));
    }
    const count = integration.findings.length;
    const row = el(
      "button",
      { class: "integration", "data-name": integration.name },
      el("span", { class: "name", text: integration.title }),
      el("span", { class: `badge ${count ? "warning" : "success"}`, text: count ? `${count} finding${count === 1 ? "" : "s"}` : "Nothing found" }),
    );
    row.addEventListener("click", () => select(integration.name));
    list.append(el("li", {}, row));
  }
  select(integrations[0].name);
}

function select(name) {
  const integration = integrations.find((i) => i.name === name);
  document.querySelectorAll("#integrations .integration").forEach((row) => row.classList.toggle("active", row.dataset.name === name));
  $("#scan-view").classList.remove("hidden");
  $("#scan-name").textContent = integration.title;
  $("#scan-about").textContent = integration.about;
  $("#scan-code").href = integration.url;
  renderResult(integration);
}

function codeBlock(excerpt, file) {
  const pieces = tokenize(excerpt.map((line) => line.text).join("\n"), langOf(file));
  return el(
    "div",
    { class: "code" },
    ...excerpt.map((line, i) =>
      el("div", { class: line.hit ? "hit" : "" }, el("span", { class: "n", text: String(line.n) }), ...codeLine(line, pieces.length === excerpt.length ? pieces[i] : [])),
    ),
  );
}

const plain = (text) => text.replace(/`/g, ""); // the agent writes Markdown
const shorten = (text, max) => (text.length > max ? `${text.slice(0, max)}…` : text);

const SEVERITY = { high: "error", medium: "warning" };

function renderFinding(finding) {
  const why = plain(finding.why);
  const fix = plain(finding.fix);
  const lines = finding.lines[0] === finding.lines[1] ? `line ${finding.lines[0]}` : `lines ${finding.lines[0]}–${finding.lines[1]}`;
  const where = `${finding.cwe_name} (${finding.cwe}) · ${shortPath(finding.file)}, ${lines}`;
  const explanation = el("p", { class: "why" });
  if (why) explanation.append(shorten(why, 360));
  if (fix) explanation.append(why ? " " : "", el("b", { text: "Fix: " }), shorten(fix, 240));
  return el(
    "div",
    { class: "finding" },
    el(
      "p",
      { class: "ftitle" },
      plain(finding.title),
      finding.severity ? el("span", { class: `badge ${SEVERITY[finding.severity] || ""}`, text: `${finding.severity} severity` }) : null,
    ),
    el("p", { class: "where", text: where }),
    finding.excerpt.length ? codeBlock(finding.excerpt, finding.file) : null,
    why || fix ? explanation : null,
  );
}

const number = (n) => n.toLocaleString("en-US");
const shortPath = (path) => path.replace(/^src\/haystack_integrations\//, ""); // every integration's code lives there

function renderResult(integration) {
  const count = integration.findings.length;
  const read = integration.read;
  const lines = read.reduce((sum, file) => sum + (file.lines || 0), 0);
  const facts = [
    ["Files read", [integration.files != null ? `${read.length} of ${integration.files}` : number(read.length)], "The files the agent opened, of all the files in the integration"],
    ["Lines read", [number(lines)], "The lines in the files it opened"],
    ["Model calls", [number(integration.calls)], "How many times the agent asked the language model: once per step of reasoning or tool use"],
    ["Scan time", duration(integration.seconds), "How long the scan took, inside the sandbox"],
  ];
  $("#scan-result").replaceChildren(
    el("p", { class: "verdict", text: count ? `The agent reported ${count} finding${count === 1 ? "" : "s"}` : "The agent found nothing to report" }),
    el("p", { class: "meta", text: `At commit ${integration.commit}, scanned on ${integration.scanned_at}` }),
    el("div", { class: "facts" }, ...facts.map(([label, value, title]) => el("div", { class: "fact", title }, el("span", { class: "label", text: label }), el("span", { class: "value" }, ...value)))),
    ...integration.findings.map(renderFinding),
    details(read),
  );
}

function details(files) {
  // Behind a disclosure: the note on what a finding is, and the files the agent opened, with their length.
  const shown = files.slice(0, 10);
  return el(
    "details",
    { class: "more" },
    el("summary", { text: "Details" }),
    el("p", { class: "footnote", text: `A finding is the agent's report, not a confirmed vulnerability.${files.length ? " The agent read these files:" : ""}` }),
    files.length
      ? el(
          "ul",
          { class: "read" },
          ...shown.map((file) =>
            el("li", {}, el("span", { class: "path", text: shortPath(file.path) }), el("span", { class: "lines", text: file.lines == null ? "–" : `${number(file.lines)} lines` })),
          ),
        )
      : null,
    files.length > shown.length ? el("p", { class: "footnote", text: `and ${files.length - shown.length} more` }) : null,
  );
}

async function showRecording() {
  // At rest the terminal holds the recorded run, so a visitor can open any step before pressing Play.
  const log = await (await fetch("/recording/session.log")).text();
  if (demo.mode !== null) return;
  const [header, footer] = [/^Script started on (\S+ \S+)/.exec(log), /Script done on (\S+ \S+)/.exec(log)];
  const body = log.slice(log.indexOf("\n") + 1).replace(/\s*Script done on[^\n]*\s*$/, "\n");
  term.clear();
  term.write(body);
  $("#term").scrollTop = 0; // from its first step
  $("#terminal-title").textContent = "The recorded run";
  $("#step-list").classList.add("browsable");
  if (header && footer) {
    const took = (Date.parse(footer[1].replace(" ", "T")) - Date.parse(header[1].replace(" ", "T"))) / 1000;
    if (took > 0) $("#terminal-title").replaceChildren("The recorded run · ", ...duration(took), " on one DGX Spark");
  }
}

// -- start --------------------------------------------------------------------------------------------------------

refreshStatus();
setInterval(refreshStatus, 15000);
fillCards();
loadIntegrations();
loadPairs();
showRecording();
const first = location.hash.slice(1);
showTab(["evolution", "demo", "scan", "pairs"].includes(first) ? first : "demo");
if (AUTOPLAY) runReplay();
