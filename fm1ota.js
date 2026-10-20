// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Leo Kuroshita (@kurogedelic), Hügelton Instruments
// USB-MIDI M-UPGRADE transport. Package and firmware-family authorization
// belong to the caller; guards run before either upgrade command and at return.

const HS_QUERY = [0xF0, 0x00, 0x32, 0x45, 0x00, 0x00, 0x00, 0x40, 0x7F, 0xF7];
const UPGRADE = [0xF0, 0x22, 0x24, 0x35, 0x7F, 0xF7];
const INFO_QUERY = [0xF0, 0x7D, 0x46, 0x4C, 1, 0xF7];
const MAXDATA = 512;
const IS_OTA = (id) => /^ota-/i.test(id.model);
export const OUR_LOADER = (id) => /^ota-FM-1_(?:9\d\d|700|701)$/i.test(id.text);
export const FM1_PORT = /fm-1|felucca|sloop|clipper|jamboxfm|pluggbox|ota|composite|sinco|usb-midi/i;
const pendingPortCleanup = new WeakMap();
const PORT_CLEANUP_WAIT_MS = 1000;

function fail(code, msg, detail = "") { const e = new Error(msg); e.code = code; e.detail = detail; return e; }
function aborted(signal) {
  if (signal?.aborted) throw fail("aborted", "Transfer cancelled. The device may already have staged or written firmware; identify it again before retrying.");
}
function abortable(promise, signal, deadline = Infinity) {
  if (!signal && deadline === Infinity) return promise;
  return new Promise((resolve, reject) => {
    let timer, settled = false;
    const finish = (accept, value) => {
      if (settled) return;
      settled = true; clearTimeout(timer); signal?.removeEventListener("abort", stop);
      (accept ? resolve : reject)(value);
    };
    const stop = () => { try { aborted(signal); } catch (e) { finish(false, e); } };
    Promise.resolve(promise).then((value) => finish(true, value), (error) => finish(false, error));
    signal?.addEventListener("abort", stop, { once: true });
    if (signal?.aborted) { stop(); return; }
    if (deadline !== Infinity) timer = setTimeout(() => finish(false, fail("timeout", "The selected MIDI operation timed out")), Math.max(0, deadline - Date.now()));
  });
}
async function sleep(ms, signal) {
  aborted(signal);
  let timer;
  try { await abortable(new Promise((r) => { timer = setTimeout(r, ms); }), signal); }
  finally { clearTimeout(timer); }
}

// WebMIDI open/close promises cannot be cancelled. Keep the actual cleanup
// promise after our bounded wait expires, so a late close cannot race a retry.
function closePort(port, after = Promise.resolve()) {
  if (pendingPortCleanup.has(port)) return pendingPortCleanup.get(port);
  const cleanup = Promise.resolve(after).catch(() => {}).then(() => port.close?.()).catch(() => {}).finally(() => {
    if (pendingPortCleanup.get(port) === cleanup) pendingPortCleanup.delete(port);
  });
  pendingPortCleanup.set(port, cleanup);
  return cleanup;
}
async function closePorts(ports) {
  const cleanup = Promise.all([...new Set(ports)].map((port) => closePort(port)));
  // Cleanup must not replace a verified result or the original transfer error.
  // A disconnected driver's rejected/stalled close is still tracked for retry.
  await abortable(cleanup, null, Date.now() + PORT_CLEANUP_WAIT_MS).catch(() => {});
}
async function openPort(port, signal, deadline = Infinity, started) {
  const end = Math.min(deadline, Date.now() + PORT_CLEANUP_WAIT_MS);
  while (pendingPortCleanup.has(port))
    await abortable(pendingPortCleanup.get(port), signal, end);
  aborted(signal);
  if (Date.now() >= deadline) throw fail("timeout", "The selected MIDI operation timed out");
  // No await between the last cleanup check and opening the port.
  started();
  return port.open();
}

export function pack7(data) {
  const out = []; let acc = 0, nb = 0;
  for (const b of data) {
    acc |= b << nb; nb += 8;
    while (nb >= 7) { out.push(acc & 0x7F); acc >>>= 7; nb -= 7; }
  }
  if (nb) out.push(acc & 0x7F);
  return out;
}
export function unpack7(s) {
  const out = []; let acc = 0, nb = 0;
  for (const b of s) {
    acc |= (b & 0x7F) << nb; nb += 7;
    while (nb >= 8) { out.push(acc & 0xFF); acc >>>= 8; nb -= 8; }
  }
  return out;
}

// Shared strict envelope for handshake, request, and read-only capability replies.
export function encodeMessage(command, body = []) {
  if (!Number.isInteger(command) || command < 0 || command > 255 || body.length > 0xFFFFFF ||
      !Array.from(body).every((b) => Number.isInteger(b) && b >= 0 && b <= 255)) throw new TypeError("invalid protocol message");
  const n = body.length, data = [0, 0x59, command, n & 255, (n >>> 8) & 255, n >>> 16, ...body];
  data.push(~body.reduce((s, b) => s + b, 0) & 255);
  return [0xF0, ...pack7(data), 0xF7];
}
export function decodeMessage(pkt, command, bodyLength) {
  if (!Number.isInteger(command) || command < 0 || command > 255 ||
      !Number.isInteger(bodyLength) || bodyLength < 0 || bodyLength > 0xFFFFFF) return null;
  const bytes = bodyLength + 7, packed = Math.ceil(bytes * 8 / 7);
  if (!pkt || pkt.length !== packed + 2 || pkt[0] !== 0xF0 || pkt[pkt.length - 1] !== 0xF7) return null;
  const wire = Array.from(pkt).slice(1, -1);
  if (!wire.every((b) => Number.isInteger(b) && b >= 0 && b < 128)) return null;
  const d = unpack7(wire), canonical = pack7(d);
  if (d.length !== bytes || canonical.length !== wire.length || canonical.some((b, i) => b !== wire[i])) return null;
  if (d[0] !== 0 || d[1] !== 0x59 || d[2] !== command ||
      (d[3] | d[4] << 8 | d[5] << 16) !== bodyLength) return null;
  const body = d.slice(6, -1);
  if ((~body.reduce((s, b) => s + b, 0) & 255) !== d[d.length - 1]) return null;
  return Uint8Array.from(body);
}
export function parseRequest(pkt) {
  const b = decodeMessage(pkt, 0x30, 8);
  return b ? { fl: b[0], addr: (b[1] | b[2] << 8 | b[3] << 16 | b[4] << 24) >>> 0,
    len: b[5] | b[6] << 8 | b[7] << 16 } : null;
}
export function parseIdentity(pkt) {
  const b = decodeMessage(pkt, 0x11, 27);
  if (!b) return null;
  const zero = b.indexOf(0), end = zero < 0 ? b.length : zero;
  if (b.slice(end).some((v) => v !== 0) || b.slice(0, end).some((v) => v < 0x21 || v > 0x7E)) return null;
  const text = String.fromCharCode(...b.slice(0, end)), m = /^([A-Za-z0-9-]+)_(\d+)$/.exec(text);
  if (!m || !Number.isSafeInteger(Number(m[2]))) return null;
  return { text, model: m[1], version: Number(m[2]) };
}
function response(addr, data, fl = 0) {
  const n = data.length;
  return encodeMessage(0x30, [fl, addr & 255, (addr >>> 8) & 255, (addr >>> 16) & 255, addr >>> 24,
    n & 255, (n >>> 8) & 255, 0, ...data]);
}

class Link {
  constructor(input, output, signal) {
    this.input = input; this.output = output; this.signal = signal;
    this.q = []; this.waiter = null; this.closed = false; this.error = null;
    this.listener = (ev) => {
      if (this.closed || ev.data?.[0] !== 0xF0) return;
      if (ev.data.length > 1024 || this.q.length >= 64) this.error = fail("badreq", "MIDI reply queue exceeded its bounds");
      else this.q.push(Array.from(ev.data));
      this.waiter?.();
    };
    if (input.addEventListener) input.addEventListener("midimessage", this.listener);
    else { this.previous = input.onmidimessage; input.onmidimessage = this.listener; }
    this.stateListener = () => { if (this.lost) this.waiter?.(); };
    for (const port of [input, output]) port.addEventListener?.("statechange", this.stateListener);
  }
  get lost() { return this.closed || this.input.state === "disconnected" || this.output.state === "disconnected"; }
  send(bytes) {
    aborted(this.signal);
    if (this.readOnly && ![HS_QUERY, INFO_QUERY].some((query) => bytes.length === query.length && query.every((b, i) => bytes[i] === b)) &&
        !decodeMessage(bytes, 0x12, 0)) throw fail("readonly", "Identification allows only read-only identity and capability queries");
    if (this.lost) return false;
    try { this.output.send(bytes); return true; } catch (_) { return false; }
  }
  drain() { this.q.length = 0; }
  async read(ms) {
    aborted(this.signal);
    if (this.error) throw this.error;
    if (!this.q.length && !this.lost) {
      let timer;
      try {
        await abortable(new Promise((resolve) => {
          this.waiter = resolve; timer = setTimeout(resolve, Math.max(0, ms));
        }), this.signal);
      } finally { clearTimeout(timer); this.waiter = null; }
    }
    aborted(this.signal);
    if (this.error) throw this.error;
    return this.q.shift() || null;
  }
  async close() {
    if (this.closed) return;
    this.closed = true;
    if (this.input.removeEventListener) this.input.removeEventListener("midimessage", this.listener);
    else if (this.input.onmidimessage === this.listener) this.input.onmidimessage = this.previous || null;
    for (const port of [this.input, this.output]) port.removeEventListener?.("statechange", this.stateListener);
    this.waiter?.(); this.q.length = 0;
    await closePorts([this.input, this.output]);
  }
}

async function handshake(link, deadline = Infinity) {
  link.drain();
  for (let t = 0; t < 2 && Date.now() < deadline; t++) {
    if (!link.send(HS_QUERY)) throw fail("lost", "Could not send the identity request");
    const end = Math.min(deadline, Date.now() + 1000);
    while (Date.now() < end) {
      const p = await link.read(end - Date.now());
      if (!p) break;
      const id = parseIdentity(p);
      if (id) return id;
    }
    if (link.lost) throw fail("lost", "MIDI port disconnected during identification");
  }
  return null;
}

export class Updater {
  constructor(access, log, options = {}) {
    this.access = access; this.log = log || (() => {}); this.options = options; this.previous = null;
  }
  listPairs() {
    const ins = [...this.access.inputs.values()].filter((p) => p.state !== "disconnected" && FM1_PORT.test(p.name || ""));
    const outs = [...this.access.outputs.values()].filter((p) => p.state !== "disconnected");
    return ins.filter((i) => ins.filter((p) => p.name === i.name).length === 1 && outs.filter((o) => o.name === i.name).length === 1)
      .map((i) => ({ inputId: i.id, outputId: outs.find((o) => o.name === i.name).id, name: i.name }))
      .sort((a, b) => a.name.localeCompare(b.name) || a.inputId.localeCompare(b.inputId) || a.outputId.localeCompare(b.outputId));
  }
  resolvePair(pair) {
    const input = this.access.inputs.get(pair?.inputId), output = this.access.outputs.get(pair?.outputId);
    if (!input || !output || input.state === "disconnected" || output.state === "disconnected") throw fail("notfound", "Selected MIDI pair is unavailable");
    if (!input.name || input.name !== output.name || !FM1_PORT.test(input.name)) throw fail("ambiguous", "Select an FM-1 input and output with the same name");
    return { input, output, pair: { inputId: input.id, outputId: output.id, name: input.name } };
  }
  async find(filter, opts = {}) {
    const o = { ...this.options, ...opts }, stage = o.stage || "identify";
    aborted(o.signal);
    let pairs;
    const explicit = opts.pair || (!this.previous ? this.options.pair : null);
    if (explicit) pairs = [explicit];
    else if (o.selectPair) {
      const pair = await abortable(o.selectPair({ stage, pairs: this.listPairs(), previous: this.previous, signal: o.signal }), o.signal, o.deadline);
      pairs = pair ? [pair] : [];
    } else {
      if (o.requireSelection) throw fail("ambiguous", "Explicit MIDI pair selection is required for this stage");
      pairs = this.listPairs();
    }
    for (const pair of pairs) {
      aborted(o.signal);
      if (Date.now() >= (o.deadline ?? Infinity)) break;
      const selected = this.resolvePair(pair);
      let link, accepted = false;
      const opened = [];
      try {
        for (const port of [selected.input, selected.output]) {
          // Another Updater may still be closing this port, including cleanup
          // after a cancelled open. Never start a new open until it settles.
          let started = false;
          const opening = openPort(port, o.signal, o.deadline, () => { started = true; });
          try { await abortable(opening, o.signal, o.deadline); opened.push(port); }
          catch (error) {
            // An in-flight WebMIDI open cannot be cancelled. Close it again if
            // it eventually resolves after cancellation or the deadline.
            if (started) closePort(port, opening);
            throw error;
          }
        }
        link = new Link(selected.input, selected.output, o.signal);
        const id = await handshake(link, o.deadline);
        if (id && (!filter || filter(id))) {
          this.previous = { ...selected.pair, stage };
          accepted = true;
          return { link, id, identity: id, name: selected.input.name, pair: selected.pair };
        }
      } catch (e) {
        if (e.code || explicit || o.selectPair) throw e.code ? e : fail("permission", "Could not open the selected MIDI pair", String(e.message || e));
      } finally {
        if (!accepted) {
          if (link) await link.close();
          else await closePorts(opened);
        }
      }
    }
    return null;
  }
  async identify(opts = {}) {
    const o = { ...this.options, ...opts };
    // Identification requires a selected pair even if legacy installs auto-find.
    if (!o.pair) throw fail("ambiguous", "Choose a MIDI input/output pair before identifying");
    const dev = await this.find(null, { ...o, stage: "identify", pair: o.pair });
    if (!dev) throw fail("identity", "The selected device did not return a valid FM-1 identity");
    try {
      dev.link.readOnly = true;
      const capabilities = o.query ? await abortable(o.query(dev.link, dev.id), o.signal) : undefined;
      return { id: dev.id, identity: dev.id, name: dev.name, pair: dev.pair, ...(capabilities === undefined ? {} : { capabilities }) };
    } finally { await dev.link.close(); }
  }
  seen() {
    const names = [...this.access.inputs.values()].filter((p) => p.state !== "disconnected").map((p) => p.name || "?");
    return names.length ? ` (MIDI: ${names.join(", ")})` : " (MIDI: none)";
  }
  async waitFor(filter, ms, opts = {}) {
    const o = { ...this.options, ...opts }, end = Date.now() + ms;
    while (Date.now() < end) {
      aborted(o.signal);
      let dev;
      try { dev = await this.find(filter, { ...o, deadline: end }); }
      catch (error) { if (error.code === "timeout" && Date.now() >= end) return null; throw error; }
      if (dev) return dev;
      await sleep(Math.min(1000, Math.max(0, end - Date.now())), o.signal);
    }
    return null;
  }
  async guard(dev, stage, opts) {
    aborted(opts.signal);
    if ((opts.product === "FM-1_700" || opts.product === "FM-1_701" ||
        dev.id.text === "FM-1_700" || dev.id.text === "ota-FM-1_700" ||
        dev.id.text === "FM-1_701" || dev.id.text === "ota-FM-1_701") &&
        typeof opts.identityGuard !== "function") throw fail("identity", "Jambox and Pluggbox updates require a firmware-family guard", dev.id.text);
    if (opts.identityGuard) {
      const allowed = await abortable(opts.identityGuard(dev.id, { stage, pair: dev.pair, link: dev.link, signal: opts.signal }), opts.signal);
      if (allowed !== true) throw fail("identity", `Device identity was not approved for ${stage}`, dev.id.text);
    }
    aborted(opts.signal);
  }
  async serve(link, image, finishAddr, idleMs, onProgress, opts = {}) {
    const signal = opts.signal || link.signal || this.options.signal;
    let served = 0, last = Date.now();
    for (;;) {
      aborted(signal);
      if (link.lost) return { served, finished: false, lost: true };
      const remaining = idleMs - (Date.now() - last);
      if (remaining <= 0) return { served, finished: false };
      const pkt = await link.read(Math.min(1000, remaining));
      if (!pkt) continue;
      const r = parseRequest(pkt);
      if (!r) continue; // malformed traffic does not extend the idle deadline
      if (!r.len || r.len > MAXDATA) throw fail("badreq", `bad request length ${r.len}`);
      if (r.addr === 0xE0000000 || r.addr === 0xF0000000) {
        if (r.addr !== finishAddr || r.len !== 8 || r.fl !== 0) throw fail("badreq", "Unexpected completion request");
        if (!link.send(response(r.addr, [115, 117, 99, 99, 101, 115, 115, 0]))) return { served, finished: false, lost: true };
        return { served, finished: true };
      }
      if (r.addr > image.length || r.len > image.length - r.addr) throw fail("badreq", `bad request ${r.addr.toString(16)}+${r.len}`);
      await sleep(10, signal);
      if (!link.send(response(r.addr, Array.from(image.subarray(r.addr, r.addr + r.len)), r.fl))) return { served, finished: false, lost: true };
      last = Date.now(); served++;
      onProgress?.(served, r.addr);
    }
  }
  loaderAllowed(id, product) {
    return OUR_LOADER(id) || (product === "FM-1_015" && id.text === "ota-FM-1_015");
  }
  async install(image, product, onStep, opts = {}) {
    const o = { ...this.options, ...opts, product }, step = onStep || (() => {});
    const dev = await this.find((id) => !IS_OTA(id), { ...o, stage: "app" });
    if (!dev) throw fail("notfound", "FM-1 not found", this.seen());
    let s1;
    try {
      if (dev.id.model !== product.split("_")[0]) throw fail("model", `the device is ${dev.id.text}, the package is for ${product}`);
      await this.guard(dev, "app", o);
      step("start", dev.id.text);
      if (!dev.link.send(UPGRADE)) throw fail("lost", "Could not send the update command");
      await sleep(2000, o.signal);
      s1 = await this.serve(dev.link, image, 0xE0000000, 8000, (n) => step("verify", n), o);
    } finally { await dev.link.close(); }
    if (!s1.finished) throw fail(s1.lost ? "lost" : "stopped", `The device stopped after ${s1.served} requests. Update staging may have changed; identify the device before retrying.`);
    step("loader"); await sleep(3000, o.signal);
    const ota = await this.waitFor(IS_OTA, 30000, { ...o, pair: undefined, stage: "loader" });
    if (!ota) throw fail("noloader", "The update loader did not appear. Identify the device before attempting to resume.");
    const s2 = await this.write(ota, image, step, { ...o, product });
    if (!s2.finished) throw fail(s2.lost ? "lost" : "stopped", `The loader stopped after ${s2.served} requests. Firmware may be partially written; resume with the approved package.`);
    return this.returned(product, step, o);
  }
  async write(ota, image, step = () => {}, opts = {}) {
    const o = { ...this.options, ...opts };
    try {
      if (!this.loaderAllowed(ota.id, o.product)) throw fail("foreign", "The selected loader is not approved for this transport", ota.id.text);
      await this.guard(ota, "loader", o);
      if (!ota.link.send(UPGRADE)) throw fail("lost", "Could not send the loader update command");
      await sleep(2000, o.signal);
      return await this.serve(ota.link, image, 0xF0000000, 180000, (n) => step("write", n), o);
    } finally { await ota.link.close(); }
  }
  async returned(product, step, opts) {
    step("reboot"); await sleep(3000, opts.signal);
    const back = await this.waitFor((id) => !IS_OTA(id), 40000, { ...opts, pair: undefined, stage: "final" });
    if (!back) throw fail("noreturn", "The device did not return; identify its current mode before continuing");
    try {
      if (back.id.text !== product) throw fail("mismatch", `The device reports ${back.id.text}`, back.id.text);
      await this.guard(back, "final", opts);
      step("done", back.id.text);
      return back.id.text;
    } finally { await back.link.close(); }
  }
  async resume(image, onStep, opts = {}) {
    const o = { ...this.options, ...opts }, step = onStep || (() => {});
    const ota = await this.find(IS_OTA, { ...o, stage: "loader" });
    if (!ota) return false;
    if (!(await this.write(ota, image, step, o)).finished) return false;
    if (o.product) await this.returned(o.product, step, o);
    return true;
  }
}
