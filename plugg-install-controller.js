// SPDX-License-Identifier: GPL-3.0-only
// Experimental Jambox-to-Pluggbox owner trial over Web MIDI.
// Transfer orchestration derives from Jambox and retains its staging guards.
// Candidate software evidence remains separate from physical validation.
import { Updater, FM1_PORT } from './fm1ota.js';
import { prepareCandidate, validateManifest, inspectDevice, PLUGG_IDENTITIES, SOURCE_IDENTITIES, TRANSITIONS } from './plugg-device-policy.js';
import { sha256hex } from './fm1pkg.js';

const OPEN_TIMEOUT = 10000, LOAD_TIMEOUT = 30000, INSTALL_TIMEOUT = 10 * 60 * 1000;
const loadedBundles = new WeakMap();
const hash = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);

function failure(code, message) { const error = new Error(message); error.code = code; return error; }
function insist(condition, message, code = 'package') { if (!condition) throw failure(code, message); }
function cancelled(signal) { if (signal?.aborted) throw failure('aborted', 'Cancelled before installation began.'); }
function sourceTransition(identity, capabilities) {
  // A numeric transport identity alone cannot authorize migration. The policy
  // recognizes only the exact Jambox schema, release, mode, identity and mask.
  if (identity?.text === SOURCE_IDENTITIES.app && capabilities?.recognized &&
      capabilities.family === 'jamboxfm' && capabilities.mode === 'normal') return TRANSITIONS[0];
  return null;
}
function extraCandidates(access) {
  // listPairs omits ambiguous same-name groups, so count raw candidates too.
  const count = ports => [...ports.values()].filter(port => port.state !== 'disconnected' && FM1_PORT.test(port.name || '')).length;
  return count(access.inputs) > 1 || count(access.outputs) > 1;
}
function oneDevice(access) {
  insist(!extraCandidates(access), 'Connect only one FM-1 MIDI device before starting this trial. Disconnect other matching MIDI devices and check again.', 'ambiguous');
}
function scope(parent, timeout, canCancel = () => true) {
  const controller = new AbortController(); let timedOut = false;
  const stop = () => { if (canCancel()) controller.abort(); };
  parent?.addEventListener('abort', stop, { once: true });
  if (parent?.aborted) stop();
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeout);
  return { signal: controller.signal, get timedOut() { return timedOut; },
    close() { clearTimeout(timer); parent?.removeEventListener('abort', stop); } };
}
function scopedError(error, operation, started = false) {
  if (operation.timedOut) error = failure('timeout', started ?
    'The installation exceeded its time limit. Firmware may be partially written; keep the device connected and identify its current mode.' :
    'The operation timed out before installation began.');
  else if (operation.signal.aborted) error = failure('aborted', 'Cancelled before installation began.');
  if (!(error instanceof Error)) error = failure('operation', String(error));
  error.started = started;
  return error;
}

async function fetchBytes(url, limit, fetchImpl, signal) {
  cancelled(signal);
  const response = await fetchImpl(url.href, { signal, cache: 'no-store', credentials: 'omit', redirect: 'error' });
  insist(response.ok, `${url.pathname}: HTTP ${response.status}`);
  const length = response.headers?.get('content-length');
  insist(length === null || length === undefined || (/^\d+$/.test(length) && Number(length) <= limit), 'Artifact exceeds its size limit');
  let bytes;
  if (response.body?.getReader) {
    const reader = response.body.getReader(), parts = []; let size = 0;
    try {
      for (;;) {
        cancelled(signal);
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > limit) { await reader.cancel(); throw failure('package', 'Artifact exceeds its size limit'); }
        parts.push(value);
      }
      bytes = new Uint8Array(size); let offset = 0;
      for (const part of parts) { bytes.set(part, offset); offset += part.length; }
    } finally { reader.releaseLock(); }
  } else {
    bytes = new Uint8Array(await response.arrayBuffer());
    insist(bytes.length <= limit, 'Artifact exceeds its size limit');
  }
  cancelled(signal);
  return bytes;
}
function json(bytes) {
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { throw failure('package', 'Trial metadata is not valid UTF-8 JSON'); }
}

export async function loadTrialBundle({ baseURL = new URL('./firmware/', import.meta.url), fetchImpl = fetch, signal } = {}) {
  const base = new URL(baseURL, import.meta.url), operation = scope(signal, LOAD_TIMEOUT);
  if (!base.pathname.endsWith('/')) base.pathname += '/';
  base.search = ''; base.hash = '';
  try {
    const trial = json(await fetchBytes(new URL('trial.json', base), 4096, fetchImpl, operation.signal));
    const fields = ['schema_version', 'kind', 'hardware_validated', 'transitions', 'manifest_sha256', 'firmware_sha256'];
    insist(trial && typeof trial === 'object' && !Array.isArray(trial) &&
      Object.keys(trial).sort().join('|') === fields.sort().join('|'), 'Invalid trial descriptor fields');
    insist(trial.schema_version === 1 && trial.kind === 'pluggbox-owner-trial' && trial.hardware_validated === false &&
      JSON.stringify(trial.transitions) === JSON.stringify(TRANSITIONS) && hash(trial.manifest_sha256) && hash(trial.firmware_sha256),
    'Unsupported experimental trial descriptor');
    const manifestBytes = await fetchBytes(new URL('manifest.json', base), 128 * 1024, fetchImpl, operation.signal);
    insist(await sha256hex(manifestBytes) === trial.manifest_sha256, 'Trial manifest SHA-256 mismatch');
    const manifest = json(manifestBytes);
    // Validate before using the manifest's filename, and before any MIDI access.
    const checked = validateManifest(manifest);
    insist(checked.firmware.sha256 === trial.firmware_sha256, 'Trial firmware binding mismatch');
    const bytes = await fetchBytes(new URL(checked.firmware.file, base), checked.firmware.size_bytes, fetchImpl, operation.signal);
    const candidate = await prepareCandidate(checked, bytes);
    cancelled(operation.signal);
    Object.freeze(trial.transitions);
    const bundle = Object.freeze({ version: candidate.version, firmwareSHA256: candidate.sha256,
      manifestSHA256: trial.manifest_sha256,
      firmwareSizeBytes: bytes.length, manifest: candidate.manifest, trial: Object.freeze(trial), hardwareValidated: false });
    loadedBundles.set(bundle, candidate);
    return bundle;
  } catch (error) { throw scopedError(error, operation); }
  finally { operation.close(); }
}

export class TrialInstaller {
  #busy = false;
  #started = false;
  constructor(access, { onStep = () => {}, onLog = () => {} } = {}) {
    insist(access?.inputs && access?.outputs && typeof onStep === 'function' && typeof onLog === 'function', 'Web MIDI access and callbacks are required', 'configuration');
    this.access = access; this.onStep = onStep; this.onLog = onLog;
  }
  get busy() { return this.#busy; }
  get started() { return this.#started; }
  listPairs() { return new Updater(this.access).listPairs(); }
  log(message) { try { this.onLog(message); } catch { /* UI logging cannot stop a flash transfer. */ } }
  step(stage, detail) { try { this.onStep(stage, detail); } catch { /* Likewise for progress rendering. */ } }
  available() { if (this.busy) throw failure('busy', 'Another device operation is still running.'); }

  async inspect(pair, { signal } = {}) {
    this.available(); this.#busy = true;
    const operation = scope(signal, OPEN_TIMEOUT);
    try {
      const updater = new Updater(this.access);
      const observation = await updater.identify({ pair, signal: operation.signal, deadline: Date.now() + OPEN_TIMEOUT,
        query: (link, identity) => inspectDevice(identity, link, { signal: operation.signal }) });
      const ambiguous = extraCandidates(this.access), transition = sourceTransition(observation.identity, observation.capabilities);
      const eligible = !!transition && !ambiguous;
      return { identity: observation.identity, capabilities: observation.capabilities, eligible, transition,
        uniqueDevice: !ambiguous, hardwareValidated: false,
        reason: ambiguous ? 'Connect only one FM-1 MIDI device before starting this trial. Disconnect other matching MIDI devices and check again.' :
          eligible ? 'Jambox is ready for the experimental Pluggbox owner trial.' :
          'Start from a running Jambox 0.1.0-dev build with the matching family response.' };
    } catch (error) { throw scopedError(error, operation); }
    finally { operation.close(); this.#busy = false; }
  }

  async install(bundle, pair, { signal } = {}) {
    this.available();
    insist(loadedBundles.has(bundle), 'Load and verify the trial bundle before installation');
    this.#busy = true; this.#started = false;
    // External UI cancellation stops preparation only. Once staging may have
    // started, neither a cancelled UI task nor a rendering error aborts a write.
    const operation = scope(signal, INSTALL_TIMEOUT, () => !this.started);
    const candidate = loadedBundles.get(bundle), updater = new Updater(this.access);
    let passedApp = false, passedLoader = false, finalIdentity = null, sourceIdentity = null, transition = null;
    try {
      cancelled(operation.signal);
      oneDevice(this.access);
      this.step('checking');
      const identityGuard = async (identity, context) => {
        if (context.stage === 'app') {
          oneDevice(this.access); // Recheck immediately before staging, not only at inspection.
          const observed = await inspectDevice(identity, context.link, { signal: operation.signal });
          oneDevice(this.access); // A device can appear while the family query is pending.
          transition = sourceTransition(identity, observed);
          passedApp = !!transition;
          if (passedApp) {
            sourceIdentity = { ...identity };
            this.log('Fresh Jambox application identity and family response checked.');
          }
          return passedApp;
        }
        const observed = await inspectDevice(identity, context.link, { signal: operation.signal });
        oneDevice(this.access); // Re-enumeration can change during a family query too.
        const pluggbox = observed.recognized && observed.family === 'pluggbox' && observed.release === candidate.version;
        if (context.stage === 'loader') {
          passedLoader = passedApp && pluggbox && observed.mode === 'loader' && identity.text === PLUGG_IDENTITIES.loader;
          if (passedLoader) this.log('Expected Pluggbox update loader identified.');
          return passedLoader;
        }
        if (context.stage === 'final' && passedApp && passedLoader && pluggbox && observed.mode === 'normal' && identity.text === PLUGG_IDENTITIES.app) {
          finalIdentity = { ...identity }; this.log('Pluggbox application identity and release checked.'); return true;
        }
        return false;
      };
      await updater.install(candidate.image(), candidate.product, (stage, detail) => {
        if (stage === 'start') this.#started = true; // Conservative: immediately before the first upgrade send attempt.
        this.step(stage, detail);
      }, { pair, requireSelection: true, signal: operation.signal, deadline: Date.now() + OPEN_TIMEOUT, identityGuard,
        selectPair: ({ stage, pairs }) => {
          insist(stage === 'loader' || stage === 'final', 'Unexpected reconnect stage', 'identity');
          insist(pairs.length <= 1 && !extraCandidates(this.access),
            'Multiple MIDI candidates are available. Keep the FM-1 connected and identify its current mode before retrying.', 'ambiguous');
          // No arbitrary scan: open only the sole current pair, then require
          // the exact expected stage identity before either writing or success.
          return pairs[0] || null;
        } });
      insist(finalIdentity, 'The expected Pluggbox application did not identify itself', 'identity');
      return { identity: finalIdentity, sourceIdentity, version: candidate.version, firmwareSHA256: candidate.sha256,
        hardwareValidated: false, experimental: true, transition, started: true,
        verification: 'reported-family-and-release' };
    } catch (error) {
      const scoped = scopedError(error, operation, this.started);
      // A fresh, eligible source can differ from the earlier inspection. Keep
      // failed-transfer reports tied to the source we actually checked.
      if (sourceIdentity && transition) {
        scoped.sourceIdentity = sourceIdentity;
        scoped.transition = transition;
      }
      throw scoped;
    }
    finally { operation.close(); this.#busy = false; }
  }
}
