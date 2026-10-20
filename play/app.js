// SPDX-License-Identifier: GPL-3.0-only
import { WHITE_KEYS } from './worklet.js';

const $ = id => document.getElementById(id);
const SHORTCUTS = ['KeyA', 'KeyS', 'KeyD', 'KeyF', 'KeyG', 'KeyH', 'KeyJ', 'KeyK', 'KeyZ', 'KeyX', 'KeyC', 'KeyV', 'KeyB', 'KeyN', 'KeyM', 'Comma'];
const LABELS = ['A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'Z', 'X', 'C', 'V', 'B', 'N', 'M', ','];
const initialParts = [{ track: 3, role: 'Drums', sound: 'PLUGG KIT' }, { track: 0, role: 'Bass', sound: 'CLEAN SLIDE' }, { track: 1, role: 'Chords', sound: 'GLASS EP' }, { track: 2, role: 'Lead', sound: 'STAR PLUCK' }];
const owners = new Map();

function message(text, error = false) { $('message').textContent = text; $('message').classList.toggle('error', error); }
function enable(on) { $('instrument-controls').disabled = $('transport-controls').disabled = !on; }

export class JamSession {
  constructor(onState, onTransport) {
    this.onState = onState; this.onTransport = onTransport; this.context = null; this.node = null;
    this.pending = []; this.inFlight = false; this.sequence = 0; this.scheduled = false; this.state = null; this.peak = 0;
    this.loading = null;
  }
  async start() {
    if (this.loading) return this.loading;
    if (this.node) { await this.context.resume(); return; }
    const Audio = window.AudioContext || window.webkitAudioContext;
    if (!Audio || !window.AudioWorkletNode) throw new Error('This browser cannot run the audio preview. Try a current Chrome, Edge, Firefox or Safari.');
    this.context = new Audio({ sampleRate: 44100, latencyHint: 'interactive' });
    if (this.context.sampleRate !== 44100) {
      await this.context.close(); this.context = null;
      throw new Error('This audio device cannot open the preview at 44.1 kHz. Try another output device.');
    }
    // Resume while still inside the user's gesture, before fetching any assets.
    const resumed = this.context.resume();
    this.loading = (async () => {
      await resumed;
      const response = await fetch(new URL('./pluggbox.wasm', import.meta.url));
      if (!response.ok) throw new Error('The instrument could not load. Reload the page and try again.');
      const module = await WebAssembly.compile(await response.arrayBuffer());
      await this.context.audioWorklet.addModule(new URL('./worklet.js', import.meta.url));
      this.node = new AudioWorkletNode(this.context, 'pluggbox-preview', {
        numberOfInputs: 0, numberOfOutputs: 1, outputChannelCount: [2], processorOptions: { module },
      });
      this.node.port.onmessage = ({ data }) => {
        if (data.error) { this.panic(); enable(false); message(`Audio stopped: ${data.error}`, true); }
        if (data.warning) { clearOwners(); message(data.warning, true); }
        if (data.ack === this.sequence) {
          if (this.selectionAckToken != null && this.selectionAckToken === this.selectionToken) this.selectionTarget = null;
          this.inFlight = false; this.schedule();
        }
        if (data.state) {
          this.state = data.state;
          this.onState(data.state);
        }
        if (data.transport) this.onTransport(data.transport);
        if (data.peak != null) { this.peak = data.peak; $('meter').value = data.peak; }
      };
      this.node.onprocessorerror = () => { enable(false); message('The audio engine stopped. Reload the page to start a fresh session.', true); };
      this.gain = this.context.createGain(); this.gain.gain.value = 0.6;
      this.node.connect(this.gain).connect(this.context.destination);
    })().catch(async error => {
      this.node?.disconnect();
      await this.context?.close(); this.context = this.node = null;
      throw error;
    }).finally(() => { this.loading = null; });
    return this.loading;
  }
  command(type, args = [], coalesce = false) {
    if (!this.node || this.context.state !== 'running') return;
    const command = { type, args };
    if (type === 'select') command.selectionToken = this.selectionToken;
    if (coalesce) {
      const previous = this.pending.at(-1);
      if (previous?.type === type && previous.args.slice(0, -1).join() === args.slice(0, -1).join()) {
        this.pending[this.pending.length - 1] = command; this.schedule(); return;
      }
    }
    if (this.pending.length >= 64) { this.panic(); message('Too many inputs at once. Notes released; press Play to continue.', true); return; }
    this.pending.push(command); this.schedule();
  }
  schedule() {
    if (this.scheduled || this.inFlight || !this.pending.length) return;
    this.scheduled = true;
    requestAnimationFrame(() => {
      this.scheduled = false;
      if (!this.node || this.inFlight || !this.pending.length) return;
      this.inFlight = true; this.sequence++;
      const commands = this.pending.splice(0, 16), selection = commands.findLast(command => command.type === 'select');
      this.selectionAckToken = selection?.selectionToken ?? null;
      this.node.port.postMessage({ type: 'commands', sequence: this.sequence, commands });
    });
  }
  panic() {
    clearOwners();
    this.pending.length = 0; this.selectionTarget = this.selectionAckToken = null;
    this.node?.port.postMessage({ type: 'panic' });
    if (this.state) this.onState(this.state);
  }
}

function selectedTrack() { return session.selectionTarget ?? session.state?.selected; }
function selected() { return session.state?.tracks.find(track => track.track === selectedTrack()); }
function selectPart(track) {
  // Selection and subsequent edits travel in order to the worklet. Keep their
  // destination tied to the user's new choice while its acknowledgement is in
  // flight, so a quick macro/scale edit cannot land on the previous part.
  session.selectionTarget = track;
  session.selectionToken = (session.selectionToken || 0) + 1;
  session.command('select', [track]);
  if (session.state) render(session.state);
}
function clearOwners() { owners.clear(); for (const pad of document.querySelectorAll('.pad.down')) pad.classList.remove('down'); }
function panic() { clearOwners(); session.panic(); }
function releaseForChange() { clearOwners(); session.command('release'); }
function hold(owner, key) {
  if (!session.node || session.context.state !== 'running' || owners.has(owner)) return;
  const alreadyHeld = [...owners.values()].includes(key);
  owners.set(owner, key);
  if (!alreadyHeld) session.command('key', [key, 1]);
  document.querySelector(`[data-key="${key}"]`)?.classList.add('down');
}
function release(owner) {
  const key = owners.get(owner);
  if (key == null) return;
  owners.delete(owner);
  if (![...owners.values()].includes(key)) {
    session.command('key', [key, 0]); document.querySelector(`[data-key="${key}"]`)?.classList.remove('down');
  }
}
function togglePlay() {
  if (!session.state) return;
  releaseForChange();
  session.command('togglePlay');
}

for (const { track, role, sound } of initialParts) {
  const article = document.createElement('article');
  article.className = `part${track === 1 ? ' selected' : ''}`; article.dataset.track = track;
  article.innerHTML = `<div class="part-head"><button class="part-select" aria-label="Select ${role}" aria-pressed="${track === 1}">${role}</button><button class="mute" aria-label="Mute ${role}" aria-pressed="false">MUTE</button></div><div class="sound-browser"><button class="sound-prev" aria-label="Previous ${role} sound">‹</button><div class="sound-name"><span class="sound-title">${sound}</span><small class="sound-number">GLASS PALETTE</small></div><button class="sound-next" aria-label="Next ${role} sound">›</button></div><div class="part-mark">${String(initialParts.findIndex(part => part.track === track) + 1).padStart(2, '0')} / ${track === 3 ? 'THE RHYTHM' : track === 0 ? 'THE WEIGHT' : track === 1 ? 'THE GLOW' : 'THE SPARK'}</div>`;
  article.querySelector('.part-select').addEventListener('click', () => { releaseForChange(); selectPart(track); });
  article.querySelector('.mute').addEventListener('click', () => {
    session.command('toggleMute', [track]);
  });
  for (const [selector, offset] of [['.sound-prev', -1], ['.sound-next', 1]]) article.querySelector(selector).addEventListener('click', () => {
    const part = session.state?.tracks.find(t => t.track === track);
    if (!part) return;
    releaseForChange(); session.command('soundStep', [track, offset]);
    selectPart(track);
  });
  $('parts').append(article);
}

for (let knob = 0; knob < 4; knob++) {
  const label = document.createElement('label'); label.className = 'macro';
  label.innerHTML = `<span class="macro-title">${['Bright', 'Move', 'Grit', 'Space'][knob]}</span><output>50</output><input type="range" min="0" max="100" value="50" aria-label="${['Bright', 'Move', 'Grit', 'Space'][knob]}" data-knob="${knob}">`;
  label.querySelector('input').addEventListener('input', event => {
    const value = Number(event.target.value); label.querySelector('output').value = value;
    session.command('macro', [selectedTrack(), knob, value], true);
  });
  $('macros').append(label);
}

WHITE_KEYS.forEach((key, index) => {
  const pad = document.createElement('button'); pad.className = 'pad'; pad.dataset.key = key;
  pad.innerHTML = `<strong>—</strong><span>${LABELS[index]}</span>`; pad.setAttribute('aria-label', `Play pad ${index + 1}`);
  pad.addEventListener('pointerdown', event => {
    if (event.button !== 0) return;
    event.preventDefault(); pad.setPointerCapture(event.pointerId); hold(`pointer:${event.pointerId}`, key);
  });
  pad.addEventListener('pointerup', event => { release(`pointer:${event.pointerId}`); if (pad.hasPointerCapture(event.pointerId)) pad.releasePointerCapture(event.pointerId); });
  pad.addEventListener('pointercancel', panic);
  pad.addEventListener('lostpointercapture', event => { if (owners.has(`pointer:${event.pointerId}`)) panic(); });
  pad.addEventListener('keydown', event => {
    if (event.code === 'Space' || event.code === 'Enter') { event.preventDefault(); event.stopPropagation(); hold(`accessible:${key}`, key); }
  });
  pad.addEventListener('keyup', event => {
    if (event.code === 'Space' || event.code === 'Enter') { event.preventDefault(); event.stopPropagation(); release(`accessible:${key}`); }
  });
  pad.addEventListener('blur', () => release(`accessible:${key}`));
  $('pads').append(pad);
});

const grid = $('drum-grid');
grid.append(document.createElement('span'));
for (let step = 0; step < 32; step++) {
  const label = document.createElement('span'); label.className = 'step-number'; label.textContent = step % 4 === 0 ? String(Math.floor(step / 4) + 1) : '·'; grid.append(label);
}
for (const [lane, name] of [[0, 'KICK'], [3, 'CLAP'], [4, 'HAT'], [5, 'OPEN HAT'], [7, 'RIM']]) {
  const label = document.createElement('span'); label.className = 'lane-label'; label.textContent = name; grid.append(label);
  for (let step = 0; step < 32; step++) {
    const button = document.createElement('button'); button.className = 'step'; button.dataset.step = step; button.dataset.lane = lane;
    button.setAttribute('aria-label', `${name} step ${step + 1}`); button.setAttribute('aria-pressed', 'false');
    button.addEventListener('click', () => session.command('step', [step, lane])); grid.append(button);
  }
}

function render(state) {
  enable(session.context?.state === 'running');
  for (const part of state.tracks) {
    const card = document.querySelector(`.part[data-track="${part.track}"]`);
    card.classList.toggle('selected', part.track === selectedTrack()); card.classList.toggle('muted', part.muted);
    card.querySelector('.part-select').setAttribute('aria-pressed', String(part.track === selectedTrack()));
    card.querySelector('.mute').setAttribute('aria-pressed', String(part.muted));
    card.querySelector('.mute').textContent = part.muted ? 'MUTED' : 'MUTE';
    card.querySelector('.sound-title').textContent = part.sound;
    card.querySelector('.sound-number').textContent = `${String(part.soundIndex + 1).padStart(2, '0')} / ${String(part.soundCount).padStart(2, '0')} SOUNDS`;
  }
  const part = selected();
  $('demo').setAttribute('aria-pressed', String(!!state.demo));
  $('demo-label').textContent = state.demo ? 'Back to my jam' : 'Hear starter jam';
  $('selected-sound').textContent = part.sound; $('setting-part').textContent = part.role;
  for (const [index, macro] of part.macros.entries()) {
    const control = document.querySelector(`[data-knob="${index}"]`), label = control.closest('label');
    label.querySelector('.macro-title').textContent = macro.name;
    control.setAttribute('aria-label', macro.name);
    if (document.activeElement !== control) control.value = macro.value;
    label.querySelector('output').value = macro.value;
  }
  for (const [id, value] of [['tempo', state.tempo], ['swing', state.swing], ['root', part.root], ['scale', part.scale], ['quant', part.quant], ['chord', part.chord]]) {
    if (document.activeElement !== $(id)) $(id).value = value;
  }
  $('swing-value').value = `${state.swing}%`; $('octave-value').value = state.octave > 0 ? `+${state.octave}` : state.octave;
  $('octave-down').disabled = state.octave <= -3 || selectedTrack() === 3;
  $('octave-up').disabled = state.octave >= 3 || selectedTrack() === 3;
  $('melodic-settings').hidden = selectedTrack() === 3; $('drum-settings').hidden = selectedTrack() !== 3;
  $('playing-hint').hidden = selectedTrack() === 3;
  $('playing-hint').textContent = !part.chord ? 'These pitch and scale settings belong to this part.'
    : part.quant === 2 ? 'White keys choose scale degrees; black keys modify a held chord. Choose Off or Snap to play chords from every key.'
    : part.chord === 5 || part.chord >= 6 ? 'Every key starts the chosen chord shape. Snap corrects only its root; the chord keeps its shape.'
    : 'Every key starts a chord built from the selected scale. Snap helps keep its root in scale.';
  state.pads.forEach(({ key, name }) => {
    const pad = document.querySelector(`[data-key="${key}"]`); pad.querySelector('strong').textContent = name;
    pad.setAttribute('aria-label', `Play ${part.role} ${name}`);
  });
  for (const step of document.querySelectorAll('.step')) step.setAttribute('aria-pressed', String(!!(state.steps[Number(step.dataset.step)] & (1 << Number(step.dataset.lane)))));
  transport({ playing: state.playing, recording: state.recording, armed: state.armed });
}

function transport(data) {
  if (session.state) {
    session.state.playing = data.playing;
    if (data.recording != null) session.state.recording = data.recording;
    if (data.armed != null) session.state.armed = data.armed;
  }
  $('play').setAttribute('aria-pressed', String(data.playing));
  $('play-label').textContent = data.playing ? 'Stop' : 'Play beat';
  $('play').firstElementChild.textContent = data.playing ? '■' : '▸';
  if (data.positions) for (const step of document.querySelectorAll('.step')) step.classList.toggle('playhead', Number(step.dataset.step) === data.positions[3]);
  if (!data.playing) for (const step of document.querySelectorAll('.step.playhead')) step.classList.remove('playhead');
  const recording = !!(session.state?.recording || session.state?.armed), role = selected()?.role.toLowerCase() || 'chords';
  $('record').setAttribute('aria-pressed', String(recording));
  $('record').textContent = recording ? '■ Finish take' : `● Record ${role}`;
  $('record-hint').textContent = session.state?.armed ? 'Armed. Play a pad to start the loop and recording.' : session.state?.recording ? `Recording ${role}. Finish take keeps the loop playing.` : 'Capture into a two-bar loop. Grid-snapped overdub.';
}

export const session = new JamSession(render, transport);
$('audio-start').addEventListener('click', async () => {
  const button = $('audio-start');
  if (session.loading) return;
  if (session.node && session.context.state === 'running') {
    panic(); await session.context.suspend(); enable(false); button.textContent = 'Resume audio ↗'; $('audio-status').textContent = 'Audio paused';
    message('Audio paused. Resume when you’re ready.'); return;
  }
  button.disabled = true; button.textContent = 'Warming up…';
  try {
    await session.start(); enable(!!session.state); button.classList.add('started'); button.textContent = 'Pause audio';
    $('audio-status').textContent = 'Audio ready'; message('Press Play beat to start with drums, or hear the complete starter jam.');
  } catch (error) { enable(false); button.textContent = 'Try audio again ↗'; message(error.message, true); }
  finally { button.disabled = false; }
});
$('play').addEventListener('click', togglePlay);
$('demo').addEventListener('click', () => {
  clearOwners();
  session.command('demo', [!session.state?.demo ? 1 : 0]);
  message(session.state?.demo ? 'Your notes are back. Press Play beat to keep working on your jam.' : 'Glass starter jam loaded. Change a sound, mute a part, or play along.');
});
$('reset').addEventListener('click', () => {
  clearOwners(); session.command('reset');
  message('Glass palette reset. Your session notes and edits have been cleared.');
});
$('record').addEventListener('click', () => {
  clearOwners(); session.command('toggleRecord');
});
$('panic').addEventListener('click', () => { panic(); message('All notes released. Press Play beat to start again.'); });
$('tempo').addEventListener('change', event => { const value = Number(event.target.value); if (Number.isFinite(value)) session.command('tempo', [Math.max(40, Math.min(240, value))], true); });
$('swing').addEventListener('input', event => { $('swing-value').value = `${event.target.value}%`; session.command('swing', [Number(event.target.value)], true); });
$('octave-down').addEventListener('click', () => { releaseForChange(); session.command('octaveStep', [-1]); });
$('octave-up').addEventListener('click', () => { releaseForChange(); session.command('octaveStep', [1]); });
for (const [index, id] of ['root', 'scale', 'quant', 'chord'].entries()) $(id).addEventListener('change', event => {
  releaseForChange(); session.command('setting', [selectedTrack(), index, Number(event.target.value)]);
});
document.addEventListener('keydown', event => {
  if (event.code === 'Escape') { event.preventDefault(); panic(); return; }
  if (event.target.closest('input,select,textarea,[contenteditable="true"]') || event.ctrlKey || event.metaKey || event.altKey) return;
  if (event.code === 'Space') { event.preventDefault(); if (!event.repeat) togglePlay(); return; }
  const index = SHORTCUTS.indexOf(event.code);
  if (index >= 0) { event.preventDefault(); hold(`keyboard:${event.code}`, WHITE_KEYS[index]); }
});
document.addEventListener('keyup', event => release(`keyboard:${event.code}`));
window.addEventListener('blur', panic);
document.addEventListener('visibilitychange', () => { if (document.hidden) panic(); });
window.addEventListener('pagehide', panic);
