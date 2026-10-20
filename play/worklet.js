// SPDX-License-Identifier: GPL-3.0-only
// Same C instrument in Node contract tests and the browser audio thread.
export const WHITE_KEYS = [0, 2, 4, 6, 7, 9, 11, 12, 14, 16, 18, 19, 21, 23, 24, 26];

export class JamEngine {
  constructor(module) {
    if (WebAssembly.Module.imports(module).length) throw new Error('Unexpected firmware runtime imports.');
    this.w = new WebAssembly.Instance(module, {}).exports;
    this.w._initialize?.();
    this.w.jam_preview_init();
    this.frames = this.w.preview_frames();
    this.sampleRate = this.w.preview_rate();
    this.bytes = new Uint8Array(this.w.memory.buffer);
    this.audio = new Float32Array(this.w.memory.buffer, this.w.preview_render(), this.frames * 2);
    this.cursor = this.frames;
  }
  text(pointer) {
    let value = '';
    for (let i = 0; i < 80 && this.bytes[pointer + i]; i++) value += String.fromCharCode(this.bytes[pointer + i]);
    return value;
  }
  value(field, track = 0, index = 0) { return this.w.jam_preview_value(field, track, index); }
  command(command) {
    const w = this.w, args = command.args || [];
    // An explicit whitelist: page messages cannot call arbitrary WASM exports.
    switch (command.type) {
      case 'demo': w.plugg_preview_demo(...args); break;
      case 'reset': w.plugg_preview_reset(); break;
      case 'key': w.jam_preview_key(...args); break;
      case 'select': w.jam_preview_select(...args); break;
      case 'play': w.jam_preview_play(...args); break;
      case 'togglePlay': w.jam_preview_toggle_play(); break;
      case 'record': w.jam_preview_record(...args); break;
      case 'toggleRecord': w.jam_preview_record(!(this.value(19) || this.value(20))); break;
      case 'tempo': w.jam_preview_tempo(...args); break;
      case 'swing': w.jam_preview_swing(...args); break;
      case 'octave': w.jam_preview_octave(...args); break;
      case 'octaveStep': w.jam_preview_octave(this.value(4) + args[0]); break;
      case 'mute': w.jam_preview_mute(...args); break;
      case 'toggleMute': w.jam_preview_mute(args[0], !this.value(5, args[0])); break;
      case 'sound': w.jam_preview_sound(...args); break;
      case 'soundStep': {
        const count = w.jam_sound_count(args[0]);
        if (count) w.jam_preview_sound(args[0], (w.jam_sound_index(args[0]) + args[1] + count) % count);
        break;
      }
      case 'macro': w.jam_macro_set(...args); break;
      case 'setting': w.jam_preview_setting(...args); break;
      case 'step': w.jam_preview_drum_step(...args); break;
      case 'release': w.jam_preview_release(); break;
      case 'panic': w.jam_preview_panic(); break;
      default: throw new Error('Unknown instrument command.');
    }
  }
  snapshot() {
    const w = this.w;
    return {
      selected: this.value(0), playing: !!this.value(1), tempo: this.value(2), swing: this.value(3), octave: this.value(4),
      recording: this.value(19), armed: !!this.value(20), demo: !!w.plugg_preview_demo_active(),
      tracks: [0, 1, 2, 3].map(role => {
        const track = w.jam_role_track(role);
        return { track, role: this.text(w.jam_role_name(track)), sound: this.text(w.jam_sound_name(track)),
          soundIndex: w.jam_sound_index(track), soundCount: w.jam_sound_count(track), muted: !!this.value(5, track),
          chord: this.value(6, track), scale: this.value(7, track), root: this.value(8, track), quant: this.value(9, track),
          macros: [0, 1, 2, 3].map(knob => ({ name: this.text(w.jam_macro_name(track, knob)), value: w.jam_macro_get(track, knob) })),
          length: this.value(14, track), events: this.value(21, track) };
      }),
      pads: WHITE_KEYS.map(key => ({ key, name: this.text(w.jam_preview_pad_name(key)) })),
      drumLanes: [0, 3, 4, 5, 7].map(lane => ({ lane, name: this.text(w.jam_preview_lane_name(lane)) })),
      steps: Array.from({ length: 32 }, (_, step) => this.value(13, 3, step)),
    };
  }
  transport() {
    return { playing: !!this.value(1), recording: this.value(19), armed: !!this.value(20),
      positions: [0, 1, 2, 3].map(track => this.value(10, track)), keys: this.value(12) };
  }
  render(left, right) {
    for (let i = 0; i < left.length; i++) {
      if (this.cursor >= this.frames) { this.w.preview_render(); this.cursor = 0; }
      left[i] = this.audio[this.cursor * 2];
      right[i] = this.audio[this.cursor * 2 + 1];
      this.cursor++;
    }
  }
}

// Fixed capacity and a fixed per-quantum budget. Overflow releases notes and
// stops the clock rather than losing a note-off behind an unbounded backlog.
export class CommandQueue {
  constructor(capacity = 64) {
    this.items = new Array(capacity); this.capacity = capacity; this.read = 0; this.write = 0; this.count = 0;
    this.needsPanic = false;
  }
  clear() { this.read = this.write = this.count = 0; }
  panic() { this.clear(); this.needsPanic = true; }
  add(commands) {
    if (!Array.isArray(commands) || commands.length > this.capacity - this.count) { this.panic(); return false; }
    for (const command of commands) {
      this.items[this.write] = command; this.write = (this.write + 1) % this.capacity; this.count++;
    }
    return true;
  }
  drain(engine, budget = 16) {
    let changed = false;
    if (this.needsPanic) { engine.command({ type: 'panic' }); this.needsPanic = false; changed = true; }
    for (let n = 0; n < budget && this.count; n++) {
      const command = this.items[this.read]; this.items[this.read] = null;
      this.read = (this.read + 1) % this.capacity; this.count--;
      engine.command(command); changed = true;
    }
    return changed;
  }
}

if (typeof registerProcessor === 'function') {
  class JamProcessor extends AudioWorkletProcessor {
    constructor(options) {
      super();
      this.engine = new JamEngine(options.processorOptions.module);
      this.queue = new CommandQueue();
      this.elapsed = 0; this.peak = 0; this.sequence = 0; this.ackPending = false;
      this.port.onmessage = ({ data }) => {
        if (data.type === 'panic') { this.queue.panic(); this.ackPending = true; }
        else if (data.type === 'commands') {
          this.sequence = data.sequence;
          this.ackPending = true;
          if (!this.queue.add(data.commands)) this.port.postMessage({ warning: 'Input queue full. Notes released; press Play to continue.' });
        }
      };
      this.port.postMessage({ ready: true, state: this.engine.snapshot() });
    }
    process(_input, outputs) {
      const [left, right] = outputs[0];
      try {
        const changed = this.queue.drain(this.engine);
        this.engine.render(left, right);
        for (let i = 0; i < left.length; i++) this.peak = Math.max(this.peak, Math.abs(left[i]), Math.abs(right[i]));
        this.elapsed += left.length;
        if (changed) this.port.postMessage({ state: this.engine.snapshot() });
        if (this.ackPending && this.queue.count === 0) {
          this.port.postMessage({ ack: this.sequence }); this.ackPending = false;
        }
        if (this.elapsed >= 2048) {
          this.port.postMessage({ transport: this.engine.transport(), peak: this.peak });
          this.elapsed = 0; this.peak = 0;
        }
      } catch (error) {
        this.queue.panic(); left.fill(0); right.fill(0);
        this.port.postMessage({ error: error.message });
        return false;
      }
      return true;
    }
  }
  registerProcessor('pluggbox-preview', JamProcessor);
}
