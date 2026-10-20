// SPDX-License-Identifier: GPL-3.0-only
// Pluggbox package/family policy, derived from Jambox's strict canonical package
// validator. No return-file routes or arbitrary firmware targets are accepted.
import { productOf, logicalImage, sha256hex } from './fm1pkg.js';
import { encodeMessage, decodeMessage } from './fm1ota.js';

export const PLUGG_VERSION = '0.1.0-proto';
export const PLUGG_IDENTITIES = Object.freeze({ app: 'FM-1_701', loader: 'ota-FM-1_701', package: 'FM-1_701', rescue: 'FM-1_000' });
export const SOURCE_VERSION = '0.1.0-dev';
export const SOURCE_IDENTITIES = Object.freeze({ app: 'FM-1_700', loader: 'ota-FM-1_700', rescue: 'FM-1_000' });
export const TRANSITIONS = Object.freeze(['jambox-normal-to-pluggbox']);
const REQUIRED_FLAGS = Object.freeze({ PLUGGBOX_PROTO: 1, JAMBOX_PROTO: 1, FELUCCA_FLASH: 1,
  FELUCCA_PERSIST: 0, FELUCCA_OTA: 1, FELUCCA_OTA_DRYRUN: 0, FELUCCA_OTA_RAMONLY: 0,
  FELUCCA_ICONS: 0, FELUCCA_SLICE: 0, JAMBOX_RECOVERY: 0 });
const TARGET = Object.freeze({ model: 'M-VAVE FM-1', soc: 'AC791N', platform: 'WL82', flash_bytes: 1048576,
  flash_jedec: '0x856014', chip_key: '0x980f' });
function insist(ok, message, code = 'policy') {
  if (!ok) { const error = new Error(message); error.code = code; throw error; }
}
function plain(value) { return value !== null && typeof value === 'object' &&
  (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null); }
function keys(value, expected, label) {
  insist(plain(value) && Object.keys(value).sort().join('|') === [...expected].sort().join('|'), `${label}: unexpected or missing fields`, 'manifest');
}
const hash = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const size = value => Number.isSafeInteger(value) && value > 0 && value <= 64 * 1024 * 1024;
function path(value) { return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_./-]*$/.test(value) &&
  !value.split('/').some(part => !part || part === '.' || part === '..'); }
function freeze(value) { if (value && typeof value === 'object') { for (const item of Object.values(value)) freeze(item); Object.freeze(value); } return value; }
function containsASCII(bytes, text) {
  const target = Uint8Array.from(text, char => char.charCodeAt(0));
  outer: for (let i = 0; i + target.length <= bytes.length; i++) {
    for (let j = 0; j < target.length; j++) if (bytes[i + j] !== target[j]) continue outer;
    return true;
  }
  return false;
}

export function validateManifest(manifest) {
  keys(manifest, ['schema_version', 'family', 'version', 'release_enabled', 'hardware_validated', 'target',
    'identities', 'firmware', 'source', 'build', 'transitions', 'licenses'], 'manifest');
  insist(manifest.schema_version === 1 && manifest.family === 'pluggbox' && manifest.version === PLUGG_VERSION,
    'Unsupported Pluggbox candidate version or family', 'manifest');
  insist(manifest.release_enabled === false && manifest.hardware_validated === false,
    'This policy accepts the explicit owner-trial candidate, not a validated hardware release', 'manifest');
  for (const [name, expected] of [['target', TARGET], ['identities', PLUGG_IDENTITIES]]) {
    keys(manifest[name], Object.keys(expected), name);
    for (const [field, value] of Object.entries(expected)) insist(manifest[name][field] === value, `${name}.${field} mismatch`, 'manifest');
  }
  keys(manifest.firmware, ['file', 'size_bytes', 'sha256'], 'firmware');
  keys(manifest.source, ['file', 'size_bytes', 'sha256', 'revision', 'dirty'], 'source');
  insist(manifest.firmware.file === `pluggbox-${PLUGG_VERSION}.fwsc` && manifest.source.file === 'pluggbox-source.tar.gz',
    'Unexpected Pluggbox artifact filenames', 'manifest');
  for (const item of [manifest.firmware, manifest.source]) insist(size(item.size_bytes) && hash(item.sha256), 'Invalid artifact size or SHA-256', 'manifest');
  insist(manifest.firmware.size_bytes >= 960 && manifest.firmware.size_bytes <= 2 * 1024 * 1024, 'Invalid firmware size', 'manifest');
  insist((manifest.source.revision === null && manifest.source.dirty === null) ||
    (typeof manifest.source.revision === 'string' && /^[0-9a-f]{40}$/.test(manifest.source.revision) && typeof manifest.source.dirty === 'boolean'),
  'Invalid source provenance', 'manifest');
  keys(manifest.build, ['receipt_file', 'receipt_sha256', 'flags', 'memory_report_file', 'memory_report_sha256'], 'build');
  insist(manifest.build.receipt_file === 'build-receipt.json' && manifest.build.memory_report_file === 'memory.json' &&
    hash(manifest.build.receipt_sha256) && hash(manifest.build.memory_report_sha256), 'Invalid build evidence descriptor', 'manifest');
  keys(manifest.build.flags, [...Object.keys(REQUIRED_FLAGS), 'FELUCCA_CDC', 'FELUCCA_UART'], 'build.flags');
  insist(Object.values(manifest.build.flags).every(value => value === 0 || value === 1), 'Invalid build flags', 'manifest');
  for (const [flag, value] of Object.entries(REQUIRED_FLAGS)) insist(manifest.build.flags[flag] === value, `Required build flag ${flag} mismatch`, 'manifest');
  keys(manifest.transitions, ['mode', 'approved', 'simulated'], 'transitions');
  insist(manifest.transitions.mode === 'owner-trial' && Array.isArray(manifest.transitions.approved) && !manifest.transitions.approved.length &&
    JSON.stringify(manifest.transitions.simulated) === JSON.stringify(TRANSITIONS), 'Only the explicit Jambox-to-Pluggbox owner trial is supported', 'manifest');
  insist(Array.isArray(manifest.licenses) && manifest.licenses.length > 0 && manifest.licenses.length <= 32, 'Missing license evidence', 'manifest');
  const files = new Set();
  for (const item of manifest.licenses) {
    keys(item, ['file', 'sha256', 'size_bytes'], 'license');
    insist(path(item.file) && hash(item.sha256) && size(item.size_bytes) && !files.has(item.file), 'Invalid license descriptor', 'manifest');
    files.add(item.file);
  }
  return freeze(JSON.parse(JSON.stringify(manifest)));
}

function u16(b, o) { return b[o] | b[o + 1] << 8; }
function u32(b, o) { return (b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24) >>> 0; }
function crc16(bytes) {
  let crc = 0;
  for (const byte of bytes) { crc ^= byte << 8; for (let bit = 0; bit < 8; bit++) crc = ((crc << 1) ^ (crc & 0x8000 ? 0x1021 : 0)) & 0xffff; }
  return crc;
}
function crypt(bytes, key = 0xffff) {
  const out = bytes.slice();
  for (let i = 0; i < out.length; i++) { out[i] ^= key & 255; key = ((key << 1) ^ (key & 0x8000 ? 0x1021 : 0)) & 0xffff; }
  return out;
}
function within(bytes, offset, length) { return Number.isSafeInteger(offset) && Number.isSafeInteger(length) && offset >= 0 && length >= 0 && offset + length <= bytes.length; }
function ascii(bytes, padding = 0) {
  const end = bytes.indexOf(0), n = end < 0 ? bytes.length : end;
  insist([...bytes.subarray(0, n)].every(b => b >= 32 && b <= 126) && (end < 0 || [...bytes.subarray(end + 1)].every(b => b === padding)), 'Invalid ASCII field', 'package');
  return String.fromCharCode(...bytes.subarray(0, n));
}
function entry32(bytes, offset = 0) {
  insist(within(bytes, offset, 32), 'Truncated directory header', 'package');
  const e = bytes.subarray(offset, offset + 32);
  insist(crc16(e.subarray(2)) === u16(e, 0), 'Directory header CRC mismatch', 'package');
  return { crc: u16(e, 2), offset: u32(e, 4), size: u32(e, 8), flags: e[12], reserved: e[13], index: u16(e, 14),
    rawName: e.slice(16), name: String.fromCharCode(...e.subarray(16)).split('\0')[0] };
}
function directory(entry, expected, label) {
  for (const [field, value] of Object.entries(expected)) insist(entry[field] === value, `${label}: invalid ${field}`, 'package');
  const name = [...entry.name].map(c => c.charCodeAt(0)); name.push(0);
  while (name.length < 16) name.push(255);
  insist(entry.rawName.every((b, i) => b === name[i]), `${label}: invalid name padding`, 'package');
}
function payload(bytes, entry, label) {
  insist(within(bytes, entry.offset, entry.size), `${label}: payload bounds`, 'package');
  const body = bytes.subarray(entry.offset, entry.offset + entry.size);
  insist(crc16(body) === entry.crc, `${label}: payload CRC mismatch`, 'package');
  return body;
}
function lz4(block, expected) {
  const out = new Uint8Array(expected); let p = 0, q = 0;
  const more = n => { if (n !== 15) return n; let b; do { insist(p < block.length, 'Truncated LZ4 length', 'package'); b = block[p++]; n += b; } while (b === 255); return n; };
  while (p < block.length) {
    const token = block[p++], literal = more(token >>> 4);
    insist(p + literal <= block.length && q + literal <= expected, 'LZ4 literal bounds', 'package');
    out.set(block.subarray(p, p + literal), q); p += literal; q += literal;
    if (p === block.length) break;
    insist(p + 2 <= block.length, 'Truncated LZ4 offset', 'package');
    const distance = u16(block, p); p += 2;
    const length = more(token & 15) + 4;
    insist(distance > 0 && distance <= q && q + length <= expected, 'LZ4 match bounds', 'package');
    for (let i = 0; i < length; i++, q++) out[q] = out[q - distance];
  }
  insist(q === expected, 'LZ4 decoded length mismatch', 'package'); return out;
}
function validateLoader(ota) {
  insist(ota.length >= 64 && ota.length <= 0x5000 - 0x200 + 32, 'Loader staging bounds', 'package');
  const outer = entry32(ota), inner = entry32(ota, 32);
  insist(outer.offset === 32 && outer.size === ota.length - 32 && outer.flags === 0x41 && outer.name === 'usb_hid_ota.bin', 'Invalid loader outer header', 'package');
  directory(outer, { reserved: 0, index: 0 }, 'loader outer');
  payload(ota, outer, 'loader');
  insist(inner.offset > 0 && inner.offset <= 0x14000 && inner.size === 0x01c0a800 && inner.flags === 0 && inner.name === outer.name, 'Invalid loader target', 'package');
  directory(inner, { reserved: 0, index: 0 }, 'loader inner');
  const decoded = new Uint8Array(inner.offset); let p = 64, q = 0;
  while (p < ota.length) {
    insist(p + 8 <= ota.length, 'Truncated loader block header', 'package');
    const compressed = u32(ota, p), length = u32(ota, p + 4); p += 8;
    insist(compressed > 0 && compressed <= 4096 && length > 0 && length === Math.min(4096, decoded.length - q) && p + compressed <= ota.length, 'Invalid loader block lengths', 'package');
    decoded.set(lz4(ota.subarray(p, p + compressed), length), q); p += compressed; q += length;
  }
  insist(q === decoded.length && crc16(decoded) === inner.crc, 'Decoded loader CRC mismatch', 'package');
  insist(String.fromCharCode(...decoded.subarray(0, 32)).includes('FELUCCA-LOADER-1'), 'Unsupported loader signature', 'package');
  insist(containsASCII(decoded, PLUGG_IDENTITIES.loader) && containsASCII(decoded, 'PLUGGBOX'), 'Loader lacks Pluggbox identity/family', 'package');
  return decoded;
}

export function validatePackage(bytes, expectedProduct) {
  insist(bytes instanceof Uint8Array && bytes.length >= 960 && bytes.length <= 2 * 1024 * 1024, 'Invalid package size', 'package');
  insist(expectedProduct === PLUGG_IDENTITIES.package, 'Unsupported target product', 'package');
  insist(productOf(bytes) === expectedProduct, 'Package product mismatch', 'package');
  for (let i = 0; i < 20; i++) insist(bytes[i * 48 + 47] === (i < expectedProduct.length ? (expectedProduct.charCodeAt(i) + i + 1) & 255 : 0x7d), 'Noncanonical product markers', 'package');
  const image = logicalImage(bytes), header = crypt(image.subarray(0, 64));
  insist(crc16(header.subarray(2)) === u16(header, 0), 'Package header CRC mismatch', 'package');
  insist(u32(header, 4) === image.length && u16(header, 8) === 2 && u16(header, 10) === 4 && u16(header, 12) === 0x200 && u16(header, 14) === 0 &&
    ascii(header.subarray(16)) === 'AC791N', 'Unsupported package header/target', 'package');
  const list = image.subarray(64, 224);
  insist(crc16(list) === u16(header, 2), 'Package entry-list CRC mismatch', 'package');
  const files = []; let last = 0x400;
  for (let i = 0; i < 2; i++) {
    const e = crypt(list.subarray(i * 80, (i + 1) * 80));
    const offset = u32(e, 8), length = u32(e, 12), name = ascii(e.subarray(64));
    insist(u16(e, 0) === (i ? 100 : 0) && u16(e, 2) === i && u16(e, 6) === 0 && name === (i ? 'ota.bin' : 'flash.bin') &&
      offset === ((last + 255) & ~255) && length > 0 && u32(e, 16) === ((length + 31) & ~31), 'Unsupported package entry', 'package');
    insist(e.subarray(20, 64).every(b => b === 0) && image.subarray(i ? last : 224, offset).every(b => b === 255), 'Noncanonical package padding', 'package');
    files.push(payload(image, { offset, size: length, crc: u16(e, 4) }, name)); last = offset + length;
  }
  insist(last === image.length, 'Trailing package data', 'package');
  const flash = files[0]; insist(flash.length === 0x93000, 'Unsupported flash image size', 'package');
  const flashHeader = crypt(flash.subarray(0, 32));
  insist(crc16(flashHeader.subarray(2)) === u16(flashHeader, 0), 'Flash header CRC mismatch', 'package');
  const expectedFlashHeader = '20022f104cc900f00f001010a4ff4e5d0b41e0cd781dc856417fb367cf9f'.match(/../g).map(b => parseInt(b, 16));
  insist(flashHeader.subarray(2).every((b, i) => b === expectedFlashHeader[i]), 'Unsupported flash target header', 'package');
  const top = [32, 64, 96, 128].map(offset => entry32(crypt(flash.subarray(offset, offset + 32))));
  insist(top[0].name === 'uboot.boot' && top[1].name === 'isd_config.ini' && top[2].name === 'app_dir_head' && top[2].offset === 0x4000 && top[3].name === 'key_mac', 'Unsupported flash directory', 'package');
  directory(top[0], { offset: 160, flags: 0, reserved: 0, index: 0 }, 'SPL');
  directory(top[1], { offset: top[0].offset + top[0].size, flags: 2, reserved: 0x80, index: 0 }, 'chip key');
  directory(top[2], { crc: 0xffff, size: 0xffffffff, flags: 0x81, reserved: 0xff, index: 0 }, 'app descriptor');
  directory(top[3], { crc: 0xffff, offset: 0xff000, size: 0x1000, flags: 0x12, reserved: 1, index: 0xffff }, 'protected key descriptor');
  for (const e of top.slice(0, 2)) insist(e.offset >= 160 && e.offset + e.size <= 0x4000, 'Boot-head payload bounds', 'package');
  payload(flash, top[0], 'SPL'); const isd = payload(flash, top[1], 'chip key');
  insist(isd.length >= 34 && crc16(isd.subarray(0, 32)) === u16(isd, 32), 'Chip-key blob CRC mismatch', 'package');
  insist(flash.subarray(top[1].offset + top[1].size, 0x4000).every(b => b === 255), 'Invalid boot-head padding', 'package');
  let threshold = isd.subarray(0, 16).reduce((a, b) => a + b, 0) & 255, key = 0;
  threshold = threshold >= 0xe0 ? 0xaa : threshold <= 0x10 ? 0x55 : threshold;
  for (let i = 0; i < 16; i++) if ((isd[16 + i] ^ isd[15 - i]) < threshold) key |= 1 << i;
  insist(key === 0x980f, 'Package chip key mismatch', 'package');
  const area = flash.slice(0x4000);
  for (let offset = 0; offset < area.length; offset += 32) area.set(crypt(area.subarray(offset, offset + 32), key ^ (offset >>> 2)), offset);
  const root = entry32(area), app = entry32(area, 32), config = entry32(area, 64);
  insist(root.name === 'app_area_head' && root.offset === 0x02000120 && root.size >= 0x120 && root.size <= area.length && crc16(area.subarray(32, root.size)) === root.crc, 'Application directory CRC/bounds', 'package');
  directory(root, { flags: 0x83, reserved: 0xff, index: 0 }, 'app root');
  directory(app, { flags: 0x82, reserved: 0xff, index: 0 }, 'app');
  directory(config, { flags: 0x82, reserved: 0xff, index: 0 }, 'tool configuration');
  const regions = [
    { name: 'VM', offset: 0x93000, size: 352256, flags: 0x12, reserved: 0x80, index: 0, raw: '564d00ffffffffffffffffff00800000' },
    { name: 'PRCT', offset: 0, size: 0x93000, flags: 0x92, reserved: 0x82, index: 0, raw: '5052435400ffffffffffffff434f4445' },
    { name: 'BTIF', offset: 0xe9000, size: 0x1000, flags: 0x92, reserved: 0x80, index: 0, raw: '4254494600ffffffffffffff4155544f' },
    { name: 'USR', offset: 0xea000, size: 0x12000, flags: 0x92, reserved: 0x81, index: 1, raw: '55535200ffffffffffffffffffffffff' },
  ];
  for (let i = 0; i < regions.length; i++) {
    const entry = entry32(area, 96 + 32 * i), { raw, ...fields } = regions[i];
    for (const [field, value] of Object.entries({ crc: 0xffff, ...fields })) insist(entry[field] === value, 'Invalid region descriptor', 'package');
    insist([...entry.rawName].map(b => b.toString(16).padStart(2, '0')).join('') === raw, 'Invalid region descriptor name', 'package');
  }
  insist(area.subarray(224, 0x120).every(b => b === 255), 'Invalid application directory padding', 'package');
  insist(app.name === 'app.bin' && app.offset === 0x120 && app.size === 0x8dfbc && config.name === 'cfg_tool.bin' && config.offset === app.offset + app.size && config.offset + config.size === root.size, 'Unsupported application layout', 'package');
  const appBytes = payload(area, app, 'application');
  insist(containsASCII(appBytes, PLUGG_IDENTITIES.app) && containsASCII(appBytes, 'PLUGGBOX') && containsASCII(appBytes, 'Pluggbox ' + PLUGG_VERSION), 'Application lacks Pluggbox identity/family/version', 'package');
  payload(area, config, 'tool configuration');
  const cfg = entry32(area, root.size), eq = entry32(area, root.size + 32);
  directory(cfg, { flags: 0x83, reserved: 0xff, index: 1 }, 'nested configuration');
  directory(eq, { flags: 0x82, reserved: 0xff, index: 1 }, 'EQ configuration');
  insist(cfg.name === 'cfg' && cfg.offset === 32 && cfg.size >= 64 && root.size + cfg.size <= area.length &&
    crc16(area.subarray(root.size + 32, root.size + cfg.size)) === cfg.crc && eq.name === 'eq_cfg_hw.bin' && eq.offset === 64 && eq.offset + eq.size === cfg.size,
  'Nested configuration CRC/bounds', 'package');
  payload(area.subarray(root.size), eq, 'EQ configuration');
  insist(flash.subarray(0x4000 + root.size + cfg.size).every(b => b === 255), 'Invalid flash trailing padding', 'package');
  validateLoader(files[1]);
  return { product: expectedProduct, image, chipKey: key, packageHeaderCRC: true, entryHeadersCRC: true, payloadCRC: true };
}

export async function prepareCandidate(manifest, bytes) {
  insist(bytes instanceof Uint8Array, 'Expected package bytes', 'package');
  const checked = validateManifest(manifest), copy = new Uint8Array(bytes);
  insist(copy.length === checked.firmware.size_bytes && await sha256hex(copy) === checked.firmware.sha256,
    'Candidate SHA-256/size mismatch', 'package');
  const validated = validatePackage(copy, checked.identities.package), image = validated.image.slice();
  return Object.freeze({ family: 'pluggbox', version: PLUGG_VERSION, sha256: checked.firmware.sha256,
    product: validated.product, manifest: checked, releaseEnabled: false, hardwareValidated: false,
    image: () => image.slice() });
}

function capabilityFlags(mask) { return { updater: !!(mask & 1), temporary: !!(mask & 2), appRescue: !!(mask & 4), boundedLoader: !!(mask & 8), readOnlyCalibration: !!(mask & 16) }; }
function unknown(identity, reason) { return freeze({ identity: { text: identity?.text || '', model: identity?.model || '', version: identity?.version || 0 },
  family: 'unknown', mode: 'unknown', release: null, capabilities: capabilityFlags(0), recognized: false, reason,
  hardwareValidated: false, installAllowed: false }); }
function paddedASCII(bytes) { try { return ascii(bytes); } catch { return null; } }
export function parseFamilyProbe(packet) {
  const body = decodeMessage(packet, 0x12, 48);
  if (!body || body[8] !== 1 || body[9] > 2) return null;
  const familyText = String.fromCharCode(...body.subarray(0, 8));
  const family = familyText === 'PLUGGBOX' ? 'pluggbox' : familyText === 'JAMBOXFM' ? 'jamboxfm' : null;
  if (!family) return null;
  const release = paddedASCII(body.subarray(12, 32)), identity = paddedASCII(body.subarray(32, 48));
  if (!release || !identity) return null;
  return { family, schema: 1, mode: ['normal', 'rescue', 'loader'][body[9]], mask: u16(body, 10), release, identity };
}
export function classifyDevice({ identity, familyProbe = null }) {
  if (!identity || typeof identity.text !== 'string' || typeof identity.model !== 'string' || !Number.isSafeInteger(identity.version))
    return unknown(identity, 'No complete device identity was received.');
  const parsed = /^([A-Za-z0-9-]+)_(\d+)$/.exec(identity.text);
  if (!parsed || parsed[1] !== identity.model || Number(parsed[2]) !== identity.version)
    return unknown(identity, 'The device identity fields do not agree.');
  const profiles = [
    { family: 'jamboxfm', version: SOURCE_VERSION, identities: SOURCE_IDENTITIES },
    { family: 'pluggbox', version: PLUGG_VERSION, identities: PLUGG_IDENTITIES },
  ];
  const masks = { normal: 0x17, rescue: 0x05, loader: 0x09 };
  for (const profile of profiles) {
    const expectedMode = { [profile.identities.app]: 'normal', [profile.identities.rescue]: 'rescue', [profile.identities.loader]: 'loader' }[identity.text];
    if (familyProbe && expectedMode && familyProbe.family === profile.family && familyProbe.schema === 1 &&
        familyProbe.mode === expectedMode && familyProbe.identity === identity.text &&
        familyProbe.release === profile.version && familyProbe.mask === masks[expectedMode])
      return freeze({ ...unknown(identity, ''), family: profile.family, mode: expectedMode, release: profile.version,
        capabilities: capabilityFlags(familyProbe.mask), recognized: true, reason: 'Exact firmware family, release and capabilities identified.' });
  }
  return unknown(identity, 'Identity lacks an exact supported family, release and capability response.');
}
async function query(link, bytes, parse, signal, timeoutMs) {
  if (signal?.aborted) throw signal.reason || new Error('Aborted');
  link.drain(); insist(link.send(bytes), 'Selected MIDI connection was lost', 'lost');
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (signal?.aborted) throw signal.reason || new Error('Aborted');
    const packet = await link.read(Math.max(1, end - Date.now()));
    insist(!link.lost, 'Selected MIDI connection was lost', 'lost');
    if (!packet) break;
    const result = parse(packet); if (result) return result;
  }
  return null;
}
export async function inspectDevice(identity, link, { signal, timeoutMs = 750 } = {}) {
  insist(Number.isFinite(timeoutMs) && timeoutMs > 0 && timeoutMs <= 5000, 'Invalid inventory timeout');
  const known = [...Object.values(SOURCE_IDENTITIES), ...Object.values(PLUGG_IDENTITIES)].includes(identity?.text);
  const familyProbe = known ? await query(link, encodeMessage(0x12), parseFamilyProbe, signal, timeoutMs) : null;
  return classifyDevice({ identity, familyProbe });
}
