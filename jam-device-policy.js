// SPDX-License-Identifier: GPL-3.0-only
// Read-only inventory, offline package checks and simulation policy. This module
// has no install entry point. Transfer exercises live in tests/helpers only.
import { productOf, logicalImage, sha256hex, validateStockPackage,
  STOCK_V15_PRODUCT, STOCK_V15_SHA256, STOCK_V15_SIZE } from './fm1pkg.js';
import { encodeMessage, decodeMessage } from './fm1ota.js';

export const JAM_VERSION = '0.1.0-dev';
export const JAM_IDENTITIES = Object.freeze({ app: 'FM-1_700', loader: 'ota-FM-1_700', package: 'FM-1_700', rescue: 'FM-1_000' });
export const SLOOP_26 = Object.freeze({ family: 'sloop', version: '2.6', product: 'FM-1_900', size_bytes: 610019,
  sha256: '199829bb5b892feae9058158dfed7a137c83ec4d8dfc1223761be1f5614ad6a2' });
export const SIMULATED_TRANSITIONS = Object.freeze(['jambox-normal-to-jambox', 'jambox-rescue-to-jambox',
  'jambox-loader-to-jambox', 'sloop-2.6-to-jambox', 'jambox-normal-to-sloop-2.6', 'jambox-rescue-to-sloop-2.6']);
// An exact uploaded return-file profile, separate from the six-transition
// candidate manifest. Numeric device identity does not authenticate this file
// as the firmware actually running on a connected instrument.
export const FACTORY_V15 = Object.freeze({ family: 'factory', version: '15', product: STOCK_V15_PRODUCT,
  size_bytes: STOCK_V15_SIZE, sha256: STOCK_V15_SHA256 });
export const FACTORY_SIMULATED_TRANSITIONS = Object.freeze(['factory-v15-to-jambox',
  'jambox-normal-to-factory-v15', 'jambox-rescue-to-factory-v15']);
const REQUIRED_FLAGS = Object.freeze({ JAMBOX_PROTO: 1, FELUCCA_FLASH: 1, FELUCCA_PERSIST: 0, FELUCCA_OTA: 1,
  FELUCCA_OTA_DRYRUN: 0, FELUCCA_OTA_RAMONLY: 0, FELUCCA_ICONS: 0, FELUCCA_SLICE: 0 });
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

export function validateManifest(manifest) {
  keys(manifest, ['schema_version', 'family', 'version', 'release_enabled', 'hardware_validated', 'target', 'identities',
    'firmware', 'source', 'build', 'transitions', 'return_firmware', 'format_validation', 'licenses'], 'manifest');
  insist(manifest.schema_version === 1 && manifest.family === 'jamboxfm' && manifest.version === JAM_VERSION,
    'Unsupported candidate manifest version or family', 'manifest');
  insist(manifest.release_enabled === false && manifest.hardware_validated === false,
    'This policy accepts software candidates only; it authorizes no hardware installation', 'manifest');
  for (const [name, expected] of [['target', TARGET], ['identities', JAM_IDENTITIES], ['return_firmware', SLOOP_26]]) {
    keys(manifest[name], Object.keys(expected), name);
    for (const [field, value] of Object.entries(expected)) insist(manifest[name][field] === value, `${name}.${field} mismatch`, 'manifest');
  }
  keys(manifest.firmware, ['file', 'size_bytes', 'sha256'], 'firmware');
  keys(manifest.source, ['file', 'size_bytes', 'sha256', 'revision', 'dirty'], 'source');
  insist(manifest.firmware.file === `jamboxfm-${JAM_VERSION}.fwsc` && manifest.source.file === 'jamboxfm-source.zip',
    'Unexpected artifact filenames', 'manifest');
  for (const item of [manifest.firmware, manifest.source]) insist(size(item.size_bytes) && hash(item.sha256), 'Invalid artifact size or SHA-256', 'manifest');
  insist(manifest.firmware.size_bytes >= 960 && manifest.firmware.size_bytes <= 2 * 1024 * 1024, 'Invalid firmware size', 'manifest');
  insist((manifest.source.revision === null && manifest.source.dirty === null) ||
    (typeof manifest.source.revision === 'string' && /^[0-9a-f]{40}$/.test(manifest.source.revision) && typeof manifest.source.dirty === 'boolean'),
  'Invalid source provenance', 'manifest');
  keys(manifest.build, ['receipt_file', 'receipt_sha256', 'flags', 'memory_report_file', 'memory_report_sha256'], 'build');
  insist(manifest.build.receipt_file === 'build-receipt.json' && manifest.build.memory_report_file === 'memory.json' &&
    hash(manifest.build.receipt_sha256) && hash(manifest.build.memory_report_sha256), 'Invalid build evidence descriptor', 'manifest');
  // Older published receipts predate this explicit gate. New normal packages
  // require the owner-approved manual-saving profile; autosave remains off.
  const recoveryFlag = plain(manifest.build.flags) && Object.hasOwn(manifest.build.flags, 'JAMBOX_RECOVERY');
  keys(manifest.build.flags, [...Object.keys(REQUIRED_FLAGS), 'FELUCCA_CDC', 'FELUCCA_UART',
    ...(recoveryFlag ? ['JAMBOX_RECOVERY'] : [])], 'build.flags');
  insist(!recoveryFlag || manifest.build.flags.JAMBOX_RECOVERY === 1,
    'Normal candidates require JAMBOX_RECOVERY=1', 'manifest');
  insist(Object.values(manifest.build.flags).every(value => value === 0 || value === 1), 'Invalid build flags', 'manifest');
  for (const [flag, value] of Object.entries(REQUIRED_FLAGS)) insist(manifest.build.flags[flag] === value, `Required build flag ${flag} mismatch`, 'manifest');
  keys(manifest.transitions, ['mode', 'approved', 'simulated'], 'transitions');
  insist(manifest.transitions.mode === 'simulation-only' && Array.isArray(manifest.transitions.approved) && !manifest.transitions.approved.length &&
    Array.isArray(manifest.transitions.simulated) && JSON.stringify(manifest.transitions.simulated) === JSON.stringify(SIMULATED_TRANSITIONS),
  'No physical transitions are approved; simulated transitions must match this policy', 'manifest');
  const evidence = ['package_header_crc', 'entry_headers_crc', 'payload_crc', 'chip_key_match', 'canonical_reconstruction', 'app_loader_elf_match', 'memory_regions'];
  keys(manifest.format_validation, evidence, 'format_validation');
  for (const field of evidence)
    insist(manifest.format_validation[field] === true, `Missing package evidence: ${field}`, 'manifest');
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
}

export function validatePackage(bytes, expectedProduct) {
  insist(bytes instanceof Uint8Array && bytes.length >= 960 && bytes.length <= 2 * 1024 * 1024, 'Invalid package size', 'package');
  insist(expectedProduct === JAM_IDENTITIES.package || expectedProduct === SLOOP_26.product, 'Unsupported target product', 'package');
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
  payload(area, app, 'application'); payload(area, config, 'tool configuration');
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
  insist(copy.length === checked.firmware.size_bytes && await sha256hex(copy) === checked.firmware.sha256, 'Candidate SHA-256/size mismatch', 'package');
  const validated = validatePackage(copy, checked.identities.package);
  return prepared('jamboxfm', JAM_VERSION, checked.firmware.sha256, validated, checked);
}
export async function prepareReturnPackage(bytes) {
  insist(bytes instanceof Uint8Array, 'Expected package bytes', 'package');
  const copy = new Uint8Array(bytes);
  insist(copy.length === SLOOP_26.size_bytes && await sha256hex(copy) === SLOOP_26.sha256, 'Only the exact audited Sloop 2.6 return package is accepted', 'package');
  return prepared('sloop', '2.6', SLOOP_26.sha256, validatePackage(copy, SLOOP_26.product), null);
}
export async function prepareStockReturnPackage(bytes) {
  insist(bytes instanceof Uint8Array, 'Expected package bytes', 'package');
  // The factory layout differs from the canonical JamBox/Sloop layout. Every
  // factory byte is pinned by its existing independently recorded digest.
  const validated = await validateStockPackage(new Uint8Array(bytes));
  return prepared(FACTORY_V15.family, FACTORY_V15.version, FACTORY_V15.sha256, validated, null);
}
const preparedPackages = new WeakSet();
function prepared(family, version, sha256, validated, manifest) {
  const image = validated.image.slice();
  const result = Object.freeze({ family, version, sha256, product: validated.product, manifest,
    releaseEnabled: false, hardwareValidated: false, installAllowed: false, image: () => image.slice() });
  preparedPackages.add(result); return result;
}

// Inventory is evidence about a protocol response, not cryptographic device
// authentication. Numeric firmware versions alone never establish a family.
function capabilityFlags(mask) { return { updater: !!(mask & 1), temporary: !!(mask & 2), appRescue: !!(mask & 4), boundedLoader: !!(mask & 8), readOnlyCalibration: !!(mask & 16) }; }
function unknown(identity, reason) { return freeze({ identity: { text: identity.text, model: identity.model, version: identity.version }, family: 'unknown', mode: 'unknown', release: null,
  capabilities: capabilityFlags(0), recognized: false, reason, hardwareValidated: false, installAllowed: false }); }
function paddedASCII(bytes) { try { return ascii(bytes); } catch { return null; } }
export function parseFamilyProbe(packet) {
  const body = decodeMessage(packet, 0x12, 48);
  if (!body || String.fromCharCode(...body.subarray(0, 8)) !== 'JAMBOXFM' || body[8] !== 1 || body[9] > 2) return null;
  const release = paddedASCII(body.subarray(12, 32)), identity = paddedASCII(body.subarray(32, 48));
  if (!release || !identity) return null;
  return { schema: 1, mode: ['normal', 'rescue', 'loader'][body[9]], mask: u16(body, 10), release, identity };
}

// Updated from the audited Sloop editor INFO layout; exact values below are
// deliberately independent of the package's numeric transport identity.
export function parseSloopInfo(packet) {
  if (!packet || packet.length < 8 || packet[0] !== 0xf0 || packet.at(-1) !== 0xf7 ||
      ![0x7d, 0x46, 0x4c, 1].every((v, i) => packet[i + 1] === v) || [...packet.slice(1, -1)].some(v => !Number.isInteger(v) || v < 0 || v > 127)) return null;
  const bytes = Uint8Array.from(packet.slice(5, -1)); let p = 0;
  const string = max => { const start = p; while (p < bytes.length && bytes[p] && p - start <= max) { if (bytes[p] < 32 || bytes[p] > 126) return null; p++; }
    if (p >= bytes.length || p - start > max) return null; return String.fromCharCode(...bytes.subarray(start, p++)); };
  const name = string(24); if (!name || p + 5 > bytes.length) return null;
  const [engines, parameters, globals, steps, engineParameterStart] = bytes.subarray(p, p + 5); p += 5;
  if (engines > 16) return null;
  const engineNames = []; for (let i = 0; i < engines; i++) { const name = string(8); if (!name) return null; engineNames.push(name); }
  if (p + 2 !== bytes.length) return null;
  return { name, engines, parameters, globals, steps, engineParameterStart, engineNames, tracks: bytes[p], protocol: bytes[p + 1] };
}
export function classifyDevice({ identity, familyProbe = null, info = null }) {
  if (!identity || typeof identity.text !== 'string' || typeof identity.model !== 'string' || !Number.isSafeInteger(identity.version))
    return unknown({ text: '', model: '', version: 0 }, 'No complete device identity was received.');
  const parsed = /^([A-Za-z0-9-]+)_(\d+)$/.exec(identity.text);
  if (!parsed || parsed[1] !== identity.model || Number(parsed[2]) !== identity.version)
    return unknown(identity, 'The device identity fields do not agree.');
  const expectedMode = { [JAM_IDENTITIES.app]: 'normal', [JAM_IDENTITIES.rescue]: 'rescue', [JAM_IDENTITIES.loader]: 'loader' }[identity.text];
  const masks = { normal: 0x17, rescue: 0x05, loader: 0x09 };
  if (familyProbe && expectedMode && familyProbe.schema === 1 && familyProbe.mode === expectedMode && familyProbe.identity === identity.text &&
      familyProbe.release === JAM_VERSION && familyProbe.mask === masks[expectedMode])
    return freeze({ ...unknown(identity, ''), family: 'jamboxfm', mode: expectedMode, release: JAM_VERSION, capabilities: capabilityFlags(familyProbe.mask),
      recognized: true, reason: 'JamBox software-candidate protocol recognized. Physical installation is not approved.' });
  if (identity.text === SLOOP_26.product && matchesSloopInfo(info))
    return freeze({ ...unknown(identity, ''), family: 'sloop', mode: 'normal', release: '2.6', capabilities: capabilityFlags(1), recognized: true,
      reason: 'Audited Sloop 2.6 protocol profile recognized. Physical installation is not approved.' });
  return unknown(identity, expectedMode ? 'Identity lacks the exact matching JamBox family/capability response.' : 'This firmware or loader is outside the audited protocol profiles.');
}
function matchesSloopInfo(info) {
  // Filled against the shared baseline's exact INFO fixture, not a name prefix.
  return !!info && info.name === 'FELUCCA SLOOP 2.6' && info.engines === 12 && info.steps === 64 && info.tracks === 4 && info.protocol === 10 &&
    info.parameters === 71 && info.globals === 45 && info.engineParameterStart === 63 &&
    JSON.stringify(info.engineNames) === JSON.stringify(['ANALOG', 'DIGITAL', 'PHASE', 'LOFI', 'SAMPLE', 'VOICE', 'TRIO', 'WHEEL', 'GRAIN', 'FM6', 'PHYS', 'NOISE']);
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
  const familyProbe = Object.values(JAM_IDENTITIES).includes(identity.text) ?
    await query(link, encodeMessage(0x12), parseFamilyProbe, signal, timeoutMs) : null;
  const info = identity.text === SLOOP_26.product ? await query(link, [0xf0, 0x7d, 0x46, 0x4c, 1, 0xf7], parseSloopInfo, signal, timeoutMs) : null;
  return classifyDevice({ identity, familyProbe, info });
}

export function simulationTransition(source, candidate) {
  insist(preparedPackages.has(candidate), 'A validated prepared package is required');
  let name = null;
  if (source?.recognized && source.family === 'jamboxfm' && ['normal', 'rescue', 'loader'].includes(source.mode)) {
    if (candidate.family === 'jamboxfm') name = `jambox-${source.mode}-to-jambox`;
    else if (candidate.family === 'sloop' && source.mode !== 'loader') name = `jambox-${source.mode}-to-sloop-2.6`;
  } else if (source?.recognized && source.family === 'sloop' && source.release === '2.6' && source.mode === 'normal' && candidate.family === 'jamboxfm') name = 'sloop-2.6-to-jambox';
  return Object.freeze({ allowed: !!name && SIMULATED_TRANSITIONS.includes(name), transition: name, simulationOnly: true, installAllowed: false });
}
