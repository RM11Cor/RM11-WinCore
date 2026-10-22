import { createHash, createDecipheriv, timingSafeEqual } from 'node:crypto';
import { get, put } from '@vercel/blob';

export const MAX_BODY_BYTES = 65000;
const CODE_PATTERN = /^[0-9a-f]{64}$/;
const MAX_PLAINTEXT_BYTES = 54000;

export function normCode(value) {
  if (typeof value !== 'string' || !CODE_PATTERN.test(value.toLowerCase())) return null;
  return value.toLowerCase();
}

// Fail closed until one device has been paired explicitly.
// The pairing digest is configured only as a sensitive Vercel environment variable.
export function deviceApproved(code) {
  const parsed = normCode(code);
  const expected = process.env.RM11_ALLOWED_CODE_DIGEST;
  if (!parsed || typeof expected !== 'string' || !/^[a-f0-9]{64}$/i.test(expected)) return false;
  const computed = createHash('sha256').update(Buffer.from(parsed, 'hex')).digest();
  const allow = Buffer.from(expected, 'hex');
  return timingSafeEqual(computed, allow);
}

function recordName(code) {
  return 'rm11/diagnostics/' + createHash('sha256').update(Buffer.from(code, 'hex')).digest('hex') + '.json';
}

export function decryptPayload(code, encrypted) {
  if (!normCode(code) || typeof encrypted !== 'string' || encrypted.length > 81000) throw new Error('INVALID_PAYLOAD');
  const binary = Buffer.from(encrypted, 'base64');
  if (binary.length < 12 + 16 || binary.length > MAX_PLAINTEXT_BYTES + 28) throw new Error('INVALID_LENGTH');
  const nonce = binary.subarray(0, 12);
  const tag = binary.subarray(binary.length - 16);
  const cipherText = binary.subarray(12, binary.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', Buffer.from(code, 'hex'), nonce);
  decipher.setAuthTag(tag);
  const clear = Buffer.concat([decipher.update(cipherText), decipher.final()]);
  if (clear.length > MAX_PLAINTEXT_BYTES) throw new Error('OVERSIZED_REPORT');
  const obj = JSON.parse(clear.toString('utf8'));
  if (!obj || typeof obj !== 'object' || obj.schema !== 'rm11.directbridge.smoke.v1') throw new Error('INVALID_SCHEMA');
  if (typeof obj.resultCode !== 'string' || obj.resultCode.length > 128) throw new Error('INVALID_DIAG');
  return obj;
}

function ensureStorage() {
  if (!process.env.BLOB_READ_WRITE_TOKEN && !(process.env.VERCEL_OIDC_TOKEN && process.env.BLOB_STORE_ID)) {
    throw new Error('PRIVATE_STORE_NOT_CONFIGURED');
  }
}

export async function receiveDiagnostic(code, encrypted) {
  if (!deviceApproved(code)) throw new Error('DEVICE_NOT_PAIRED');
  ensureStorage();
  const validated = decryptPayload(code, encrypted);
  // Never put the access code or plaintext diagnostic into persistent storage.
  const doc = JSON.stringify({schema:'rm11.encrypted.v1', storedAt:Date.now(), encrypted});
  await put(recordName(code), doc, {
    access:'private', allowOverwrite:true, contentType:'application/json', cacheControlMaxAge:60
  });
  return {accepted:true, resultCode:validated.resultCode};
}

export async function readDiagnostic(code) {
  ensureStorage();
  const parsed = normCode(code);
  if (!parsed) return {connected:false, reason:'INVALID_ACCESS_CODE'};
  if (!deviceApproved(parsed)) return {connected:false, reason:'DEVICE_NOT_PAIRED'};
  const response = await get(recordName(parsed), {access:'private', useCache:false});
  if (!response || response.statusCode !== 200 || !response.stream) {
    return {connected:false, reason:'NO_DEVICE_DIAGNOSTIC_RECEIVED'};
  }
  const raw = await new Response(response.stream).text();
  if (raw.length > 90000) throw new Error('OVERSIZED_STORAGE_RECORD');
  const data = JSON.parse(raw);
  const report = decryptPayload(parsed, data.encrypted);
  return {connected:true, storedAt:data.storedAt, report};
}

export function noCache(res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
}
