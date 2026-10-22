import { noCache, receiveDiagnostic, normCode, MAX_BODY_BYTES } from '../lib/bridge.js';
export default async function handler(req,res) {
  noCache(res);
  if (req.method !== 'POST') return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
  const length = Number(req.headers['content-length'] || 0);
  if (length > MAX_BODY_BYTES) return res.status(413).json({error:'TOO_LARGE'});
  const input = req.body;
  if (!input || typeof input !== 'object' || !normCode(input.code) ||
      typeof input.encrypted !== 'string' || input.encrypted.length > MAX_BODY_BYTES) {
    return res.status(400).json({error:'INVALID_REQUEST'});
  }
  try {
    const result = await receiveDiagnostic(input.code.toLowerCase(), input.encrypted);
    return res.status(200).json(result);
  } catch (err) {
    if (err.message === 'DEVICE_NOT_PAIRED') return res.status(403).json({error:'DEVICE_NOT_PAIRED'});
    if (err.message === 'PRIVATE_STORE_NOT_CONFIGURED') return res.status(503).json({error:'PRIVATE_STORE_NOT_CONFIGURED'});
    if (['INVALID_PAYLOAD','INVALID_LENGTH','INVALID_SCHEMA','INVALID_DIAG','OVERSIZED_REPORT'].includes(err.message)
          || err instanceof SyntaxError) return res.status(400).json({error:'INVALID_ENCRYPTED_REPORT'});
    if (err.message.includes('authenticate data')) return res.status(403).json({error:'INVALID_DEVICE_KEY'});
    console.error('RM11 ingest storage failure:', err.name);
    return res.status(503).json({error:'STORAGE_UNAVAILABLE'});
  }
}
