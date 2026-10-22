import { noCache } from '../lib/bridge.js';
export default async function handler(req,res) {
  noCache(res);
  if (req.method !== 'GET') return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
  const storage = Boolean(process.env.BLOB_READ_WRITE_TOKEN ||
    (process.env.VERCEL_OIDC_TOKEN && process.env.BLOB_STORE_ID));
  return res.status(200).json({
    service:'RM11 DirectBridge', version:'0.1.0',
    healthy:true, privateStorageConfigured:storage,
    devicePaired:false, explanation:'Pairing and first device upload are required. No device control is implied.'
  });
}
