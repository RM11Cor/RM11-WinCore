import { noCache, readPairingStatus } from '../lib/bridge.js';
const PROTOCOL = '2025-06-18';
const STATUS_TOOL = {
  name:'get_rm11_pairing_status',
  title:'Check RM11 encrypted diagnostic delivery',
  description:'Check whether an RM11 phone has uploaded an encrypted diagnostic by supplying only its public SHA-256 pairing fingerprint. Does not decrypt or expose the report.',
  inputSchema:{type:'object',properties:{fingerprint:{type:'string',pattern:'^[a-fA-F0-9]{64}
function fail(id,code,message) {return {jsonrpc:'2.0',id,error:{code,message}};}
export default async function handler(req,res) {
  noCache(res);
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type, MCP-Protocol-Version, Mcp-Session-Id');
  if(req.method==='OPTIONS') return res.status(204).end();
  if(req.method!=='POST') return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
  const input=req.body;
  if(!input || typeof input !== 'object' || Array.isArray(input) || typeof input.method !== 'string') {
    return res.status(400).json(fail(null,-32600,'Invalid JSON-RPC request'));
  }
  const id=Object.hasOwn(input,'id')?input.id:null;
  if(input.method==='notifications/initialized') return res.status(202).end();
  if(input.method==='initialize') {
    return res.status(200).json(response(id,{
      protocolVersion:PROTOCOL,capabilities:{tools:{listChanged:false}},
      serverInfo:{name:'rm11-directbridge',version:'0.1.0'}
    }));
  }
  if(input.method==='ping') return res.status(200).json(response(id,{}));
  if(input.method==='tools/list') return res.status(200).json(response(id,{tools:[STATUS_TOOL]}));
  if(input.method!=='tools/call') return res.status(200).json(fail(id,-32601,'Unknown method'));
  if(input.params?.name === 'get_rm11_pairing_status') {
    const fingerprint = input.params?.arguments?.fingerprint;
    try {
      const status = await readPairingStatus(fingerprint);
      return res.status(200).json(response(id,{content:[{type:'text',text:JSON.stringify(status)}]}));
    } catch(err) {
      console.error('RM11 pairing lookup failed:',err.name);
      return res.status(200).json(response(id,{content:[{type:'text',text:'RM11 storage unavailable.'}],isError:true}));
    }
  }
  return res.status(200).json(fail(id,-32601,'Tool not available; only read-only fingerprint status is supported.')); 
}
