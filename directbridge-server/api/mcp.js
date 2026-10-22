import { noCache, readDiagnostic, readPairingStatus } from '../lib/bridge.js';
const PROTOCOL = '2025-06-18';
const TOOL = {
  name:'get_rm11_diagnostic',
  title:'Read paired RM11 diagnostics',
  description:'Read the latest encrypted Wine/FEX diagnostic uploaded by an RM11-WinCore phone that is paired using its 256-bit access code. Read-only; cannot run commands or modify device files.',
  inputSchema: {
    type:'object',
    properties:{deviceAccessCode:{type:'string',pattern:'^[0-9a-fA-F]{64}$',description:'64-character device pairing code generated within RM11.'}},
    required:['deviceAccessCode'], additionalProperties:false
  },
  annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}
};
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
  if(input.method==='tools/list') return res.status(200).json(response(id,{tools:[STATUS_TOOL,TOOL]}));
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
  if(input.params?.name !== 'get_rm11_diagnostic') return res.status(200).json(fail(id,-32602,'Unknown tool'));
  const code=input.params?.arguments?.deviceAccessCode;
  if(typeof code!=='string' || !/^[a-f0-9]{64}$/i.test(code)) {
    return res.status(200).json(response(id,{content:[{type:'text',text:'Invalid pairing code.'}],isError:true}));
  }
  try {
    const snapshot=await readDiagnostic(code);
    const safe = snapshot.connected ? snapshot : {connected:false,reason:snapshot.reason};
    return res.status(200).json(response(id,{content:[{type:'text',text:JSON.stringify(safe)}]}));
  } catch(err) {
    console.error('RM11 MCP private storage failure:',err.name);
    return res.status(200).json(response(id,{content:[{type:'text',text:'RM11 diagnostic storage is not available.'}],isError:true}));
  }
}
,
    description:'Public device fingerprint shown in RM11 v2.5.9, not the secret key.'}},
    required:['fingerprint'],additionalProperties:false},
  annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}
};
function response(id,result) {return {jsonrpc:'2.0',id,result};}
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
  if(input.method==='tools/list') return res.status(200).json(response(id,{tools:[TOOL]}));
  if(input.method!=='tools/call') return res.status(200).json(fail(id,-32601,'Unknown method'));
  if(input.params?.name !== 'get_rm11_diagnostic') return res.status(200).json(fail(id,-32602,'Unknown tool'));
  const code=input.params?.arguments?.deviceAccessCode;
  if(typeof code!=='string' || !/^[a-f0-9]{64}$/i.test(code)) {
    return res.status(200).json(response(id,{content:[{type:'text',text:'Invalid pairing code.'}],isError:true}));
  }
  try {
    const snapshot=await readDiagnostic(code);
    const safe = snapshot.connected ? snapshot : {connected:false,reason:snapshot.reason};
    return res.status(200).json(response(id,{content:[{type:'text',text:JSON.stringify(safe)}]}));
  } catch(err) {
    console.error('RM11 MCP private storage failure:',err.name);
    return res.status(200).json(response(id,{content:[{type:'text',text:'RM11 diagnostic storage is not available.'}],isError:true}));
  }
}
