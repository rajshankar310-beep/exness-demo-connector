import http from 'node:http';
import {createHash, createPrivateKey, sign} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';

export function configuration(env) {
  if (env.EXN_ENABLED !== 'true') return null;
  if (env.EXN_ACCOUNT_MODE !== 'demo') throw new Error('INVALID_CONFIG');
  if (!/^\d+$/.test(env.EXN_ACCOUNT_ID || '') ||
      env.EXN_ACCOUNT_ID !== env.EXN_ALLOWED_DEMO_ACCOUNT_ID) throw new Error('INVALID_CONFIG');
  if (!['https://api.exness.com','https://api.exness-api.com'].includes(env.EXN_API_BASE_URL))
    throw new Error('INVALID_CONFIG');
  if (!env.EXN_API_KEY || !env.EXN_PRIVATE_KEY_FILE) throw new Error('INVALID_CONFIG');
  return {account:env.EXN_ACCOUNT_ID, base:env.EXN_API_BASE_URL, apiKey:env.EXN_API_KEY,
    keyFile:env.EXN_PRIVATE_KEY_FILE};
}
export function headers(apiKey, key, path, timestamp=Date.now()) {
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('INVALID_KEY');
  const data=Buffer.from(JSON.stringify({api_key:apiKey,idempotency_key:'',
    timestamp,sign_version:1,method:'GET',path,
    body_hash:createHash('sha256').update('').digest('base64url')}));
  return {'EXN-API-KEY':apiKey,'EXN-IDEMPOTENCY-KEY':'',
    'EXN-TIMESTAMP':String(timestamp),'EXN-SIGN-VERSION':'1',
    'EXN-DATA':data.toString('base64url'),'EXN-SIGN':sign(null,data,key).toString('base64url')};
}
export async function check(env, request=fetch) {
  try {
    const config=configuration(env);
    if (!config) return {status:'waiting_for_credentials'};
    const key=createPrivateKey(readFileSync(config.keyFile));
    const path='/v1/configuration/accounts/'+config.account+'/account';
    const response=await request(config.base+path,{method:'GET',redirect:'error',
      headers:headers(config.apiKey,key,path),signal:AbortSignal.timeout(15000)});
    // Never retain or log broker response bodies, credentials or account data.
    if (response.body) await response.body.cancel();
    return {status:response.status===200?'read_request_accepted':'read_request_rejected',
      http_status:response.status};
  } catch {
    return {status:'configuration_or_connection_failed'};
  }
}
export function server() {
  return http.createServer((req,res)=>{
    const pages={'/setup':['setup.html','text/html; charset=utf-8'],
      '/keygen.mjs':['keygen.mjs','text/javascript; charset=utf-8']};
    if (req.method==='GET' && Object.hasOwn(pages,req.url)) {
      const [file,type]=pages[req.url];
      res.writeHead(200,{'Content-Type':type,'Cache-Control':'no-store',
        'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        'Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff'});
      res.end(readFileSync(new URL(file,import.meta.url)));
      return;
    }
    const ok=req.method==='GET' && ['/', '/healthz'].includes(req.url);
    res.writeHead(ok?200:404,{'Content-Type':'application/json','Cache-Control':'no-store',
      'X-Content-Type-Options':'nosniff'});
    res.end(JSON.stringify(ok?{service:'exness-demo-connector',status:'running',
      trading_enabled:false}:{error:'not_found'}));
  });
}
if (process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  const app=server();
  app.listen(Number(process.env.PORT || 10000),'0.0.0.0',async ()=>{
    console.log('Connector listening; order execution unavailable.');
    console.log(JSON.stringify(await check(process.env)));
  });
  process.on('SIGTERM',()=>app.close(()=>process.exit(0)));
}
