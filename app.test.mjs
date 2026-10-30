import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,verify,createPrivateKey,createPublicKey} from 'node:crypto';
import {generatePair} from './keygen.mjs';
import {headers,configuration,check,server} from './app.mjs';
test('missing enable flag makes no requests',async()=>{
 assert.deepEqual(await check({},()=>{throw Error('must not call')}),{status:'waiting_for_credentials'});
});
test('rejects live mode, unapproved account and credential forwarding hosts',()=>{
 const e={EXN_ENABLED:'true',EXN_ACCOUNT_MODE:'demo',EXN_ACCOUNT_ID:'123',
 EXN_ALLOWED_DEMO_ACCOUNT_ID:'123',EXN_API_BASE_URL:'https://api.exness.com',
 EXN_API_KEY:'test',EXN_PRIVATE_KEY_FILE:'test'};
 for(const change of [{EXN_ACCOUNT_MODE:'real'},{EXN_ACCOUNT_ID:'456'},
 {EXN_API_BASE_URL:'https://evil.example'},{EXN_API_BASE_URL:'https://api.exness.com.evil.example'}])
 assert.throws(()=>configuration({...e,...change}));
});
test('signed decoded bytes verify and bind exact GET path',()=>{
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 const h=headers('test',privateKey,'/v1/example?a=1',123);
 const data=Buffer.from(h['EXN-DATA'],'base64url');
 assert.equal(verify(null,data,publicKey,Buffer.from(h['EXN-SIGN'],'base64url')),true);
 const p=JSON.parse(data);
 assert.equal(p.method,'GET');assert.equal(p.path,'/v1/example?a=1');
 assert.equal(p.body_hash,'47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU');
 assert.equal(h['EXN-IDEMPOTENCY-KEY'],'');
});
test('public health reveals no credentials and rejects writes',async()=>{
 const app=server();await new Promise(r=>app.listen(0,'127.0.0.1',r));
 try {
 const url='http://127.0.0.1:'+app.address().port;
 assert.deepEqual(await (await fetch(url+'/healthz')).json(),
 {service:'exness-demo-connector',status:'running',trading_enabled:false});
 assert.equal((await fetch(url,{method:'POST'})).status,404);
 const setup=await fetch(url+'/setup');
 assert.equal(setup.status,200);
 assert.match(setup.headers.get('content-security-policy'),/connect-src 'none'/);
 assert.match(await setup.text(),/Copy private key/);
 assert.equal((await fetch(url+'/keygen.mjs')).status,200);
 assert.equal((await fetch(url+'/signing.pem')).status,404);
 } finally {await new Promise(r=>app.close(r));}
});
test('browser generated PKCS8 and SPKI keys work with connector signer',async()=>{
 const first=await generatePair();const second=await generatePair();
 assert.notEqual(first.publicKey,second.publicKey);
 const privateKey=createPrivateKey(first.privateKey);
 const publicKey=createPublicKey({key:Buffer.from(first.publicKey,'base64'),format:'der',type:'spki'});
 const h=headers('test',privateKey,'/account',123);
 assert.equal(verify(null,Buffer.from(h['EXN-DATA'],'base64url'),publicKey,Buffer.from(h['EXN-SIGN'],'base64url')),true);
});
