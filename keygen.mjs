export async function generatePair() {
  const pair=await crypto.subtle.generateKey({name:'Ed25519'},true,['sign','verify']);
  const publicBytes=await crypto.subtle.exportKey('spki',pair.publicKey);
  const privateBytes=await crypto.subtle.exportKey('pkcs8',pair.privateKey);
  const b64=bytes=>btoa(String.fromCharCode(...new Uint8Array(bytes)));
  const publicKey=b64(publicBytes);
  const privateKey='-----BEGIN PRIVATE KEY-----\n'+b64(privateBytes).match(/.{1,64}/g).join('\n')+'\n-----END PRIVATE KEY-----\n';
  return {publicKey,privateKey};
}
if (typeof document!=='undefined') {
  let keys;
  const el=id=>document.getElementById(id);
  el('generate').onclick=async()=>{
    el('generate').disabled=true;
    try {
      keys=await generatePair();
      el('public').value=keys.publicKey;
      el('results').hidden=false;
      el('message').textContent='Key pair generated. Save the private key before closing this tab.';
    } catch {
      el('message').textContent='This browser could not generate an Ed25519 key. Try an updated Chrome browser over HTTPS.';
      el('generate').disabled=false;
    }
  };
  for(const [button,field] of [['copyPrivate','privateKey'],['copyPublic','publicKey']]) {
    el(button).onclick=async()=>{
      try {
        await navigator.clipboard.writeText(keys[field]);
        el('message').textContent=field==='privateKey'?'Private key copied. Paste it directly into Render Secret Files.':'Public key copied. Paste it into Exness.';
      } catch {el('message').textContent='Clipboard access blocked. Download the private key, or select the public key text manually.';}
    };
  }
  el('download').onclick=()=>{
    const url=URL.createObjectURL(new Blob([keys.privateKey],{type:'application/x-pem-file'}));
    const a=document.createElement('a');a.href=url;a.download='signing.pem';a.click();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
  };
  window.addEventListener('beforeunload',e=>{if(keys){e.preventDefault();e.returnValue='';}});
}
