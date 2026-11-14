import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import worker from '../src/index.js';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

class FakeD1 {
  users = [];
  otps = [];
  sessions = [];
  nextId = 1;
  prepare(sql) {
    const db = this;
    let args = [];
    return {
      bind(...values) { args = values; return this; },
      async first() {
        if (sql.includes('COUNT(*) AS n FROM users')) return { n: db.users.length };
        if (sql.includes('FROM users WHERE email=?')) return db.users.find(x => x.email === args[0]) || null;
        if (sql.includes('FROM otp_codes')) {
          const userId=args[0], setupOrLogin=sql.includes("purpose IN ('setup','login')"), resetOnly=sql.includes("purpose='reset'"), purposeArg=resetOnly?'reset':args[1], time=setupOrLogin||resetOnly?args[1]:args[2];
          const purposes = setupOrLogin ? ['setup','login'] : [purposeArg];
          return [...db.otps].reverse().find(x => x.user_id === userId && purposes.includes(x.purpose) && !x.used && x.attempts < 5 && x.expires_at > time) || null;
        }
        if (sql.includes('FROM sessions')) return db.sessions.find(x => x.token_hash === args[0] && x.expires_at > args[1]) || null;
        return null;
      },
      async run() {
        if (sql.startsWith('INSERT INTO users')) {
          const [user_id,email,password_hash,is_active,two_factor_enabled,created_at]=args;
          db.users.push({user_id,email,password_hash,is_active,two_factor_enabled,created_at});
        } else if (sql.startsWith('INSERT INTO otp_codes')) {
          const [user_id,otp_hash,purpose,expires_at]=args;
          db.otps.push({id:db.nextId++,user_id,otp_hash,purpose,expires_at,attempts:0,used:0});
        } else if (sql.startsWith('UPDATE otp_codes SET attempts=attempts+1')) {
          const row=db.otps.find(x=>x.id===args[1]); row.attempts++; row.used=args[0];
        } else if (sql.startsWith('UPDATE users SET is_active=1')) {
          const row=db.users.find(x=>x.user_id===args[0]); row.is_active=1;
        } else if (sql.startsWith('UPDATE users SET password_hash')) {
          const row=db.users.find(x=>x.user_id===args[1]); row.password_hash=args[0];
        } else if (sql.startsWith('INSERT INTO sessions')) {
          const [user_id,token_hash,expires_at,created_at]=args; db.sessions.push({user_id,token_hash,expires_at,created_at});
        } else if (sql.startsWith('DELETE FROM sessions')) {
          db.sessions=db.sessions.filter(x=>x.token_hash!==args[0]);
        }
        return { success:true };
      }
    };
  }
}

const req=(path,method='GET',body,token)=>new Request('https://worker.test'+path,{method,headers:{...(body?{'Content-Type':'application/json'}:{}),...(token?{Authorization:'Bearer '+token}:{})},body:body?JSON.stringify(body):undefined});
const read=async response=>({status:response.status,body:await response.json()});
const baseEnv=()=>({BD:new FakeD1(),AUTH_SECRET:'test-signing-key-long-enough',SETUP_KEY:'test-one-time-setup',RESEND_API_KEY:'test',MAIL_FROM:'test@example.com',TRACKER_CSV_URL:'https://sheets.test/tracker',COSTING_CSV_URL:'https://sheets.test/costing',SHEETS_WRITE_URL:'https://script.test/exec',SHEETS_WRITE_KEY:'writer-key'});

test('health reports D1 auth config without exposing secrets',async()=>{
  const {status,body}=await read(await worker.fetch(req('/api/health'),baseEnv()));
  assert.equal(status,200); assert.equal(body.authConfigured,true); assert.equal(body.writeConfigured,true); assert.equal('AUTH_SECRET' in body,false);
});

test('setup, two-step login, sheet read/append, logout, forgot password and reset',async t=>{
  const env=baseEnv(); let deliveredCode='',writeBody;
  const originalFetch=globalThis.fetch;
  globalThis.fetch=async(url,options={})=>{
    if(String(url)==='https://api.resend.com/emails'){
      const msg=JSON.parse(options.body); deliveredCode=/code is (\d{6})/.exec(msg.text)?.[1]||/code is (\d{6})/.exec(msg.text)?.[1];
      return new Response('{}',{status:200});
    }
    if(String(url).startsWith('https://sheets.test/'))return new Response('Name,Value\nExample,1',{status:200});
    if(String(url)==='https://script.test/exec'){writeBody=JSON.parse(options.body);return Response.json({ok:true,appended:writeBody.rows.length});}
    throw Error('Unexpected fetch '+url);
  };
  t.after(()=>{globalThis.fetch=originalFetch});
  let r=await read(await worker.fetch(req('/api/auth/setup','POST',{email:'user@example.com',password:'long-password-for-test',setupKey:'test-one-time-setup'}),env));
  assert.equal(r.status,200); assert.equal(env.BD.users[0].is_active,0);
  r=await read(await worker.fetch(req('/api/auth/verify','POST',{email:'user@example.com',code:deliveredCode}),env));
  assert.equal(r.status,200); assert.equal(env.BD.users[0].is_active,1); let token=r.body.token; assert.ok(token);
  r=await read(await worker.fetch(req('/api/auth/login','POST',{email:'user@example.com',password:'long-password-for-test'}),env));
  assert.equal(r.status,200); assert.equal(r.body.requiresOtp,true);
  r=await read(await worker.fetch(req('/api/auth/verify','POST',{email:'user@example.com',code:'000000'}),env));
  assert.equal(r.status,400);
  r=await read(await worker.fetch(req('/api/auth/verify','POST',{email:'user@example.com',code:deliveredCode}),env));
  assert.equal(r.status,200); token=r.body.token;
  r=await read(await worker.fetch(req('/api/sheets'),env)); assert.equal(r.status,401);
  r=await read(await worker.fetch(req('/api/sheets','GET',undefined,token),env)); assert.equal(r.status,200); assert.match(r.body.tracker,/Example,1/);
  r=await read(await worker.fetch(req('/api/sheets','PUT',{sheet:'tracker',rows:[['Header'],['Row']]},token),env));
  assert.equal(r.status,200); assert.equal(writeBody.mode,'append'); assert.equal(writeBody.key,'writer-key');
  await worker.fetch(req('/api/auth/forgot','POST',{email:'user@example.com'}),env); const resetCode=deliveredCode;
  r=await read(await worker.fetch(req('/api/auth/reset','POST',{email:'user@example.com',code:resetCode,password:'another-long-password'}),env)); assert.equal(r.status,200,JSON.stringify(r.body));
  await worker.fetch(req('/api/auth/logout','POST',{},token),env);
  r=await read(await worker.fetch(req('/api/sheets','GET',undefined,token),env)); assert.equal(r.status,401);
  r=await read(await worker.fetch(req('/api/auth/login','POST',{email:'user@example.com',password:'another-long-password'}),env)); assert.equal(r.status,200);
});

test('first account setup rejects wrong key and a second account',async()=>{
  const env=baseEnv();
  let r=await read(await worker.fetch(req('/api/auth/setup','POST',{email:'user@example.com',password:'long-password-for-test',setupKey:'wrong'}),env));
  assert.equal(r.status,403);
  env.BD.users.push({user_id:'existing',email:'existing@example.com'});
  r=await read(await worker.fetch(req('/api/auth/setup','POST',{email:'user@example.com',password:'long-password-for-test',setupKey:'test-one-time-setup'}),env));
  assert.equal(r.status,409);
});

