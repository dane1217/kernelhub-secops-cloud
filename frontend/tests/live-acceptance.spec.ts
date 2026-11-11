import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';

function totp(secret:string) {
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits='';
  for(const character of secret.toUpperCase().replace(/[^A-Z2-7]/g,'')) bits+=alphabet.indexOf(character).toString(2).padStart(5,'0');
  const bytes=[];for(let i=0;i+8<=bits.length;i+=8) bytes.push(parseInt(bits.slice(i,i+8),2));
  const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));
  const hash=createHmac('sha1',Buffer.from(bytes)).update(counter).digest(),offset=hash[hash.length-1]&15;
  return String((hash.readUInt32BE(offset)&0x7fffffff)%1000000).padStart(6,'0');
}

test('real OIDC + OTP, organization, ingestion, evidence, incident and tenant isolation',async({page,baseURL})=>{
  test.skip(process.env.RUN_LIVE_BROWSER_TESTS!=='1','Requires the generated local Compose realm; never point at production.');
  test.setTimeout(180000);
  const login=readFileSync('../.local/pilot-login.txt','utf8');
  const username=login.match(/^Username: (.+)$/m)![1], password=login.match(/^Password: (.+)$/m)![1];
  await expect.poll(async()=>{try{return (await page.request.get(`${baseURL}/idp/realms/kernelhub/.well-known/openid-configuration`)).status()}catch{return 0}}, {timeout:60000}).toBe(200);
  await page.goto('/');
  await page.getByRole('link',{name:/sign in securely/i}).click();
  await page.locator('#username').fill(username);
  await page.locator('#password').fill(password);
  await page.locator('#kc-login').click();
  console.log('OIDC form state',JSON.stringify({path:new URL(page.url()).pathname,
    headings:await page.locator('h1,h2,[role="alert"]').allTextContents(),
    inputs:await page.locator('input').evaluateAll(es=>es.map(e=>({id:e.id,name:e.getAttribute('name'),type:e.getAttribute('type')}))),
    linkIds:await page.locator('a[id]').evaluateAll(es=>es.map(e=>e.id))}));
  await expect(page.locator('#mode-manual')).toBeVisible({timeout:15000});
  await page.locator('#mode-manual').click();
  const secret=await page.locator('#kc-totp-secret-key').innerText();
  await page.locator('#totp').fill(totp(secret));
  if(await page.locator('#userLabel').count()) await page.locator('#userLabel').fill('Synthetic CI authenticator');
  await page.locator('#saveTOTPBtn').click();
  await expect(page.getByRole('heading',{name:'Overview',exact:true})).toBeVisible({timeout:30000});
  const meResponse=await page.request.get('/api/me');expect(meResponse.status()).toBe(200);
  const me=await meResponse.json();expect(me.platform_admin).toBe(true);
  await page.getByRole('button',{name:/platform administration/i}).click();
  const organizationName=`Synthetic acceptance ${Date.now()}`;
  await page.getByLabel('Organization name').fill(organizationName);
  await page.getByRole('button',{name:'Create organization',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Overview',exact:true})).toBeVisible();
  const orgs=await (await page.request.get('/api/orgs')).json();const org=orgs.find((o:any)=>o.name===organizationName);
  await page.getByRole('button',{name:'Integrations',exact:false}).click();
  await page.getByLabel('Source name').fill('Synthetic acceptance source');
  await page.getByLabel('Parser',{exact:true}).selectOption('normalized');
  await page.getByRole('button',{name:'Create ingestion credential'}).click();
  const ingestionKey=await page.locator('.secret code').innerText();
  const start=Date.now()-30000;
  const telemetry=Array.from({length:5},(_,i)=>({event_id:`acceptance-${start}-${i}`,timestamp:new Date(start+i*1000).toISOString(),action:'auth.failure',host:'synthetic-acceptance',user:'synthetic-user',source_ip:'192.0.2.50',synthetic:true}));
  const accepted=await page.request.post('/api/ingest',{headers:{Authorization:`Bearer ${ingestionKey}`},data:telemetry});expect(accepted.status()).toBe(202);
  await page.getByRole('button',{name:'Dismiss',exact:true}).click();
  const path=`/api/orgs/${org.id}`;
  await expect.poll(async()=> (await (await page.request.get(path+'/alerts')).json()).length,{timeout:90000}).toBeGreaterThan(0);
  const alerts=await (await page.request.get(path+'/alerts')).json();const alert=alerts.find((a:any)=>a.rule_id==='KH-001');
  const evidence=await (await page.request.get(path+'/alerts/'+alert.id)).json();expect(evidence.evidence).toHaveLength(5);
  const searched=await (await page.request.get(path+'/events?action=auth.failure')).json();expect(searched.total).toBe(5);
  await page.getByRole('button',{name:'Alerts',exact:false}).first().click();
  await page.getByRole('button',{name:'Repeated failed authentication',exact:true}).click();
  await expect(page.getByRole('dialog')).toContainText('5 supporting events');
  await page.getByRole('button',{name:'Create incident',exact:true}).click();
  await page.getByRole('button',{name:'Repeated failed authentication',exact:true}).click();
  for(const status of ['triaging','investigating','resolved']) {
    await page.getByLabel('Next status').selectOption(status);
    if(status==='resolved') await page.getByLabel('Resolution',{exact:true}).selectOption('benign_activity');
    await page.getByLabel('Customer summary').fill('Synthetic acceptance: activity reviewed and resolved.');
    await page.getByRole('button',{name:'Update incident',exact:true}).click();
    await expect.poll(async()=> (await (await page.request.get(path+'/incidents')).json())[0].status).toBe(status);
    await expect(page.getByRole('button',{name:'Update incident',exact:true})).toBeEnabled();
  }
  const audits=await (await page.request.get(path+'/audit')).json();expect(audits.some((a:any)=>a.action==='incident.transition')).toBe(true);
  const headers={'Origin':new URL(page.url()).origin,'X-CSRF-Token':me.csrf};
  const other=await (await page.request.post('/api/orgs',{headers,data:{name:'Synthetic independent tenant'}})).json();
  const scoped=await (await page.request.post(`/api/orgs/${other.id}/credentials`,{headers,data:{role:'viewer'}})).json();
  expect((await page.request.get(path+'/events',{headers:{Authorization:`Bearer ${scoped.credential}`}})).status()).toBe(403);
  const isolated=await page.request.get(`/api/orgs/${other.id}/events`,{headers:{Authorization:`Bearer ${scoped.credential}`}});expect(isolated.status()).toBe(200);expect((await isolated.json()).total).toBe(0);
});
