// Optional browser QA and public screenshot capture. Only temporary --no-journal
// operational fixtures and an explicit --demo ledger are mutated. No host data is read.
const {chromium}=require(process.env.PLAYWRIGHT_MODULE_PATH || 'playwright');
const {spawn}=require('node:child_process');
const fs=require('node:fs');const os=require('node:os');const path=require('node:path');const crypto=require('node:crypto');
const assert=require('node:assert/strict');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'athernex-operational-qa-'));
const key=crypto.randomBytes(32).toString('hex');
const url='http://127.0.0.1:8792';
let child,browser;
const captures=[];
const binary=path.resolve('target/release/athernex-siem');
const checksum=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
async function capture(page,name,mode,description){
  // Never capture a one-time credential reveal or a transient flash message.
  assert.equal(await page.locator('.secret-token').count(),0);
  await page.mouse.move(1,1);
  await page.evaluate(()=>{window.scrollTo({top:0,behavior:'instant'});return document.fonts.ready;});
  const file='siem-'+name+'.png';
  await page.screenshot({path:path.join('docs/assets',file),fullPage:true});
  const bytes=fs.readFileSync(path.join('docs/assets',file));
  captures.push({file,mode,route:new URL(page.url()).pathname,description,
    width:bytes.readUInt32BE(16),height:bytes.readUInt32BE(20),bytes:bytes.length,sha256:checksum(bytes)});
}
async function checkLayout(page,routes){
  let checks=0;
  for(const width of [1440,390]){
    await page.setViewportSize({width,height:1000});
    for(const route of routes){
      const response=await page.goto(url+route);
      assert.equal(response.status(),200,route);
      const style=await page.evaluate(()=>{
        const root=getComputedStyle(document.documentElement);
        return {overflow:document.documentElement.scrollWidth>innerWidth+1,
          background:root.getPropertyValue('--bg').trim(),cyan:root.getPropertyValue('--cyan').trim()};
      });
      assert.equal(style.overflow,false,`overflow ${width} ${route}`);
      assert.equal(style.background,'#06120f',`forest palette ${route}`);
      assert.equal(style.cyan,'#64e3eb',`cyan contour ${route}`);
      checks++;
    }
  }
  return checks;
}
function start(demo=false){child=spawn(binary,[...(demo?['--demo']:[]),'--no-journal','--db',path.join(dir,demo?'demo.db':'qa.db'),'--port','8792'],{env:{...process.env,ATHERNEX_OPERATOR_KEY:key},stdio:['ignore','ignore','pipe']});child.stderr.on('data',b=>process.stderr.write(b));}
async function ready(){for(let i=0;i<80;i++){if(child.exitCode!==null)throw Error('QA server exited before readiness');try{if((await fetch(url+'/healthz')).ok)return;}catch{}await new Promise(r=>setTimeout(r,100));}throw Error('QA server unavailable');}
async function stop(){if(child && child.exitCode===null){child.kill('SIGTERM');await new Promise(r=>child.once('exit',r));}}
(async()=>{
 try{
  start();await ready();
  browser=await chromium.launch({executablePath:process.env.CHROME_BIN || '/usr/bin/google-chrome',headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
  const page=await browser.newPage({viewport:{width:1440,height:1080},deviceScaleFactor:1});
  const errors=[];page.on('pageerror',e=>errors.push(String(e)));
  await page.goto(url);assert.match(page.url(),/login/);
  await page.locator('#key').fill(key);await page.getByRole('button',{name:'Unlock console'}).click();
  assert.equal(await page.getByText('Inject scenario',{exact:false}).count(),0);
  assert.equal(await page.locator('.metrics a').count(),4);
  await page.getByRole('link',{name:'Sources',exact:true}).click();
  await page.locator('input[name=id]').fill('public-fixture');
  await page.locator('select[name=kind]').selectOption('api');
  await page.getByRole('button',{name:'Register source'}).click();
  let token=(await page.locator('.secret-token').textContent()).trim();
  const input=Array.from({length:9},(_,i)=>({time_ms:Date.now()-9000+i*1000,source:'public-fixture',subject:'fixture-analyst',object:'ssh:192.0.2.10',kind:'authentication',outcome:'deny',severity:3,idempotency_key:'public-qa-'+i}));
  async function ingest(k=token){return fetch(url+'/api/ingest/public-fixture',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+k},body:JSON.stringify(input)});}
  assert.equal((await ingest()).status,200);
  await page.goto(url+'/source/public-fixture');
  await page.getByRole('button',{name:'Pause collection'}).click();assert.equal((await ingest()).status,400);
  await page.getByRole('button',{name:'Resume collection'}).click();assert.equal((await ingest()).status,200);
  await page.getByRole('button',{name:'Rotate credential'}).click();const old=token;token=(await page.locator('.secret-token').textContent()).trim();assert.equal((await ingest(old)).status,401);assert.equal((await ingest()).status,200);
  await page.goto(url+'/cases');await page.locator('.case-row').first().click();const caseURL=page.url();
  await page.locator('input[name=owner]').fill('Lab analyst');await page.locator('select[name=status]').selectOption('in_progress');await page.locator('textarea[name=note]').fill('Controlled public fixture. Reviewing the authentication burst and checking its source context. No host telemetry is included.');await page.getByRole('button',{name:'Save investigation'}).click();
  assert.equal(await page.locator('.case-note').count(),1);
  await page.goto(url+'/event/9');await page.getByRole('button',{name:'Preserve this event'}).click();assert.equal(page.url(),caseURL);assert.equal(await page.locator('tbody tr').count(),9);
  await page.getByRole('link',{name:'Inspect originating detection'}).click();await page.getByRole('button',{name:'Create review plan'}).click();
  await page.getByRole('button',{name:'Approve case triage'}).click();await page.getByRole('button',{name:'Execute case triage'}).click();assert.match(await page.locator('.complete-note').textContent(),/Investigation moved to triage/);
  await page.goto(caseURL);assert.equal(await page.locator('select[name=status]').inputValue(),'triage');assert.equal(await page.locator('.case-note').count(),2);
  await capture(page,'case','operational-fixture','API fixture authentication burst; assigned case, copied evidence and committed triage receipt.');
  await page.goto(url+'/source/public-fixture');await capture(page,'source','operational-fixture','Managed public-fixture source after credential rotation; no credential is displayed.');
  // Case export and manual lifecycle, including delete confirmation.
  const exportResult=await page.request.get(url+'/api/cases/1/export');assert.equal(exportResult.status(),200);assert.equal((await exportResult.json()).evidence.length,9);
  await page.goto(url+'/cases');await page.locator('input[name=title]').fill('Disposable QA case');await page.locator('select[name=severity]').selectOption('2');await page.getByRole('button',{name:'Create investigation'}).click();await page.locator('select[name=status]').selectOption('resolved');await page.getByRole('button',{name:'Save investigation'}).click();await page.locator('summary').filter({hasText:'Remove a closed investigation'}).click();await page.locator('input[name=exported]').check();await page.getByRole('button',{name:'Delete closed case'}).click();assert.equal(await page.locator('.case-row').count(),1);
  // All current primary routes on desktop/mobile, including scrolling tables.
  const paths=['/','/sources','/source/public-fixture','/cases','/case/1','/event/9','/detections','/hive','/workbench','/retention','/research'];
  let layoutChecks=await checkLayout(page,paths);
  assert.deepEqual(errors,[]);
  const before=await (await page.request.get(url+'/api/state')).json();
  await stop();start();await ready();await page.goto(url+'/login');await page.locator('#key').fill(key);await page.getByRole('button',{name:'Unlock console'}).click();
  const after=await (await page.request.get(url+'/api/state')).json();assert.equal(after.total_received,before.total_received);assert.equal(after.cases.length,1);assert.equal(after.cases[0].evidence.length,9);assert.equal(after.sources.find(s=>s.id==='public-fixture').received,9);
  await page.goto(url+'/case/1');await page.getByRole('button',{name:'Lock operator console'}).click();assert.match(page.url(),/login/);
  // Separate, explicitly synthetic ledger for the six populated platform views.
  await stop();start(true);await ready();
  await page.setViewportSize({width:1440,height:1080});
  await page.goto(url+'/login');await page.locator('#key').fill(key);
  await page.getByRole('button',{name:'Unlock console'}).click();
  const demo=await (await page.request.get(url+'/api/state')).json();
  assert.equal(demo.mode,'demo');assert.ok(demo.retained_events>=500);
  assert.equal(demo.hive.agents.length,4);
  const quarantined=demo.hive.agents.find(a=>a.state==='quarantined');
  assert.ok(quarantined,'Demo has a real policy-driven quarantine');
  await capture(page,'overview','demo','Explicit synthetic ledger; chart, metrics and stream counts derive from retained facts.');
  assert.equal(await page.locator('.source-row').count(),5);
  const counts=await page.locator('.source-count').allTextContents();
  assert.equal(counts.reduce((sum,value)=>sum+parseInt(value),0),demo.retained_events);
  // The demo stream links are usable event-explorer filters.
  await page.locator('.source-row').first().click();
  assert.ok(new URL(page.url()).searchParams.get('q'));
  assert.ok(await page.locator('tbody tr').count()>0);
  await page.goto(url+'/hive');
  await capture(page,'hive','demo','Four fixture identities, task-bound grants and a policy-enforced quarantine.');
  const agentRoute='/agent/'+quarantined.id;
  await page.goto(url+agentRoute);
  await page.locator('.decision summary').first().click();
  await capture(page,'agent','demo','Quarantined identity with an expanded access-decision trail.');
  const events=await (await page.request.get(url+'/api/events')).json();
  const eventRoute='/event/'+events.events[0].id;
  await page.goto(url+eventRoute);
  await capture(page,'event','demo','Decoded fixture fact and its actual compact binary representation.');
  await page.goto(url+'/workbench');
  await page.getByRole('button',{name:'Draft plan',exact:false}).first().click();
  assert.equal(await page.locator('.plan-card').count(),1);
  const audit=page.getByRole('region',{name:'Decision audit records'});
  await audit.focus();await page.keyboard.press('End');
  await page.waitForFunction(()=>{const el=document.querySelector('.audit-list');return el.scrollTop>0 && el.scrollHeight-el.clientHeight-el.scrollTop<2;});
  await audit.evaluate(el=>el.scrollTo({top:0,behavior:'instant'}));await audit.blur();
  await capture(page,'workbench','demo','Deterministic evidence-bound plan awaiting operator review; no model is connected.');
  await page.goto(url+'/retention');
  await capture(page,'retention','demo','Actual fixture archive blocks, storage accounting and retention controls.');
  layoutChecks+=await checkLayout(page,['/','/hive',agentRoute,eventRoute,'/workbench','/retention']);
  assert.deepEqual(errors,[]);
  const totalBytes=captures.reduce((sum,c)=>sum+c.bytes,0);
  assert.ok(totalBytes<3*1024*1024,'Keep the eight-image public gallery under 3 MiB');
  fs.writeFileSync('docs/assets/siem-screenshots.json',JSON.stringify({
    schema:'athernex.screenshot-provenance.v1',
    captured_at:new Date().toISOString(),
    capture_command:'node tools/verify_siem_ui.cjs',
    data_policy:'Temporary --no-journal ledgers only. Operational API fixtures and explicit synthetic demo. No host telemetry or credentials.',
    browser:await browser.version(),viewport:{width:1440,height:1080},
    stylesheet_sha256:checksum(fs.readFileSync('core-engines/siem/assets/app.css')),
    binary_sha256:checksum(fs.readFileSync(binary)),
    total_bytes:totalBytes,screenshots:captures
  },null,2)+'\n');
  console.log(JSON.stringify({result:'passed',layout_checks:layoutChecks,fixture_events:after.total_received,
    cases:after.cases.length,restart:'preserved cases, source credentials, counts and evidence',
    screenshots:captures.map(c=>c.file),screenshot_bytes:totalBytes}));
 }finally{if(browser)await browser.close();await stop();fs.rmSync(dir,{recursive:true,force:true});}
})().catch(e=>{console.error(e);process.exitCode=1;});
