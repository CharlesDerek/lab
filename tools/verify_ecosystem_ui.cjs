// Browser verification uses only a private temporary ledger and public fixture data.
const {chromium}=require(process.env.PLAYWRIGHT_MODULE_PATH||'playwright');
const {spawn}=require('node:child_process');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'athernex-ecosystem-ui-'));
const key=crypto.randomBytes(32).toString('hex'),base='http://127.0.0.1:8797',out=path.resolve('.athernex/verification');
let server,browser;
(async()=>{try{
 fs.mkdirSync(out,{recursive:true});
 server=spawn(path.resolve(process.env.SIEM_BINARY||'target/debug/athernex-siem'),['--no-journal','--db',path.join(dir,'db'),'--port','8797'],{env:{...process.env,ATHERNEX_OPERATOR_KEY:key,ATHERNEX_ENDPOINT_RELEASES:path.join(dir,'catalog')},stdio:['ignore','ignore','inherit']});
 for(let n=0;n<100;n++){if(server.exitCode!==null)throw Error('Fixture server exited');try{if((await fetch(base+'/healthz')).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
 browser=await chromium.launch({executablePath:process.env.CHROME_BIN||'/usr/bin/google-chrome',headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
 const page=await browser.newPage({viewport:{width:1440,height:1100}});
 await page.goto(base+'/control');await page.locator('input[name=key]').fill(key);await page.getByRole('button',{name:'Unlock console'}).click();await page.goto(base+'/control');
 await page.getByText('Register a resource pool',{exact:true}).click();
 const pool=page.locator('form').filter({has:page.getByRole('button',{name:'Register pool',exact:true})});
 await pool.locator('input[name=pool]').fill('fixture-rack');await pool.getByRole('button').click();assert.match(await page.locator('body').innerText(),/fixture-rack/);
 await page.getByText('Admit storage and detection work',{exact:true}).click();await page.getByRole('button',{name:'Use shared resource pool'}).click();
 await page.getByRole('button',{name:'Compact retained signal fields'}).click();assert.match(await page.locator('body').innerText(),/compaction/);
 await page.goto(base+'/cases');await page.locator('input[name=title]').fill('Public ecosystem fixture');await page.getByRole('button',{name:'Create investigation'}).click();
 const caseId=new URL(page.url()).pathname.split('/').pop();await page.goto(base+'/analysis');await page.locator('select[name=case_id]').selectOption(caseId);await page.getByRole('button',{name:'Analyze admitted evidence'}).click();
 for(let n=0;n<30;n++){if((await page.locator('body').innerText()).includes('deterministic baseline'))break;await page.waitForTimeout(100);await page.reload();}
 assert.match(await page.locator('body').innerText(),/deterministic baseline/);
 await page.screenshot({path:path.join(out,'ecosystem-analysis-1440.png'),fullPage:true});
 await page.goto(base+'/engine-updates');assert.match(await page.locator('body').innerText(),/No unexpired signed engine releases/);
 await page.goto(base+'/control');const operator=page.locator('form').filter({has:page.getByRole('button',{name:'Issue or rotate credential'})});await operator.locator('input[name=id]').fill('fixture-viewer');await operator.getByRole('button').click();
 const token=await page.locator('code').innerText();assert.match(token,/^[a-f0-9]{64}$/);const auth={authorization:'Bearer '+token};
 assert.equal((await page.request.get(base+'/api/control',{headers:auth})).status(),200);
 assert.equal((await page.request.post(base+'/api/control',{headers:auth,data:{operation:'compact_signals'}})).status(),403);
 await page.goto(base+'/control');assert.ok(!(await page.locator('body').innerText()).includes(token));
 await page.getByRole('button',{name:'Revoke fixture-viewer'}).click();assert.equal((await page.request.get(base+'/api/control',{headers:auth})).status(),401);
 for(const width of [1440,390]){await page.setViewportSize({width,height:1000});for(const route of ['control','analysis','engine-updates']){await page.goto(base+'/'+route);assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),`${route} overflow at ${width}`);await page.screenshot({path:path.join(out,`ecosystem-${route}-${width}.png`),fullPage:true});}}
 const report={pool_setup:true,background_admission:true,measured_compaction:true,baseline_analysis:true,engine_catalog:true,credential_issue_and_revoke:true,role_boundary:true,mobile_and_desktop:true};fs.writeFileSync(path.join(out,'ecosystem-ui.json'),JSON.stringify(report,null,2));console.log(JSON.stringify(report,null,2));
}finally{await browser?.close();server?.kill('SIGTERM');await new Promise(r=>setTimeout(r,250));fs.rmSync(dir,{recursive:true,force:true});}})().catch(error=>{console.error(error);process.exitCode=1;});
