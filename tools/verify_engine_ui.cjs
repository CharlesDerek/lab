// Public fixtures test review controls; no scanner or installation is executed.
const {chromium}=require(process.env.PLAYWRIGHT_MODULE_PATH||'playwright');
const {spawn,execFileSync}=require('node:child_process');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const crypto=require('node:crypto'),net=require('node:net'),assert=require('node:assert/strict');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'athernex-engine-ui-'));
const agent=path.resolve(process.env.ATHERNEX_VERIFY_AGENT||'target/release/athernex-endpoint');
const binary=path.resolve(process.env.ATHERNEX_VERIFY_SERVER||'target/release/athernex-siem');
const output=path.resolve('.athernex/verification');
let server,browser;
(async()=>{try{
  fs.mkdirSync(output,{recursive:true});
  const probe=net.createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));
  const port=probe.address().port;await new Promise(r=>probe.close(r));const origin=`http://127.0.0.1:${port}`;
  const key=crypto.randomBytes(32).toString('hex');
  const publicKey=execFileSync(agent,['release-keygen',path.join(dir,'keys')],{encoding:'utf8'}).trim();
  const fingerprint=crypto.createHash('sha256').update(Buffer.from(publicKey,'hex')).digest('hex');
  const publicFile=path.join(dir,'public-key.txt');fs.writeFileSync(publicFile,publicKey);
  const content=path.join(dir,'content'),catalog=path.join(dir,'releases','engines');
  const roles={scanner:'bin/clamscan',updater:'bin/freshclam',daemon:'sbin/clamd',monitor:'sbin/clamonacc',library_dirs:['lib'],certificates:'etc/certs'};
  for(const name of [roles.scanner,roles.updater,roles.daemon,roles.monitor,'lib/libfixture.so','etc/certs/fixture.crt']){
    const file=path.join(content,name);fs.mkdirSync(path.dirname(file),{recursive:true});
    if(name.startsWith('bin/')||name.startsWith('sbin/'))fs.copyFileSync('/bin/true',file);
    else fs.writeFileSync(file,'Public browser fixture '+name);
  }
  const rolesFile=path.join(dir,'roles.json');fs.writeFileSync(rolesFile,JSON.stringify(roles));
  const releaseIds=[];
  for(const sequence of [1,2]){
    const manifest=path.join(dir,`release-${sequence}.json`);
    execFileSync(agent,['engine-sign',path.join(dir,'keys/release.pk8'),content,rolesFile,'linux-x86_64','fixture','stable',String(sequence),String(Date.now()+3600000),manifest]);
    releaseIds.push(execFileSync(agent,['engine-publish',manifest,content,publicFile,catalog],{encoding:'utf8'}).trim());
  }
  const artifacts=path.join(dir,'artifacts');fs.mkdirSync(artifacts);
  fs.copyFileSync(agent,path.join(artifacts,'athernex-endpoint-linux-x86_64'));
  fs.writeFileSync(path.join(artifacts,'linux-x86_64.json'),JSON.stringify({target:'linux-x86_64',version:'fixture',signing:'development-unsigned',sha256:crypto.createHash('sha256').update(fs.readFileSync(agent)).digest('hex')}));
  server=spawn(binary,['--no-journal','--db',path.join(dir,'server.db'),'--port',String(port)],{env:{...process.env,ATHERNEX_OPERATOR_KEY:key,ATHERNEX_ENDPOINT_RELEASES:path.dirname(catalog),ATHERNEX_ENDPOINT_ARTIFACTS:artifacts},stdio:['ignore','ignore','inherit']});
  for(let i=0;i<100;i++){if(server.exitCode!==null)throw Error('Fixture server exited');try{if((await fetch(origin+'/healthz')).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
  browser=await chromium.launch({executablePath:process.env.CHROME_BIN||'/usr/bin/google-chrome',headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
  const page=await browser.newPage({viewport:{width:1440,height:1000}});
  await page.goto(origin+'/endpoints');await page.locator('input[name=key]').fill(key);await page.getByRole('button',{name:'Unlock console'}).click();
  const devices=[];
  async function post(device,suffix,data){const response=await page.request.post(origin+`/api/endpoint/${device.id}/${suffix}`,{headers:{authorization:'Bearer '+device.credential},data});assert.equal(response.status(),200,await response.text());return response.json();}
  async function heartbeat(device){const now=Date.now();await post(device,'heartbeat',{version:'fixture-agent',capabilities:['inventory'],scanner:'Public browser scanner',realtime:true,signature_version:'Public signatures',spool_events:0,error:'',protection:{state:'active',backend:'fixture',checked_ms:now,roots:['/public/fixture'],excluded_uid:1000,pending_events:0,dropped_events:0,error:''},collector:{mode:'snapshot',last_attempt_ms:now,last_success_ms:now,process_count:1,connection_count:0,pending_changes:0,incomplete:false,error:''}});}
  const engineHealth={managed:true,automatic:true,supervised:true,target:'linux-x86_64',key_fingerprint:fingerprint,channel:'stable',highwater:0,staged_release:null,installed_release:null,phase:'ready',error:''};
  for(let n=0;n<2;n++){
    await page.goto(origin+'/endpoints');await page.locator('input[name=server]').fill(origin+'/');await page.locator('input[name=antivirus]').uncheck();
    const pending=page.waitForEvent('download');await page.getByRole('button',{name:'Download installer'}).click();
    const download=await pending,archive=path.join(dir,`installer-${n}.zip`),unpacked=path.join(dir,`installer-${n}`);await download.saveAs(archive);execFileSync('unzip',['-q',archive,'-d',unpacked]);
    const bootstrap=JSON.parse(fs.readFileSync(path.join(unpacked,'bootstrap.json'),'utf8'));
    const device={id:crypto.randomBytes(32).toString('hex'),credential:crypto.randomBytes(32).toString('hex')};devices.push(device);
    const response=await page.request.post(origin+'/api/endpoint/enroll',{data:{protocol:1,enrollment_token:bootstrap.enrollment_token,endpoint_id:device.id,credential:device.credential,hostname:`Public engine device ${n+1} <review>`,platform:'linux',arch:'x86_64',version:'fixture-agent'}});assert.equal(response.status(),200);
    await heartbeat(device);await post(device,'engines/health',engineHealth);
  }
  async function propose(install){await page.goto(origin+'/engine-updates');const form=page.locator('form').filter({has:page.getByRole('button',{name:'Propose engine delivery',exact:true})});await form.locator('select[name=release_id]').selectOption(releaseIds[0]);await form.locator('select[name=endpoint]').selectOption(devices[0].id);await form.locator('input[name=install]').setChecked(install);await form.getByRole('button').click();}
  await propose(false);await page.getByText('Exact delivery approval',{exact:true}).click();
  const pending=(await (await page.request.get(origin+'/api/control/engines')).json())[0];assert.match(await page.locator('body').innerText(),new RegExp(pending.plan_hash));assert.equal(pending.deployment.install,false);
  await page.getByRole('button',{name:'Approve exact engine delivery'}).click();await page.getByRole('button',{name:'Cancel delivery',exact:true}).click();
  assert.equal((await (await page.request.get(origin+'/api/control/engines')).json())[0].state,'cancelled');
  await propose(true);await page.getByRole('button',{name:'Approve exact engine delivery'}).click();
  const current=(await (await page.request.get(origin+'/api/control/engines')).json())[0];assert.equal(current.deployment.install,true);
  const receipt={deployment_id:current.deployment.id,release_id:releaseIds[0],outcome:'staged',detail:'Controlled browser staging result',finished_ms:Date.now()};
  await post(devices[0],'engines/receipt',receipt);await post(devices[0],'engines/health',{...engineHealth,phase:'staged',highwater:1,staged_release:releaseIds[0]});
  await post(devices[0],`engines/${current.deployment.id}/install`,{});
  await post(devices[0],'engines/receipt',{...receipt,outcome:'installed',detail:'Controlled browser installation result',finished_ms:Date.now()});
  await post(devices[0],'engines/health',{...engineHealth,phase:'installed',highwater:1,installed_release:releaseIds[0]});
  await page.goto(origin+'/engine-updates');assert.match(await page.locator('body').innerText(),/Controlled browser installation result/);
  for(const device of devices)await heartbeat(device);
  const group=page.locator('form').filter({has:page.getByRole('button',{name:'Propose engine rollout',exact:true})});await group.locator('select[name=release_id]').selectOption(releaseIds[1]);await group.locator('input[name=name]').fill('Public engine canary review');await group.locator('input[name=deadline_minutes]').fill('30');await group.locator(`select[name=target_${devices[0].id}]`).selectOption('canary');await group.locator(`select[name=target_${devices[1].id}]`).selectOption('later');await group.getByRole('button').click();
  assert.match(await page.locator('body').innerText(),/Public engine canary review · pending/);
  await page.getByRole('button',{name:'approve exact engine rollout'}).click();
  let dispatched=false;for(let n=0;n<100;n++){const records=await (await page.request.get(origin+'/api/control/engine-rollouts')).json();if(records[0].members[0].deployment_id){dispatched=true;break;}await page.waitForTimeout(100);}assert.ok(dispatched,'Canary deployment was not dispatched');
  await page.reload();await page.getByRole('button',{name:'pause exact engine rollout'}).click();assert.equal(await page.getByRole('button',{name:'Cancel delivery',exact:true}).count(),0);assert.match(await page.locator('body').innerText(),/use its group controls above/);
  const rollout=(await (await page.request.get(origin+'/api/control/engine-rollouts')).json())[0];assert.equal(rollout.state,'paused');assert.deepEqual(rollout.plan.request.endpoint_ids,devices.map(d=>d.id));
  for(const width of [1440,390]){await page.setViewportSize({width,height:1000});await page.goto(origin+'/engine-updates');await page.getByText('Exact approval content',{exact:true}).click();await page.getByText('Exact delivery approval',{exact:true}).first().click();assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),`overflow at ${width}`);await page.evaluate(()=>window.scrollTo(0,0));await page.screenshot({path:path.join(output,`engine-review-${width}.png`),fullPage:true});}
  await page.getByRole('button',{name:'resume exact engine rollout'}).click();await page.getByRole('button',{name:'cancel exact engine rollout'}).click();assert.equal((await (await page.request.get(origin+'/api/control/engine-rollouts')).json())[0].state,'cancelled');
  console.log(JSON.stringify({exact_device_review_and_hash:'passed',cancel_after_approval:'passed',installation_and_staging_receipts:'passed',reviewed_canary_membership:'passed',group_members_use_rollout_controls:'passed',pause_resume_cancel:'passed',desktop_mobile_layouts:2,scope:'Controlled browser health and receipts; no engine installation executed'},null,2));
}finally{await browser?.close();if(server&&server.exitCode===null){server.kill('SIGTERM');await new Promise(r=>server.once('exit',r));}fs.rmSync(dir,{recursive:true,force:true});}})().catch(error=>{console.error(error);process.exitCode=1;});
