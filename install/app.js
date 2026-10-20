// SPDX-License-Identifier: GPL-3.0-only
// UI only: package validation and all device writes stay in the guarded controller.
const PENDING = 'FM-1 installer is being prepared. You can play Pluggbox in your browser now.';
const STAGES = ['checking','start','verify','loader','write','reboot','done'];
const CODES = ['aborted','permission','ambiguous','notfound','identity','model','lost','timeout','stopped','noloader','noreturn','mismatch','foreign','badreq','bundle','manifest','trial','package','hash','busy','ineligible','configuration','operation','policy'];
const safeIdentity = value => /^(?:ota-)?FM-1_\d{3}$/.test(value?.text || '') ? value.text : null;
const safeCode = error => CODES.includes(error?.code) ? error.code : 'unknown';
function trialRelease(value) {
  return value && Object.keys(value).sort().join('|') === ['schema_version','family','status','install_available','hardware_validated','version','manifest_sha256','firmware_sha256'].sort().join('|') &&
    value.schema_version===1 && value.family==='pluggbox' && value.status==='experimental' && value.install_available===true && value.hardware_validated===false && value.version==='0.1.0-proto' &&
    /^[a-f0-9]{64}$/.test(value.manifest_sha256 || '') && /^[a-f0-9]{64}$/.test(value.firmware_sha256 || '');
}
function beforeStart(error) {
  if (error?.name==='NotAllowedError' || error?.name==='SecurityError' || error?.code==='permission') return 'MIDI access wasn’t allowed. Allow MIDI and system exclusive access in this page’s browser permissions, then connect again.';
  if (error?.code==='ambiguous') return 'Connect only one FM-1. Disconnect other matching MIDI devices and check the selected ports again. No update was started.';
  if (error?.code==='lost' || error?.code==='notfound') return 'The FM-1 disconnected. Check its USB cable and selected ports, then check again. No update was started.';
  if (error?.code==='ineligible' || error?.code==='identity') return 'This trial requires the supported Jambox build in normal mode. Check its firmware and selected ports. No update was started.';
  return 'The check could not finish. Close other MIDI apps, check the USB connection, and check your FM-1 again. No update was started.';
}

export function mountInstallerPage({
  document: doc = document,
  requestMIDIAccess = typeof navigator.requestMIDIAccess==='function' ? navigator.requestMIDIAccess.bind(navigator) : null,
  loadTransport = () => Promise.all([import('../fm1ota.js'),import('../jam-device-policy.js')]),
  loadInstaller = () => import('../plugg-install-controller.js'),
  fetchRelease = () => fetch('../firmware/pluggbox-release.json',{cache:'no-store'}),
  now = () => new Date(),
} = {}) {
  const get=id=>doc.getElementById(id);
  const ids=['release-badge','release-status','connect-device','connection-status','port-fields','midi-input','midi-output','port-hint','check-device','device-result','result-title','result-detail','install-device','install-hint','firmware-retry','trial-ack','install-progress','progress-stage','progress-detail','install-result','install-result-title','install-result-detail','download-report','report-details'];
  const ui=Object.fromEntries(ids.map(id=>[id,get(id)]));
  let access=null, updater=null, inspectDevice=null, installer=null, installerModule=null, bundle=null, observation=null, operation=null;
  let generation=0, disposed=false, permissionPending=false, bundlePending=false, attempted=false, success=false, topologyKey='', report=null, lastStage=null;
  let inputs=[], outputs=[], stages=[], requestCounts={verify:0,write:0};
  const removers=[], bundleAbort=new AbortController();
  const on=(target,type,fn)=>{target.addEventListener(type,fn);removers.push(()=>target.removeEventListener(type,fn));};
  const status=(message,error=false)=>{ui['connection-status'].textContent=message;ui['connection-status'].dataset.tone=error?'error':'info';};
  const started=()=>attempted || installer?.started===true;
  const timestamp=()=>now().toISOString();
  const topology=()=>JSON.stringify(['inputs','outputs'].flatMap(direction=>[...access[direction].values()].filter(port=>port.state!=='disconnected').map(port=>[direction,port.id,port.name||''])).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b))));
  function invalidate() { observation=null;ui['trial-ack'].checked=false;ui['device-result'].hidden=true; }
  function pair() {
    const input=inputs.find(port=>port.id===ui['midi-input'].value && port.state!=='disconnected');
    const output=outputs.find(port=>port.id===ui['midi-output'].value && port.state!=='disconnected');
    return input && output && input.name===output.name ? {inputId:input.id,outputId:output.id} : null;
  }
  function controls() {
    const busy=!!operation || permissionPending;
    ui['connect-device'].disabled=!requestMIDIAccess || busy || started();
    ui['check-device'].disabled=busy || started() || !pair();
    ui['port-fields'].disabled=busy || started() || !access;
    ui['check-device'].textContent=operation?.kind==='inspect'?'Checking your FM-1…':'Check my FM-1';
    ui['check-device'].setAttribute('aria-busy',String(operation?.kind==='inspect'));
    ui['trial-ack'].disabled=busy || started() || !bundle;
    ui['install-device'].disabled=busy || started() || !bundle || !observation?.eligible || !pair() || !ui['trial-ack'].checked;
    ui['firmware-retry'].disabled=busy || bundlePending || started();
    ui['install-hint'].textContent=started()?'Keep the FM-1 powered and connected until the result is confirmed.':!bundle?'The install button will become available with a verified Pluggbox device build.':!observation?.eligible?'Check your supported Jambox, then acknowledge the trial notes above.':!ui['trial-ack'].checked?'Read and acknowledge the trial notes above to enable installation.':'Ready to replace Jambox with experimental Pluggbox.';
  }
  async function prepareBundle() {
    if (bundlePending || started() || disposed) return;
    bundlePending=true;bundle=null;ui['firmware-retry'].hidden=true;ui['release-badge'].textContent='IN PREPARATION';controls();
    try {
      const response=await fetchRelease();if(!response.ok)throw new Error('Release unavailable');
      const release=await response.json();if(disposed)return;
      if (!trialRelease(release)) {
        ui['release-status'].textContent=release?.schema_version===1 && release.family==='pluggbox' && release.status==='blocked' && typeof release.message==='string' && release.message.length<=300?release.message:PENDING;
        return;
      }
      ui['release-status'].textContent='Checking the experimental Pluggbox firmware download…';
      const module=await loadInstaller();
      const loaded=await module.loadTrialBundle({baseURL:new URL('../firmware/',doc.baseURI),signal:bundleAbort.signal});
      if(disposed)return;
      if(loaded.version!==release.version || loaded.firmwareSHA256!==release.firmware_sha256 || loaded.hardwareValidated!==false || loaded.manifestSHA256!==release.manifest_sha256)throw new Error('Release binding mismatch');
      installerModule=module;bundle=loaded;
      if(access)installer=new module.TrialInstaller(access,{onStep:step,onLog:()=>{}});
      invalidate();ui['release-badge'].textContent='EXPERIMENTAL';
      ui['release-status'].textContent=`Pluggbox ${loaded.version} · firmware download verified. This owner trial has not been validated on hardware. It replaces Jambox and uses temporary sessions.`;
    } catch {
      if(!disposed){ui['release-status'].textContent='The Pluggbox firmware download could not be verified. Installation is disabled.';ui['firmware-retry'].hidden=false;}
    } finally {bundlePending=false;if(!disposed)controls();}
  }
  function ports() {
    if(!access || started())return;
    const currentTopology=topology();
    if(currentTopology===topologyKey)return;
    topologyKey=currentTopology;
    if(operation?.kind==='install')return;
    const oldIn=ui['midi-input'].value,oldOut=ui['midi-output'].value;
    const available=map=>[...map.values()].filter(port=>port.state!=='disconnected');
    inputs=available(access.inputs);outputs=available(access.outputs);
    for(const [id,list,old,label] of [['midi-input',inputs,oldIn,'Choose an input'],['midi-output',outputs,oldOut,'Choose an output']]) {
      const select=ui[id];select.replaceChildren(new Option(label,''));
      for(const [index,port] of list.entries())select.add(new Option(`${port.name||'Unnamed MIDI device'}${list.filter(p=>p.name===port.name).length>1?` (${index+1})`:''}`,port.id));
      if(list.some(p=>p.id===old))select.value=old;
    }
    const exact=inputs.filter(input=>outputs.some(output=>input.name===output.name));
    if(!oldIn && !oldOut && exact.length===1 && outputs.filter(port=>port.name===exact[0].name).length===1){ui['midi-input'].value=exact[0].id;ui['midi-output'].value=outputs.find(port=>port.name===exact[0].name).id;}
    generation++;operation?.abort.abort();invalidate();
    ui['port-hint'].textContent=!inputs.length||!outputs.length?'No MIDI input/output pair is available. Check your USB data cable, then refresh the ports.':pair()?'Matching ports selected. The check only reads firmware identification.':'Choose an input and output with the same instrument name. If several look identical, unplug other MIDI devices.';
    if(oldIn || oldOut)status('The MIDI connections changed. Check your FM-1 again before installing.');
    controls();
  }
  async function connect() {
    if(!requestMIDIAccess || operation || permissionPending || started() || disposed)return;
    if(access){topologyKey='';ports();return;}
    permissionPending=true;controls();status('Waiting for MIDI permission. Allow MIDI and system exclusive access when your browser asks.');
    try {
      const granted=await requestMIDIAccess({sysex:true});if(disposed)return;
      const [{Updater},{inspectDevice:inspect}]=await loadTransport();if(disposed)return;
      access=granted;updater=new Updater(access);inspectDevice=inspect;
      if(installerModule)installer=new installerModule.TrialInstaller(access,{onStep:step,onLog:()=>{}});
      on(access,'statechange',ports);ui['port-fields'].hidden=false;ui['connect-device'].textContent='Refresh ports';ports();
      status(inputs.length&&outputs.length?'Connected to MIDI. Check the matching FM-1 ports below.':'MIDI is available. Connect your FM-1 with a USB data cable, then refresh the ports.');
    }catch(error){if(!disposed)status(beforeStart(error),true);}
    finally{permissionPending=false;if(!disposed)controls();}
  }
  async function check() {
    const selected=pair();if(!selected || operation || !updater || started() || disposed)return;
    const token=++generation,current={kind:'inspect',abort:new AbortController()};operation=current;invalidate();controls();status('Reading your FM-1. Its sounds and firmware are left unchanged.');
    try {
      const result=installer?await installer.inspect(selected,{signal:current.abort.signal}):await updater.identify({pair:selected,signal:current.abort.signal,query:(link,identity)=>inspectDevice(identity,link,{signal:current.abort.signal})});
      if(disposed || token!==generation || current.abort.signal.aborted)return;
      const identity=result.identity||result.id||{},info=result.capabilities||{};
      const family=info.family==='jamboxfm'?'Jambox':info.family==='sloop'?'Sloop':identity.text==='FM-1_015'?'Factory FM-1':null;
      observation={...result,eligible:!!bundle && result.eligible===true && result.uniqueDevice!==false};
      ui['result-title'].textContent=observation.eligible?'Jambox checked · ready for Pluggbox.':family?`${family} identified.`:'Firmware identity received.';
      ui['result-detail'].textContent=`${safeIdentity(identity)||'Unconfirmed firmware'}${typeof info.release==='string'?` · ${info.release.slice(0,40)}`:''}. ${observation.eligible?'Read the trial notes and keep your Jambox backups before installing.':bundle?'This trial requires the supported Jambox build in normal mode, with only one FM-1 connected. Nothing was installed.':'Pluggbox installation is still being prepared; nothing was installed.'}`;
      ui['device-result'].hidden=false;status(observation.eligible?'Your Jambox is ready. Read and acknowledge the trial notes before installing.':'Device check complete. No changes were made.');
    }catch(error){if(!disposed && token===generation && !current.abort.signal.aborted)status(beforeStart(error),true);}
    finally{if(operation===current)operation=null;if(!disposed)controls();}
  }
  function step(stage,detail) {
    if(disposed || !STAGES.includes(stage))return;
    if(stage==='start')attempted=true;
    if((stage==='verify'||stage==='write') && Number.isSafeInteger(detail) && detail>=0 && detail<=1000000)requestCounts[stage]=Math.max(requestCounts[stage],detail);
    if(stage===lastStage)return;
    lastStage=stage;stages.push({stage,at:timestamp()});
    const descriptions={checking:['Checking your Jambox.','Reading the selected instrument again before starting.'],start:['Preparing the update.','The update has started. Keep power and USB connected, and leave this tab open.'],verify:['Sending the update loader.','Your FM-1 is requesting the firmware needed to prepare the update.'],loader:['Waiting for the update loader.','USB will briefly reconnect as your FM-1 enters its update loader.'],write:['Installing Pluggbox.','Your FM-1 is writing Pluggbox. Keep power and USB connected.'],reboot:['Waiting for Pluggbox.','Transfer finished. Waiting for the instrument to return and identify itself.'],done:['Confirming Pluggbox.','Pluggbox replied. Finishing the connection check.']};
    const index={checking:0,start:1,verify:1,loader:1,write:2,reboot:3,done:3}[stage];
    ['stage-check','stage-loader','stage-write','stage-return'].forEach((id,i)=>{get(id).dataset.state=i<index?'done':i===index?'active':'waiting';if(i===index)get(id).setAttribute('aria-current','step');else get(id).removeAttribute('aria-current');});
    ui['progress-stage'].textContent=descriptions[stage][0];ui['progress-detail'].textContent=descriptions[stage][1];status(descriptions[stage][1]);controls();
  }
  function showResult(outcome,result,error) {
    report={format:'pluggbox-install-report',formatVersion:1,recordedAt:timestamp(),experimental:true,hardwareValidated:false,transition:'jambox-normal-to-pluggbox',outcome,updateStarted:started(),sourceIdentity:safeIdentity(result?.sourceIdentity||error?.sourceIdentity||observation?.identity),finalIdentity:safeIdentity(result?.identity),unexpectedIdentity:safeIdentity({text:error?.detail}),version:bundle?.version||null,firmwareSHA256:bundle?.firmwareSHA256||null,stages:stages.map(entry=>({...entry})),requestCounts:{...requestCounts},errorCode:error?safeCode(error):null};
    ui['report-details'].textContent=JSON.stringify(report,null,2);ui['install-result'].hidden=false;
    if(outcome==='completed') {
      ui['install-result-title'].textContent='Pluggbox is on your FM-1.';ui['install-result-detail'].textContent='Your instrument returned as Pluggbox. Start with low volume, then check its sound, screen, keys, and knobs. Download this report. Sessions are temporary and saving is disabled.';
      ui['progress-stage'].textContent='Pluggbox identified.';ui['progress-detail'].textContent='Transfer and firmware identity confirmed. Hardware behavior still needs your check.';
      for(const id of ['stage-check','stage-loader','stage-write','stage-return']){get(id).dataset.state='done';get(id).removeAttribute('aria-current');}status('Pluggbox returned successfully. Start with low volume when checking the sound.');
    } else if(started()) {
      ui['install-result-title'].textContent='Installation was not confirmed.';ui['install-result-detail'].textContent='Firmware may be partly written. Keep the FM-1 powered and connected. Download this report and share it before retrying, unplugging, or restarting. This page will not retry automatically.';
      ui['progress-stage'].textContent='Installation needs review.';ui['progress-detail'].textContent='Keep power and USB connected, and download the report.';status('Installation stopped. Keep power and USB connected, and download the report.',true);
    }else{ui['install-result-title'].textContent='The update did not start.';ui['install-result-detail'].textContent=beforeStart(error);ui['install-progress'].hidden=true;status(beforeStart(error),true);}
    ui['install-result-title'].focus({preventScroll:true});
  }
  async function install() {
    const selected=pair();if(!bundle || !selected || !observation?.eligible || !ui['trial-ack'].checked || operation || started() || disposed || !installer)return;
    const current={kind:'install',abort:new AbortController()};operation=current;stages=[];lastStage=null;requestCounts={verify:0,write:0};report=null;
    ui['install-result'].hidden=true;ui['install-progress'].hidden=false;step('checking');ui['progress-stage'].focus({preventScroll:true});controls();
    try {
      const result=await installer.install(bundle,selected,{signal:current.abort.signal});if(disposed)return;
      if(safeIdentity(result?.identity)!=='FM-1_701')throw Object.assign(new Error('Final identity not confirmed'),{code:'mismatch',started:started()});
      success=true;showResult('completed',result,null);
    }catch(error){if(disposed)return;if(error?.started)attempted=true;showResult('error',null,error);if(!started())invalidate();}
    finally{if(operation===current)operation=null;if(!disposed)controls();}
  }
  function pairChanged(){if(started())return;generation++;operation?.abort.abort();invalidate();controls();status(pair()?'Ready to check the selected FM-1.':'Choose the matching input and output for your FM-1.');}
  function downloadReport(){if(!report)return;const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)+'\n'],{type:'application/json'}));const link=doc.createElement('a');link.href=url;link.download='pluggbox-install-report.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
  function dispose(){disposed=true;generation++;bundleAbort.abort();if(!started())operation?.abort.abort();for(const remove of removers)remove();}
  on(ui['connect-device'],'click',connect);on(ui['check-device'],'click',check);on(ui['install-device'],'click',install);on(ui['trial-ack'],'change',controls);on(ui['firmware-retry'],'click',prepareBundle);on(ui['download-report'],'click',downloadReport);
  on(ui['midi-input'],'change',pairChanged);on(ui['midi-output'],'change',pairChanged);
  on(doc.defaultView,'beforeunload',event=>{if(started()&&!success){event.preventDefault();event.returnValue='';}});on(doc.defaultView,'pagehide',dispose);
  const players=[get('audio-glass'),get('audio-harder')];for(const player of players)on(player,'play',()=>{for(const other of players)if(other!==player)other.pause();});
  if(!requestMIDIAccess)status('To connect an FM-1, use Chrome or Edge on a computer over HTTPS. You can still listen and play in the browser above.');
  controls();prepareBundle();return{dispose};
}
if(typeof document!=='undefined')mountInstallerPage();
