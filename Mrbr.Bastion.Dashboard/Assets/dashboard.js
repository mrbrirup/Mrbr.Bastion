'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const state = { view: 'fleet', server: null, serverTab: 'history', page: 1, historyBefore: null, historyNext: null, alertBefore: null, alertNext: null, deliveryBefore: null, deliveryNext: null, deliveryAlert: null, csrf: null, busy: false, evidence: null };
  const can=permission=>(state.permissions||[]).includes(permission);
  const names = { VerificationUnavailable: 'Health verification unavailable', NoHeartbeat: 'No accepted heartbeat', LocalCacheIntegrityFailure: 'Local cache integrity failure', CacheAuditUnavailable: 'Cache audit unavailable', LocalLedgerRollback: 'Local ledger rollback', CheckpointHashMismatch: 'Checkpoint hash mismatch', CollectorFaulted: 'Collector faulted', CollectorStopped: 'Collector stopped', CollectorNotStarted: 'Collector not started', CounterRollback: 'Counter rollback', EventsLost: 'New events lost', ClockSkewOrDelay: 'Clock skew or delay', LargeBacklog: 'Large telemetry backlog', CollectorRestarted: 'Collector restarted', LocalTailAwaitingIngestion: 'Local tail awaiting ingestion', StaleHeartbeat: 'Heartbeat stale', Offline: 'Heartbeat offline', ServerClockInconsistent: 'Receiver clock inconsistent' };
  const date = v => v ? new Date(v).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC') : 'No accepted heartbeat';
  const text = (id, v) => { $(id).textContent = v; };
  function el(tag, content, cls) { const n = document.createElement(tag); if (content !== undefined) n.textContent = content; if (cls) n.className = cls; return n; }
  function badge(label, style) { return el('span', label, 'badge ' + (style || label).toLowerCase()); }
  function cell(row, value) { const td = el('td'); td.append(value instanceof Node ? value : document.createTextNode(String(value))); row.append(td); return td; }
  function button(label, action, cls = 'quiet') { const b = el('button', label, cls); b.type = 'button'; b.addEventListener('click', () => work(action)); return b; }
  function query(values) { return new URLSearchParams(Object.entries(values).filter(([,v]) => v !== null && v !== undefined && v !== '')).toString(); }
  function scope(values = {}) { return state.server ? { ...values, nodeId: state.server.nodeId, ledgerId: state.server.ledgerId } : values; }
  async function response(path, options = {}) {
    const response = await fetch('/dashboard/api/' + path, { credentials: 'same-origin', cache: 'no-store', ...options });
    if (response.status === 401) { window.location.assign('/dashboard/login'); throw new Error('Your operator session has expired.'); }
    if (response.status === 403) throw new Error('Your role does not permit this action.');
    if (response.status === 409) { const details=await response.json().catch(()=>null);throw new Error(details?.error==='LastAdministrator'?'Keep at least one enabled administrator.':details?.error==='OperatorRevisionChanged'?'This account changed. Refresh and review it before saving.':details?.error==='OperatorNameExists'?'That username is already registered.':'The action conflicts with the current state. Refresh and try again.'); }
    if (!response.ok) throw new Error(response.status === 503 ? 'Evidence or storage is unavailable. Retained alerts and deliveries remain in place. Try refreshing.' : response.status === 429 ? 'The server is busy. Try again shortly.' : response.status === 409 ? 'This action is unavailable in the current state. Check the route, retry limit, and delivery history.' : 'The request could not be completed (' + response.status + ').');
    return response;
  }
  async function api(path, options = {}) { return (await response(path, options)).json(); }
  async function work(action) {
    if (state.busy) return;
    state.busy = true; $('refresh').disabled = true; $('error').hidden = true;
    try { await action(); }
    catch (error) { $('error').textContent = error.message; $('error').hidden = false; }
    finally { state.busy = false; $('refresh').disabled = false; }
  }
  function layout() {
    $('users-view').hidden=state.view!=='users';$('account-view').hidden=state.view!=='account';$('nav-users').classList.toggle('selected',state.view==='users');$('nav-users').setAttribute('aria-current',state.view==='users'?'page':'false');
    $('software-view').hidden = state.view !== 'software'; $('nav-software').classList.toggle('selected',state.view === 'software'); $('nav-software').setAttribute('aria-current',state.view === 'software'?'page':'false');
    $('fleet-view').hidden = state.view !== 'fleet'; $('server-view').hidden = state.view !== 'server';
    $('notifications-view').hidden = state.view !== 'notifications';
    $('alerts-panel').hidden = !(state.view === 'alerts' || (state.view === 'server' && state.serverTab === 'alerts'));
    $('history-panel').hidden = state.serverTab !== 'history';
    $('nav-servers').classList.toggle('selected', state.view === 'fleet' || state.view === 'server'); $('nav-alerts').classList.toggle('selected', state.view === 'alerts'); $('nav-notifications').classList.toggle('selected', state.view === 'notifications');
    $('nav-servers').setAttribute('aria-current', state.view === 'fleet' || state.view === 'server' ? 'page' : 'false'); $('nav-alerts').setAttribute('aria-current', state.view === 'alerts' ? 'page' : 'false'); $('nav-notifications').setAttribute('aria-current', state.view === 'notifications' ? 'page' : 'false');
    $('tab-history').classList.toggle('selected', state.serverTab === 'history'); $('tab-alerts').classList.toggle('selected', state.serverTab === 'alerts');
    text('page-title', state.view === 'notifications' ? 'Notification deliveries' : state.view === 'alerts' ? 'Alerts' : state.view === 'server' ? 'Server details' : 'Server health');
    text('breadcrumb', state.view === 'notifications' ? 'DELIVERIES' : state.view === 'alerts' ? 'ALERTS' : state.view === 'server' ? 'SERVERS / DETAILS' : 'SERVERS');
    text('page-description', state.view === 'notifications' ? 'Durable attempts, provider acceptance, and operator retries.' : state.view === 'alerts' ? 'Retained conditions, operator acknowledgement, and recovery.' : state.view === 'server' ? 'Current monitoring health and the evidence behind it.' : 'Fresh evidence. Clear conditions. One central view.');
    text('alerts-title', state.server ? 'Server alerts' : 'Fleet alerts');
    if(state.view==='software'){text('page-title','Software & CVE exposure');text('breadcrumb','SOFTWARE');text('page-description','Observed software, reviewed identity mappings, and published vulnerability criteria.');}
    if(state.view==='users'){text('page-title','Operator access');text('breadcrumb','OPERATORS');text('page-description','Per-user identities, explicit roles, and retained security history.');}
    if(state.view==='account'){text('page-title','My account');text('breadcrumb','ACCOUNT');text('page-description','Your operator identity and password.');}
  }
  async function session() {
    const s = await api('session'); state.csrf = s.csrfToken; $('logout-token').value = state.csrf; text('nav-alert-count', s.alerts.open);
    state.permissions=s.permissions;state.identity=s;state.mustChange=s.mustChangePassword;
    $('nav-users').hidden=!can('users.manage');$('account-button').hidden=s.authenticationMode!=='Users';text('operator-name',s.displayName||s.operatorName);
    for(const name of ['servers','software','alerts','notifications'])$('nav-'+name).hidden=state.mustChange;
    if(state.mustChange){state.view='account';$('evaluation-warning').hidden=true;$('notification-warning').hidden=true;return;}
    const overdue = !s.evaluation.lastCompletedUtc || Date.now() - new Date(s.evaluation.lastCompletedUtc) > Math.max(60000, s.evaluationIntervalSeconds * 3000);
    const warning = s.evaluation.error || (overdue ? 'Alert evaluation has not completed recently. Displayed alert state may be out of date.' : null);
    $('evaluation-warning').hidden = !warning;
    $('evaluation-warning').textContent = warning || '';
    text('nav-delivery-count', s.notificationCounts.deadLetter);
    const deliveryWarning = s.notifications.enabled && (s.notifications.routingError || s.notifications.deliveryError);
    $('notification-warning').hidden = !deliveryWarning;
    $('notification-warning').textContent = deliveryWarning ? 'Notification routing or delivery storage needs attention. Inspect Deliveries; source events and admitted deliveries remain retained.' : '';
  }
  function serverButton(server) {
    const b = button('', () => openServer(server), 'server-link'); b.append(el('strong', server.displayName));
    b.append(el('div', server.nodeId + ' · ' + server.ledgerId.slice(0,8), 'muted mono')); return b;
  }
  async function fleet() {
    const data = await api('fleet?' + query({ search: $('search').value.trim(), state: $('health-filter').value, page: state.page, pageSize: 25 }));
    text('metric-total', data.summary.total); text('metric-healthy', data.summary.healthy); text('metric-attention', data.summary.degraded + data.summary.critical);
    text('metric-unavailable', data.summary.offline + data.summary.unknown + data.summary.verificationUnavailable);
    text('nav-alert-count', data.alerts.open); text('fleet-count', data.totalMatches + ' matching enrollments · ' + data.alerts.open + ' open alerts');
    $('server-rows').replaceChildren();
    for (const item of data.servers) {
      const row = el('tr'); const h = item.health; cell(row, serverButton(item.server));
      cell(row, badge(item.error ? 'Verification unavailable' : h.assessment.state, item.error ? 'Critical' : h.assessment.state));
      const score = el('span', h?.assessment.score === null || !h ? '—' : String(h.assessment.score), 'score'); if (h?.assessment.score !== null && h) score.append(el('small', '/100')); cell(row, score);
      cell(row, date(h?.lastAcceptedAuditUtc)); cell(row, h?.lastAuditSequenceNumber ? '#' + h.lastAuditSequenceNumber : '—');
      cell(row, button('View →', () => openServer(item.server))); $('server-rows').append(row);
    }
    $('fleet-empty').hidden = data.servers.length > 0;
    text('fleet-page', 'Page ' + state.page + ' of ' + Math.max(1, Math.ceil(data.totalMatches / 25)));
    $('fleet-prev').disabled = state.page <= 1; $('fleet-next').disabled = state.page * 25 >= data.totalMatches;
  }
  async function openServer(server) {
    state.server = server; state.view = 'server'; state.serverTab = 'history'; state.historyBefore = null; state.alertBefore = null;
    text('server-name', server.displayName); text('server-identity', 'Node / ' + server.nodeId); text('server-ledger', 'Ledger / ' + server.ledgerId);
    text('server-last', 'Loading…'); text('server-sequence', '—'); text('server-policy', '—'); $('server-score').replaceChildren(); $('server-findings').replaceChildren();
    $('audit-rows').replaceChildren(); $('history-empty').hidden = true; text('history-range', 'Loading retained assessments…');
    layout(); await refreshView();
  }
  async function serverHealth() {
    const result = await api('server?' + query(scope())); const h = result.health;
    text('server-name', result.server.displayName); text('server-identity', 'Node / ' + result.server.nodeId); text('server-ledger', 'Ledger / ' + result.server.ledgerId);
    $('server-score').replaceChildren(badge(result.error ? 'Verification unavailable' : h.assessment.state, result.error ? 'Critical' : h.assessment.state), el('strong', h?.assessment.score === null || !h ? '—' : h.assessment.score + '/100'));
    text('server-last', date(h?.lastAcceptedAuditUtc)); text('server-sequence', h?.lastAuditSequenceNumber ? '#' + h.lastAuditSequenceNumber : '—'); text('server-policy', h?.assessment.policyVersion || 'Unavailable');
    $('server-findings').replaceChildren();
    const findings = result.error ? [result.error] : h.assessment.findings;
    if (findings.length === 0) $('server-findings').append(badge('No current monitoring findings', 'Healthy'));
    for (const finding of findings) $('server-findings').append(badge(names[finding] || finding, finding === 'CollectorRestarted' || finding === 'LocalTailAwaitingIngestion' ? 'Unknown' : 'Warning'));
  }
  async function history() {
    const data = await api('history?' + query(scope({ beforeSequence: state.historyBefore, limit: 25 }))); state.historyNext = data.nextBeforeSequence;
    $('audit-rows').replaceChildren();
    for (const audit of data.records) {
      const row = el('tr'); cell(row, '#' + audit.sequence); cell(row, date(audit.acceptedUtc)); cell(row, badge(audit.collector.state, audit.collector.state === 'Running' ? 'Healthy' : 'Warning'));
      const cache = el('div'); cache.append(el('div', audit.cache.outcome));
      if (audit.cache.snapshot) cache.append(el('div', audit.cache.snapshot.pendingBlocks + ' pending · tail #' + audit.cache.snapshot.checkpoint.sequenceNumber, 'muted'));
      cell(row, cache); const findings = el('div'); for (const f of audit.findings) findings.append(el('div', names[f] || f)); if (!audit.findings.length) findings.textContent = 'None'; cell(row, findings);
      cell(row, can('evidence.read')?button('View evidence', () => showAudit(audit.sequence)):'Restricted'); $('audit-rows').append(row);
    }
    $('history-empty').hidden = data.records.length > 0; $('history-older').disabled = !state.historyNext; $('history-newest').disabled = state.historyBefore === null;
    text('history-range', data.records.length ? 'Audits #' + data.records[0].sequence + ' – #' + data.records[data.records.length - 1].sequence : 'No retained assessments');
  }
  async function alerts() {
    const data = await api('alerts?' + query(scope({ state: $('alert-filter').value, beforeId: state.alertBefore, limit: 25 }))); state.alertNext = data.nextBeforeId;
    $('alert-rows').replaceChildren();
    for (const alert of data.alerts) {
      const row = el('tr'); const label = el('div'); label.append(el('strong', names[alert.code] || alert.code));
      if(alert.category==='Exposure')label.append(el('div','Exposure · ' + (alert.subject?.split(':').slice(1).join(':') || 'Data unavailable'),'muted'));
      label.append(button(alert.nodeId + ' · ' + alert.ledgerId.slice(0,8), () => openServer({nodeId:alert.nodeId, ledgerId:alert.ledgerId, displayName:alert.nodeId}), 'server-link muted'));
      cell(row, label); cell(row, badge(alert.severity)); const status = el('div'); status.append(badge(alert.state));
      if (alert.acknowledgedBy) status.append(el('div', 'Acknowledged by ' + alert.acknowledgedBy, 'muted')); cell(row, status);
      cell(row, date(alert.openedUtc)); cell(row, date(alert.lastObservedUtc)); const actions = el('div');
      if (alert.state === 'Open'&&can('alerts.acknowledge')) actions.append(button('Acknowledge', async () => { await api('alerts/' + alert.id + '/acknowledge', { method:'POST', headers:{'X-CSRF-TOKEN':state.csrf} }); await refreshView(); }, 'secondary'));
      if(can('evidence.read'))actions.append(button('Activity', () => showAlert(alert))); cell(row, actions); $('alert-rows').append(row);
      actions.append(button('Deliveries', async () => { state.view = 'notifications'; state.server = null; state.deliveryAlert = alert.id; state.deliveryBefore = null; await refreshView(); }));
    }
    $('alerts-empty').hidden = data.alerts.length > 0; $('alerts-older').disabled = !state.alertNext; $('alerts-newest').disabled = state.alertBefore === null;
    text('alerts-range', data.alerts.length + ' retained alerts in this page');
  }
  async function deliveries() {
    const data = await api('notifications?' + query({ state:$('delivery-filter').value, beforeSequence:state.deliveryBefore, alertId:state.deliveryAlert, limit:25 }));
    state.deliveryNext = data.nextBeforeSequence;
    text('delivery-pending',data.counts.pending); text('delivery-inflight',data.counts.inFlight); text('delivery-delivered',data.counts.delivered); text('delivery-dead',data.counts.deadLetter);
    text('nav-delivery-count',data.counts.deadLetter);
    text('delivery-title',state.deliveryAlert ? 'Deliveries for alert #' + state.deliveryAlert : 'Email and webhook deliveries');
    text('delivery-status',!data.worker.enabled ? 'Notifications are disabled. Configure destinations on the central server to enable delivery.' : 'Active route IDs: ' + data.worker.activeRoutes.join(', ') + ' · Last completed pass: ' + (data.worker.lastCompletedUtc ? date(data.worker.lastCompletedUtc) : 'Awaiting first pass'));
    $('delivery-rows').replaceChildren();
    for(const job of data.deliveries) {
      const row=el('tr'); const target=el('div'); target.append(el('strong',job.routeId),el('div',job.nodeId,'muted'));
      if(!data.worker.enabled || !data.worker.activeRoutes.includes(job.routeId)) target.append(badge('Route inactive','Unknown'));
      target.title=job.routeId;
      cell(row,target); cell(row,'#' + job.alertId + ' · ' + job.eventKind);
      const status=el('div'); status.append(badge(job.state),el('div',job.lastCode ? job.lastCode.replace(/([a-z])([A-Z])/g,'$1 $2').replace(/^Http /,'HTTP ').replace(/^Smtp /,'SMTP ') : 'Awaiting first attempt','muted'));
      cell(row,status); cell(row,job.attempts + ' total / ' + job.cycleAttempts + ' of ' + job.maximumAttempts);
      cell(row,job.state==='Pending' ? date(job.nextAttemptUtc) : job.state==='InFlight' ? 'Lease until ' + date(job.leaseExpiresUtc) : '—');
      const actions=el('div',undefined,'delivery-actions'); if(can('evidence.read'))actions.append(button('History',async()=>evidence('Delivery ' + job.id,'Durable attempt and operator retry history. Provider acceptance does not prove inbox placement or downstream processing.',await api('notifications/' + job.id),'bastion-delivery-' + job.id + '.json')));
      if(can('notifications.retry')&&job.state==='DeadLetter' && job.redrives<job.maximumRedrives && data.worker.enabled && data.worker.activeRoutes.includes(job.routeId))
        actions.append(button('Retry delivery',async()=>{await api('notifications/' + job.id + '/retry',{method:'POST',headers:{'X-CSRF-TOKEN':state.csrf}}); await refreshView();},'secondary'));
      cell(row,actions); $('delivery-rows').append(row);
    }
    $('deliveries-empty').hidden=data.deliveries.length>0; $('deliveries-older').disabled=!state.deliveryNext; $('deliveries-newest').disabled=state.deliveryBefore===null; $('deliveries-all').hidden=state.deliveryAlert===null;
    text('delivery-range',data.deliveries.length + ' retained deliveries in this page');
  }
  function evidence(title, description, data, filename) {
    const content = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
    text('dialog-title', title); text('dialog-description', description); text('evidence-content', content);
    state.evidence = { content, filename }; $('evidence-dialog').showModal();
  }
  const softwareState={tab:'items',after:null,next:null,servers:[],initialized:false};
  async function software() {
    if(!softwareState.initialized){
      for(let page=1;;page++){
        const fleet=await api('fleet?'+query({page,pageSize:100}));softwareState.servers.push(...fleet.servers.map(s=>s.server));
        if(page*100>=fleet.totalMatches||!fleet.servers.length)break;
      }
      $('software-server').replaceChildren();softwareState.servers.forEach((s,i)=>{const option=el('option',s.displayName+' · '+s.ledgerId.slice(0,8));option.value=String(i);$('software-server').append(option);});softwareState.initialized=true;
    }
    const server=softwareState.servers[Number($('software-server').value)];if(!server){text('software-status','No enrolled servers.');return;}
    const params={nodeId:server.nodeId,ledgerId:server.ledgerId};
    const inventory=await api('software?'+query({...params,after:softwareState.tab==='items'?softwareState.after:null,limit:100,search:$('software-search').value.trim()}));
    const status=inventory.status;
    text('software-status',!status.enabled?'Software inventory is disabled on the central server.':(status.error?'Needs attention: '+status.error+' · ':'')+'Projection: '+(status.lastProjectionUtc?date(status.lastProjectionUtc):'Awaiting first pass')+' · Evaluation: '+(status.lastEvaluationUtc?date(status.lastEvaluationUtc):'Pending')+' · NVD '+(status.intelligenceEnabled?'enabled':'disabled'));
    $('software-search-form').hidden=softwareState.tab!=='items';$('mapping-panel').hidden=softwareState.tab!=='mappings'||!status.enabled||!can('mappings.review');$('product-search-form').hidden=!can('intelligence.search');
    for(const tab of ['items','exposures','scans','mappings'])$('software-'+tab+'-tab').classList.toggle('selected',softwareState.tab===tab);
    $('software-rows').replaceChildren();let rows=[],columns=[];softwareState.next=null;
    const details=(title,data,extra)=>can('evidence.read')?button('Evidence',async()=>evidence(title,'Retained observations and assessment history. Raw evidence can be incomplete or stale.',extra?{current:data,history:await extra()}:data,'bastion-software-evidence.json')):el('span','Restricted','muted');
    if(softwareState.tab==='items'){
      columns=['Software / publisher','Version evidence','Source / observation','Reported parent','Location','Actions'];rows=inventory.items;softwareState.next=inventory.nextAfter;
      for(const item of rows){const a=item.observation.artifact,row=el('tr'),name=el('div');name.append(el('strong',a.product||'Unknown product'),el('div',a.publisher||'Unknown publisher','muted'));cell(row,name);
        const versions=el('div');for(const [label,value] of [['Product',a.productVersion],['File',a.fileVersion],['Package',a.packageVersion]])if(value)versions.append(el('div',label+': '+value));if(!versions.childNodes.length)versions.textContent='Unknown version';cell(row,versions);
        const source=el('div');source.append(el('div',item.observation.source),el('div',date(item.observation.observedUtc),'muted'));if(item.missing)source.append(badge('No longer observed','Unknown'));else if(a.reportedRunning)source.append(badge(Date.now()-new Date(item.observation.observedUtc)<=120000?'Recently reported running':'Running evidence stale','Warning'));cell(row,source);
        const parent=el('div');
        if(a.parentProcess){const p=a.parentProcess;parent.append(el('strong',p.processName||'Unknown name'),el('div','PID '+p.processId+' · '+p.processInstanceId.slice(0,8),'mono'),el('div',p.executablePath||'Path unavailable','software-location mono'));}
        else parent.textContent=item.observation.source==='RunningProcess'?(a.parentProcessId==null?'Unknown / not observed':'PID '+a.parentProcessId+' · lifetime not correlated'):'—';
        cell(row,parent);cell(row,el('div',a.location+(a.memberPath?' ! '+a.memberPath:''),'software-location mono'));cell(row,details('Software observation',item));$('software-rows').append(row);}
    }else if(softwareState.tab==='exposures'){
      columns=['Software / CVE','Applicability','Evidence / freshness','Priority','Actions'];const page=await api('exposures?'+query({...params,after:softwareState.after,limit:100}));rows=page.findings;softwareState.next=page.nextAfter;
      for(const f of rows){const row=el('tr'),name=el('div');name.append(el('strong',f.product||'Unknown product'));if(f.cveId){const link=el('a',f.cveId);link.href='https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(f.cveId);link.target='_blank';link.rel='noopener noreferrer';const linkRow=el('div');linkRow.append(link);name.append(linkRow);}else name.append(el('div','No matched CVE','muted'));cell(row,name);
        const result=el('div');result.append(badge(f.applicability,f.applicability==='Affected'?'Critical':f.applicability==='Unknown'?'Unknown':'Healthy'),el('div',f.reason.replace(/([a-z])([A-Z])/g,'$1 $2'),'muted'));cell(row,result);
        const fresh=el('div');fresh.append(el('div','Version: '+(f.version||'unknown')),el('div',f.mappingConfidence+' · '+(f.mappingId?'mapping '+f.mappingId+' r'+f.mappingRevision:'No reviewed identity'),'muted'),el('div','Inventory: '+date(f.observedUtc),'muted'),el('div','NVD: '+(f.intelligenceUtc?date(f.intelligenceUtc):'unavailable'),'muted'),el('div','Evaluated: '+date(f.evaluatedUtc),'muted'));cell(row,fresh);
        cell(row,(f.recentlyRunning?'Recently reported running · ':'')+'CVSS '+(f.cvss??'unknown'));cell(row,details('CVE exposure history',f,()=>api('exposures/'+f.id+'/history')));$('software-rows').append(row);}
    }else if(softwareState.tab==='scans'){
      columns=['Task / source','Coverage','Observations / issues','Received · UTC','Actions'];rows=await api('software/scans?'+query(params));
      for(const scan of rows){const row=el('tr'),task=el('div');task.append(el('strong',scan.taskId),el('div',scan.source,'muted'),el('div',scan.scope,'software-location mono'));cell(row,task);cell(row,badge(!scan.finished?'In progress':scan.complete?'Complete':'Partial',scan.complete?'Healthy':'Warning'));cell(row,scan.softwareCount+' items · '+scan.coverageCount+' coverage issues · '+scan.pending+' pending / '+scan.completed+' work items completed');cell(row,date(scan.receivedUtc));cell(row,details('Scan coverage',scan,()=>api('software/coverage?'+query({...params,scanId:scan.scanId}))));$('software-rows').append(row);}
    }else{
      columns=['Observed identity','Reviewed CPE','Version rule','Review','Actions'];rows=await api('mappings');
      for(const mapping of rows){const row=el('tr');cell(row,mapping.publisher+' / '+mapping.product);cell(row,el('div',mapping.cpe,'software-location mono'));cell(row,mapping.versionField+' · '+mapping.scheme);cell(row,'r'+mapping.revision+' · '+mapping.reviewer+' · '+date(mapping.reviewedUtc));const actions=el('div');actions.append(details('Mapping review history',mapping,()=>api('mappings/'+encodeURIComponent(mapping.id)+'/history')));if(can('mappings.review'))actions.append(button('Revise',async()=>{for(const key of ['id','publisher','product','cpe','scheme','versionField'])$('mapping-form').elements.namedItem(key).value=mapping[key];$('mapping-form').elements.namedItem('revision').value=mapping.revision+1;$('mapping-form').scrollIntoView({block:'center'});}));cell(row,actions);$('software-rows').append(row);}
    }
    const heading=el('tr');for(const column of columns)heading.append(el('th',column));$('software-columns').replaceChildren(heading);$('software-empty').hidden=rows.length>0;
    $('software-next').disabled=softwareState.next===null;$('software-first').disabled=softwareState.after===null;text('software-range',rows.length+' retained records in this page');
  }
  $('nav-software').addEventListener('click',()=>work(async()=>{state.view='software';state.server=null;await refreshView();}));
  for(const tab of ['items','exposures','scans','mappings'])$('software-'+tab+'-tab').addEventListener('click',()=>work(async()=>{softwareState.tab=tab;softwareState.after=null;await software();}));
  $('software-server').addEventListener('change',()=>work(async()=>{softwareState.after=null;await software();}));
  $('software-search-form').addEventListener('submit',e=>{e.preventDefault();work(async()=>{softwareState.after=null;await software();});});
  $('software-next').addEventListener('click',()=>work(async()=>{softwareState.after=softwareState.next;await software();}));
  $('software-first').addEventListener('click',()=>work(async()=>{softwareState.after=null;await software();}));
  $('mapping-form').addEventListener('submit',e=>{e.preventDefault();work(async()=>{const data=Object.fromEntries(new FormData(e.target));data.revision=Number(data.revision);await api('mappings',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-TOKEN':state.csrf},body:JSON.stringify(data)});text('mapping-result','Review saved. Correlation will use it on the next evaluation pass.');await software();});});
  $('product-search-form').addEventListener('submit',e=>{e.preventDefault();work(async()=>{const candidates=await api('products?'+query({query:$('product-query').value.trim()}));text('product-candidates',candidates.length?candidates.join('\n'):'No product candidates returned. Review the identity evidence.');});});
  async function showAudit(sequence) { evidence('Audit #' + sequence, 'Signed request, receiver challenge, node observations, and original central assessment. Stored signatures and bindings are verified on read.', await (await response('audit?' + query(scope({ sequence })))).text(), 'bastion-audit-' + sequence + '.json'); }
  const userState={after:null,next:null,before:null,historyNext:null,editing:null};
  const post=(path,data)=>api(path,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-TOKEN':state.csrf},body:JSON.stringify(data)});
  function editUser(user) {
    userState.editing=user;$('user-editor').hidden=false;text('user-editor-title',user?'Edit '+user.userName:'New operator');
    const form=$('user-form');form.reset();form.elements.namedItem('userName').value=user?.userName||'';form.elements.namedItem('userName').disabled=!!user;form.elements.namedItem('displayName').value=user?.displayName||'';
    for(const input of form.querySelectorAll('input[name="roles"]'))input.checked=(user?.roles||['Viewer']).includes(input.value);
    form.elements.namedItem('enabled').value=String(user?.enabled??true);form.elements.namedItem('password').required=!user;form.elements.namedItem('password').disabled=!!user;
    $('user-password-label').hidden=!!user;$('user-enabled-label').hidden=!user;$('user-reset-form').hidden=!user;$('user-reset-form').reset();
  }
  async function users() {
    if(!can('users.manage'))throw new Error('Your role cannot manage operator accounts.');
    const page=await api('operators?'+query({after:userState.after,limit:50}));userState.next=page.nextAfter;$('user-rows').replaceChildren();
    for(const user of page.users){const row=el('tr'),identity=el('div');identity.append(el('strong',user.displayName),el('div',user.userName,'muted mono'));cell(row,identity);cell(row,user.roles.join(', '));
      cell(row,(user.enabled?'Enabled':'Disabled')+' · r'+user.revision+(user.mustChangePassword?' · Password change required':''));cell(row,user.lastLoginUtc?date(user.lastLoginUtc):'No sign in');
      const actions=el('div',undefined,'delivery-actions');actions.append(button('Edit',async()=>editUser(user)),button('Revoke sessions',async()=>{await post('operators/'+user.id+'/sessions/revoke',{revision:user.revision});await refreshView();}));cell(row,actions);$('user-rows').append(row);}
    $('users-empty').hidden=page.users.length>0;text('users-range',page.users.length+' operator accounts in this page');$('users-first').disabled=userState.after===null;$('users-next').disabled=!userState.next;
    const history=await api('operator-security?'+query({before:userState.before,limit:50}));userState.historyNext=history.nextBefore;$('operator-security-rows').replaceChildren();
    for(const event of history.events){const row=el('tr');cell(row,date(event.occurredUtc));cell(row,event.actor);cell(row,event.action.replace(/([a-z])([A-Z])/g,'$1 $2'));cell(row,event.target||'—');cell(row,(event.detail||'')+(event.remoteAddress?' · '+event.remoteAddress:''));$('operator-security-rows').append(row);}
    text('operator-security-range',history.events.length+' retained security events');$('operator-security-first').disabled=userState.before===null;$('operator-security-next').disabled=!userState.historyNext;
  }
  $('nav-users').addEventListener('click',()=>work(async()=>{state.view='users';state.server=null;await refreshView();}));
  $('account-button').addEventListener('click',()=>work(async()=>{state.view='account';state.server=null;await refreshView();}));
  $('user-new').addEventListener('click',()=>editUser(null));
  $('users-first').addEventListener('click',()=>work(async()=>{userState.after=null;await users();}));
  $('users-next').addEventListener('click',()=>work(async()=>{userState.after=userState.next;await users();}));
  $('operator-security-first').addEventListener('click',()=>work(async()=>{userState.before=null;await users();}));
  $('operator-security-next').addEventListener('click',()=>work(async()=>{userState.before=userState.historyNext;await users();}));
  $('user-form').addEventListener('submit',e=>{e.preventDefault();work(async()=>{
    const form=e.target,data=new FormData(form),roles=data.getAll('roles');if(!roles.length)throw new Error('Choose at least one role.');
    if(userState.editing)await post('operators/'+userState.editing.id,{revision:userState.editing.revision,displayName:data.get('displayName'),roles,enabled:data.get('enabled')==='true'});
    else await post('operators',{userName:data.get('userName'),displayName:data.get('displayName'),roles,password:data.get('password')});
    form.reset();$('user-editor').hidden=true;userState.editing=null;await refreshView();
  });});
  $('user-reset-form').addEventListener('submit',e=>{e.preventDefault();work(async()=>{if(!userState.editing)return;await post('operators/'+userState.editing.id+'/password',{revision:userState.editing.revision,password:new FormData(e.target).get('password')});e.target.reset();$('user-editor').hidden=true;userState.editing=null;await refreshView();});});
  $('account-password-form').addEventListener('submit',e=>{e.preventDefault();work(async()=>{const data=new FormData(e.target);if(data.get('newPassword')!==data.get('confirmPassword'))throw new Error('New passwords do not match.');await post('account/password',{currentPassword:data.get('currentPassword'),newPassword:data.get('newPassword')});e.target.reset();window.location.assign('/dashboard/login');});});
  async function showAlert(alert) { evidence('Alert #' + alert.id + ' · ' + (names[alert.code] || alert.code), 'Operational alert transitions are retained separately from signed heartbeat evidence.', { alert, events: await api('alerts/' + alert.id + '/events') }, 'bastion-alert-' + alert.id + '.json'); }
  async function refreshView() {
    await session(); layout();
    if(state.view==='account'){text('account-identity',state.identity.displayName+' · '+state.identity.operatorName+' · '+state.identity.roles.join(', '));$('password-required').hidden=!state.mustChange;text('updated','Updated '+new Date().toLocaleTimeString());return;}
    if(state.view==='users'){await users();text('updated','Updated '+new Date().toLocaleTimeString());return;}
    if(state.view==='software'){await software();text('updated','Updated '+new Date().toLocaleTimeString());return;}
    if (state.view === 'fleet') await fleet();
    else if (state.view === 'alerts') await alerts();
    else if (state.view === 'notifications') await deliveries();
    else { await serverHealth(); if (state.serverTab === 'history') await history(); else await alerts(); }
    text('updated', 'Updated ' + new Date().toLocaleTimeString());
  }
  $('nav-servers').addEventListener('click', () => work(async () => { state.view = 'fleet'; state.server = null; await refreshView(); }));
  $('back').addEventListener('click', () => work(async () => { state.view = 'fleet'; state.server = null; await refreshView(); }));
  $('nav-alerts').addEventListener('click', () => work(async () => { state.view = 'alerts'; state.server = null; state.alertBefore = null; await refreshView(); }));
  $('nav-notifications').addEventListener('click', () => work(async () => { state.view = 'notifications'; state.server = null; state.deliveryBefore = null; state.deliveryAlert = null; await refreshView(); }));
  $('refresh').addEventListener('click', () => work(refreshView));
  $('fleet-filter').addEventListener('submit', e => { e.preventDefault(); work(async () => { state.page = 1; await refreshView(); }); });
  $('fleet-prev').addEventListener('click', () => work(async () => { state.page--; await refreshView(); }));
  $('fleet-next').addEventListener('click', () => work(async () => { state.page++; await refreshView(); }));
  $('tab-history').addEventListener('click', () => work(async () => { state.serverTab = 'history'; await refreshView(); }));
  $('tab-alerts').addEventListener('click', () => work(async () => { state.serverTab = 'alerts'; state.alertBefore = null; await refreshView(); }));
  $('history-older').addEventListener('click', () => work(async () => { state.historyBefore = state.historyNext; await history(); }));
  $('history-newest').addEventListener('click', () => work(async () => { state.historyBefore = null; await history(); }));
  $('alert-filter').addEventListener('change', () => work(async () => { state.alertBefore = null; await alerts(); }));
  $('alerts-older').addEventListener('click', () => work(async () => { state.alertBefore = state.alertNext; await alerts(); }));
  $('alerts-newest').addEventListener('click', () => work(async () => { state.alertBefore = null; await alerts(); }));
  $('delivery-filter').addEventListener('change', () => work(async () => { state.deliveryBefore = null; await deliveries(); }));
  $('deliveries-older').addEventListener('click', () => work(async () => { state.deliveryBefore = state.deliveryNext; await deliveries(); }));
  $('deliveries-newest').addEventListener('click', () => work(async () => { state.deliveryBefore = null; await deliveries(); }));
  $('deliveries-all').addEventListener('click', () => work(async () => { state.deliveryBefore = null; state.deliveryAlert = null; await deliveries(); }));
  $('dialog-close').addEventListener('click', () => $('evidence-dialog').close());
  $('download-evidence').addEventListener('click', () => {
    if (!state.evidence) return; const url = URL.createObjectURL(new Blob([state.evidence.content], { type:'application/json' }));
    const link = el('a'); link.href = url; link.download = state.evidence.filename; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  work(refreshView);
  setInterval(() => { if (!document.hidden && !$('evidence-dialog').open && !state.busy) work(refreshView); }, 15000);
})();
