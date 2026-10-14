'use strict';
const $ = id => document.getElementById(id);
let targets = [], activeId = null, pollTimer = null, report = null, editing = false, workspaceId = 'default';
const terminal = new Set(['completed', 'cancelled', 'failed', 'interrupted']);
function node(tag, text, cls) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; }
function message(text = '') { $('message').textContent = text; }
async function api(path, options = {}) {
  const response = await fetch(path, { ...options, headers: { 'Content-Type': 'application/json', ...(options.headers || {}) } });
  const data = await response.json();
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Invalid request. Check the entered values.');
  return data;
}
function button(text, handler, cls = '') { const b = node('button', text, cls); b.type = 'button'; b.addEventListener('click', async () => { b.disabled = true; try { await handler(); } catch (e) { message(e.message); } finally { b.disabled = false; } }); return b; }
async function loadScope(selected) {
  const data = await api(`/api/workspaces/${encodeURIComponent(workspaceId)}/scope`); targets = data.targets;
  const current = selected || $('target').value;
  $('target').replaceChildren(); $('targets').replaceChildren();
  if (!targets.length) { const option = node('option', 'Add an approved staging or lab target'); option.value = ''; $('target').append(option); $('targets').append(node('p', 'Your scope is empty. Add your first approved target.', 'hint')); }
  for (const t of targets) {
    const option = node('option', `${t.host} · ${t.environment}`); option.value = t.host; $('target').append(option);
    const row = node('div', undefined, 'row'), main = node('div', undefined, 'row-main'), actions = node('div', undefined, 'actions');
    main.append(node('b', t.host), node('small', `${t.environment} · ${t.paths.length} health paths${t.allow_private ? ' · private network approved' : ''}`));
    actions.append(button('Edit', () => editTarget(t)), button('Remove', async () => { if (!confirm(`Remove ${t.host} from approved scope?`)) return; await api(`/api/workspaces/${encodeURIComponent(workspaceId)}/scope/${encodeURIComponent(t.host)}`, { method: 'DELETE' }); await loadScope(); }, 'danger'));
    row.append(main, actions); $('targets').append(row);
  }
  if (targets.some(t => t.host === current)) $('target').value = current;
  showScopeMeta(); $('run').disabled = !targets.length || !!activeId;
}
function showScopeMeta() { const t = targets.find(t => t.host === $('target').value); $('scope-meta').textContent = t ? `Health paths: ${t.paths.join(', ') || 'root only'} · ${t.allow_private ? 'Private target explicitly approved' : 'Public addresses only'}` : ''; }
function editTarget(t) {
  editing = !!t; $('form-title').textContent = t ? 'Edit approved target' : 'Add an approved target'; $('host').value = t?.host || ''; $('host').readOnly = editing; $('environment').value = t?.environment || 'staging'; $('paths').value = t?.paths.join('\n') || ''; $('private').checked = t?.allow_private || false; $('target-authorized').checked = false; $('target-form').hidden = false; $('host').focus();
}
$('new-target').addEventListener('click', () => editTarget(null));
$('close-form').addEventListener('click', () => { $('target-form').hidden = true; });
$('target').addEventListener('change', showScopeMeta);
$('parse-openapi').addEventListener('click', async () => {
  const file=$('openapi-file').files?.[0];if(!file){message('Choose an OpenAPI JSON file first.');return}if(file.size>1024*1024){message('OpenAPI JSON must be smaller than 1 MB.');return}
  const button=$('parse-openapi');button.disabled=true;message('Reading the local API definition…');
  try{const result=await api(`/api/workspaces/${encodeURIComponent(workspaceId)}/openapi/paths`,{method:'POST',body:JSON.stringify({document_json:await file.text()})});const panel=$('openapi-results');panel.replaceChildren();panel.hidden=false;panel.append(node('p',result.note,'hint'));if(!result.paths.length){panel.append(node('p','No concrete GET or HEAD paths were found. Add health paths manually.','hint'));return}for(const path of result.paths){const label=node('label',undefined,'check'),box=document.createElement('input');box.type='checkbox';box.value=path;box.checked=true;label.append(box,node('span',path));panel.append(label)}const apply=buttonNode('Append selected paths',()=>{const selected=[...panel.querySelectorAll('input:checked')].map(x=>x.value);const values=[...new Set([...$('paths').value.split('\n').map(x=>x.trim()).filter(Boolean),...selected])].slice(0,10);$('paths').value=values.join('\n');panel.hidden=true;$('openapi-file').value='';message('Selected read-only paths added. Review them and confirm authorization before saving.');});panel.append(apply);message('Review the candidates. No scan requests were sent.')}catch(e){message(e.message)}finally{button.disabled=false}
});
function buttonNode(text,handler){const button=document.createElement('button');button.type='button';button.className='primary';button.textContent=text;button.addEventListener('click',handler);return button}
$('target-form').addEventListener('submit', async event => {
  event.preventDefault(); const submit = $('target-form').querySelector('[type=submit]'); submit.disabled = true;
  try { const host = $('host').value.trim(); await api(`/api/workspaces/${encodeURIComponent(workspaceId)}/scope/${encodeURIComponent(host)}`, { method: 'PUT', body: JSON.stringify({ host, environment: $('environment').value, paths: $('paths').value.split('\n').map(s => s.trim()).filter(Boolean), allow_private: $('private').checked, authorization_confirmed: $('target-authorized').checked }) }); await loadScope(host); $('target-form').hidden = true; message('Approved scope saved on this computer.'); } catch (e) { message(e.message); } finally { submit.disabled = false; }
});
function busy(id) { activeId = id; $('run').disabled = !!id || !targets.length; $('cancel').hidden = !id; $('workspace').disabled = !!id; $('new-workspace').disabled = !!id; }
async function startScan() {
  if (!$('scan-authorized').checked) throw new Error('Confirm that this target is authorized before running checks.');
  if (!$('target').value) throw new Error('Add an approved target first.');
  const data = await api(`/api/workspaces/${encodeURIComponent(workspaceId)}/scans`, { method: 'POST', body: JSON.stringify({ target: $('target').value, authorization_confirmed: true, workspace_id: workspaceId }) });
  busy(data.id); message(); $('report-panel').hidden = true; schedulePoll(); await loadHistory();
}
$('run').addEventListener('click', async () => { $('run').disabled = true; try { await startScan(); } catch (e) { message(e.message); $('run').disabled = !!activeId || !targets.length; } });
$('cancel').addEventListener('click', async () => { if (!activeId) return; try { await api(`/api/workspaces/${encodeURIComponent(workspaceId)}/scans/${activeId}/cancel`, { method: 'POST', body: '{}' }); $('progress').textContent = 'Cancelling after the current bounded network operation…'; } catch (e) { message(e.message); } });
function schedulePoll() { clearTimeout(pollTimer); pollTimer = setTimeout(poll, 700); }
async function poll() {
  if (!activeId) return;
  try { const job = await api(`/api/workspaces/${encodeURIComponent(workspaceId)}/scans/${activeId}`); $('progress').textContent = `${job.state}: ${job.progress}`; if (terminal.has(job.state)) { busy(null); if (job.report) renderReport(job); if (job.error) message(job.error); await loadHistory(); } else schedulePoll(); } catch (e) { message(`Status unavailable: ${e.message}. Retrying…`); schedulePoll(); }
}
async function loadHistory() {
  const data = await api(`/api/workspaces/${encodeURIComponent(workspaceId)}/scans`); $('history').replaceChildren();
  if (!data.scans.length) $('history').append(node('p', 'No scans yet. Completed reports will appear here.', 'hint'));
  for (const job of data.scans) {
    const row = node('div', undefined, 'row'), main = node('div', undefined, 'row-main'), actions = node('div', undefined, 'actions');
    main.append(node('b', job.target), node('small', `${new Date(job.created_at).toLocaleString()} · ${job.state}${job.error ? ' · ' + job.error : ''}`));
    if (job.state === 'completed') actions.append(button('Report', async () => { const full = await api(`/api/workspaces/${encodeURIComponent(workspaceId)}/scans/${job.id}`); renderReport(full); $('report-panel').scrollIntoView({ behavior: 'smooth' }); }), button('Retest', async () => { await loadScope(job.target); if (!targets.some(t => t.host === job.target)) throw new Error('This target has been removed from scope. Add and authorize it before retesting.'); $('scan-authorized').checked = false; $('target').focus(); message('Target selected. Confirm current authorization, then run checks.'); }));
    if (terminal.has(job.state)) actions.append(button('Delete', async () => { if (!confirm('Delete this locally stored scan report?')) return; await api(`/api/workspaces/${encodeURIComponent(workspaceId)}/scans/${job.id}`, { method: 'DELETE' }); if (report?.job_id === job.id) { report = null; $('report-panel').hidden = true; } await loadHistory(); }, 'danger'));
    else if (!activeId) { busy(job.id); schedulePoll(); }
    row.append(main, actions); $('history').append(row);
  }
}
function renderReport(job) {
  report = job.report; $('report-panel').hidden = false; $('report-title').textContent = report.target; $('report-meta').textContent = `${report.environment} · ${new Date(report.completed_at).toLocaleString()} · Scanner ${report.scanner_version}`;
  $('exports').replaceChildren(); for (const format of ['pdf', 'csv', 'json']) { const a = node('a', format.toUpperCase(), 'button'); a.href = `/api/workspaces/${encodeURIComponent(workspaceId)}/scans/${job.id}/report/${format}`; a.download = `report-${job.id}.${format}`; $('exports').append(a); }
  $('counts').replaceChildren(); for (const severity of ['critical', 'high', 'medium', 'low', 'info']) { const card = node('div', undefined, `count ${severity}`); card.append(node('b', String(report.summary[severity] || 0)), node('small', severity)); $('counts').append(card); }
  const c = report.comparison; $('comparison').textContent = c ? `Compared with previous identical scope: ${c.new.length} new, ${c.not_observed.length} not observed, ${c.changed.length} changed, ${c.unchanged.length} unchanged. ${c.note}` : 'First report for this scope. Repeat the assessment after remediation to compare findings.';
  $('evidence').textContent = JSON.stringify(report, null, 2); renderFindings();
}
function renderFindings() {
  if (!report) return; const severity = $('severity').value, search = $('search').value.toLowerCase(); const findings = report.findings.filter(f => (!severity || f.severity === severity) && JSON.stringify(f).toLowerCase().includes(search)); $('findings').replaceChildren();
  if (!findings.length) $('findings').append(node('p', report.findings.length ? 'No findings match these filters.' : 'No findings raised by these limited checks. Review probe errors and your environment baseline.', 'hint'));
  for (const f of findings) { const card = node('article', undefined, 'finding'), title = node('h3', f.title); title.append(node('span', f.severity, `badge ${f.severity}`)); card.append(title, node('p', `${f.category} · Confidence: ${f.confidence}`, 'metadata'), node('p', f.summary)); for (const evidence of f.evidence) card.append(node('p', `Evidence: ${evidence}`)); card.append(node('p', `Suggested action: ${f.remediation}`)); $('findings').append(card); }
}
$('severity').addEventListener('change', renderFindings); $('search').addEventListener('input', renderFindings);
$('refresh').addEventListener('click', () => loadHistory().catch(e => message(e.message)));
async function loadWorkspaces(preferred) {
  const data=await api('/api/workspaces'), select=$('workspace'), previous=preferred||workspaceId;
  select.replaceChildren();
  for(const item of data.workspaces){const option=node('option',item.name);option.value=item.id;select.append(option)}
  if(!data.workspaces.length) throw new Error('No customer workspace is available.');
  workspaceId=data.workspaces.some(x=>x.id===previous)?previous:data.workspaces[0].id;select.value=workspaceId;
  await loadScope();await loadHistory();
}
$('workspace').addEventListener('change',async()=>{workspaceId=$('workspace').value;report=null;$('report-panel').hidden=true;$('progress').textContent='';busy(null);try{await loadScope();await loadHistory()}catch(e){message(e.message)}});
$('new-workspace').addEventListener('click',async()=>{const name=prompt('Customer or workspace name:');if(name===null)return;try{const item=await api('/api/workspaces',{method:'POST',body:JSON.stringify({name})});busy(null);await loadWorkspaces(item.id);message(`Workspace ${item.name} is ready. Add its approved staging or lab targets.`)}catch(e){message(e.message)}});
(async () => { try { await loadWorkspaces(); } catch (e) { message(`Could not load workspace: ${e.message}`); } })();
