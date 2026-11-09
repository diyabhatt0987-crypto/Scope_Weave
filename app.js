(() => {
  'use strict';

  const KEYS = {
    scopes: 'sentinel-desk.scopes.v1',
    findings: 'sentinel-desk.findings.v1',
    activity: 'sentinel-desk.activity.v1',
    approvals: 'sentinel-desk.approvals.v1',
    imports: 'sentinel-desk.imports.v1',
    riskContexts: 'sentinel-desk.risk-contexts.v1',
    remediations: 'sentinel-desk.remediations.v1',
    findingReviews: 'sentinel-desk.finding-reviews.v1',
    activeScope: 'sentinel-desk.active-scope.v1',
  };
  const SEVERITY_ORDER = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1, Unknown: 0 };
  const REPORT_MODES = { all: 'Include all', deduplicated: 'Remove the duplicates', duplicates: 'Only duplicates' };
  const REMEDIATION_STATUS_LABELS = { planned: 'Planned', in_progress: 'In progress', fix_reported: 'Fix reported' };
  const RETEST_RESULT_LABELS = { verified: 'Fix verified', still_present: 'Still present', inconclusive: 'Inconclusive' };
  const FINDING_REVIEW_STATUS_LABELS = { needs_review: 'Needs review', confirmed: 'Confirmed issue', false_positive: 'False positive' };
  const REPORT_HEADER_ALIASES = new Map([
    ['content security policy csp header not set', 'Missing Content-Security-Policy header'],
    ['content security policy header not set', 'Missing Content-Security-Policy header'],
    ['content security policy header missing', 'Missing Content-Security-Policy header'],
    ['missing content security policy header', 'Missing Content-Security-Policy header'],
    ['strict transport security header not set', 'Missing Strict-Transport-Security header'],
    ['strict transport security header missing', 'Missing Strict-Transport-Security header'],
    ['hsts header missing', 'Missing Strict-Transport-Security header'],
    ['missing strict transport security header', 'Missing Strict-Transport-Security header'],
    ['x content type options header missing', 'Missing X-Content-Type-Options header'],
    ['x content type options header not set', 'Missing X-Content-Type-Options header'],
    ['missing x content type options header', 'Missing X-Content-Type-Options header'],
  ]);
  const BUG_REPORT_FIELDS = [
    ['title', 'Title'],
    ['description', 'Description'],
    ['steps', 'Steps to reproduce'],
    ['expected', 'Expected result'],
    ['actual', 'Actual result'],
    ['severity', 'Severity'],
  ];
  const WEB_WORDS = ['web', 'website', 'application', 'app', 'api', 'header', 'cookie', 'form', 'route'];
  const NETWORK_WORDS = ['network', 'port', 'service', 'host', 'tcp', 'reachability'];
  const INSTRUCTION_PATTERNS = [
    /\b(?:ignore|disregard|forget|override|bypass)\s+(?:(?:all|any|the|your)\s+)*(?:previous|prior|earlier|above|system|developer|safety)\s+(?:instructions?|prompts?|rules?|messages?|polic(?:y|ies))\b/i,
    /\b(?:reveal|print|show|output|repeat|disclose|leak)\s+(?:(?:me|the|your|full|original|hidden)\s+)*(?:system|developer)\s+(?:prompt|instructions?)\b/i,
    /(?:<\|(?:im_start|system|assistant|user)\|>|\[\/?INST\])/i,
  ];
  const IMPORT_TOOLS = [
    { name: 'Nmap', aliases: ['nmap'], area: 'Network', action: 'Network diagnostics' },
    { name: 'Nessus', aliases: ['nessus'], area: 'Network', action: 'Network diagnostics' },
    { name: 'OpenVAS / Greenbone', aliases: ['openvas', 'greenbone'], area: 'Network', action: 'Network diagnostics' },
    { name: 'Nikto', aliases: ['nikto'], area: 'Web', action: 'Web checks' },
    { name: 'OWASP ZAP', aliases: ['owasp zap', 'zap'], area: 'Web', action: 'Web checks' },
    { name: 'Burp Suite', aliases: ['burp'], area: 'Web', action: 'Web checks' },
  ];
  const state = {
    scopes: readStore(KEYS.scopes, []),
    findings: readStore(KEYS.findings, []),
    activity: readStore(KEYS.activity, []),
    approvals: readStore(KEYS.approvals, []),
    imports: readStore(KEYS.imports, []),
    riskContexts: readStore(KEYS.riskContexts, []),
    remediations: readStore(KEYS.remediations, []),
    findingReviews: readStore(KEYS.findingReviews, []),
    activeScopeId: readPreference(KEYS.activeScope, ''),
    importScopeId: '',
    lastPlan: null,
    fileAction: 'import',
    zapBusy: false,
    plannerBusy: false,
    plannerRequestId: 0,
    plannerWarningKey: '',
    bugReportSelection: null,
    findingReviewSelection: null,
    loadingSavedPdfs: false,
    movingSavedPdf: false,
  };

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const escapeHTML = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[char]);

  function readStore(key, fallback) {
    try {
      const value = JSON.parse(localStorage.getItem(key));
      return Array.isArray(value) ? value : fallback;
    } catch (_) {
      return fallback;
    }
  }

  function readPreference(key, fallback) {
    try { return localStorage.getItem(key) || fallback; } catch (_) { return fallback; }
  }

  function saveActiveScope() {
    try {
      localStorage.setItem(KEYS.activeScope, state.activeScopeId || '');
      return true;
    } catch (_) {
      toast('The active lab could not be saved in browser storage.', true);
      return false;
    }
  }

  function saveStore(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
      return true;
    } catch (_) {
      toast('Browser storage is unavailable or full. Export your report before closing this page.', true);
      return false;
    }
  }

  function migrateEvidenceTimestampBasis() {
    let changed = false;
    for (const finding of state.findings) {
      if (finding.timestamp_basis === 'Imported file modification time; scanner timestamp unavailable') {
        finding.timestamp_basis = 'Import time; earlier importer did not capture file modification time';
        changed = true;
      }
      for (const record of finding.evidence_records || []) {
        if (record.timestamp_basis === 'Imported file modification time; scanner timestamp unavailable') {
          record.timestamp_basis = 'Import time; earlier importer did not capture file modification time';
          changed = true;
        }
      }
    }
    if (changed) saveStore(KEYS.findings, state.findings);
  }
  migrateEvidenceTimestampBasis();

  function makeId(prefix = 'ID') {
    return `${prefix}-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 7).toUpperCase()}`;
  }

  function toast(message, isError = false) {
    const region = $('#toastRegion');
    const node = document.createElement('div');
    node.className = `toast${isError ? ' error' : ''}`;
    node.textContent = message;
    region.append(node);
    window.setTimeout(() => node.remove(), 4500);
  }

  function recordActivity(action, details = '') {
    const result = ({
      SCOPE_REGISTERED: 'Saved', SCOPE_SELECTED: 'Selected', SCOPE_REMOVED: 'Moved to Trash', SCOPE_RESTORED: 'Restored',
      PLAN_CREATED: state.lastPlan?.plannerMode === 'groq' ? 'Review ready · Groq cloud'
        : state.lastPlan?.plannerMode === 'ollama' ? 'Plan ready · local AI' : 'Plan ready · rule fallback',
      IMPORT_REVIEWED: 'Reviewed · no in-scope records', RESULTS_IMPORTED: 'Evidence imported',
      ZAP_SCAN_STARTED: 'Running · confirmed', ZAP_SCAN_COMPLETED: 'Completed · evidence imported',
      ZAP_SCAN_FAILED: 'Failed · recovery shown', RISK_CONTEXT_UPDATED: 'Context saved',
      VALIDATION_APPROVED_NOT_EXECUTED: 'Decision recorded · not executed',
      VALIDATION_REJECTED: 'Decision recorded · not executed',
      REMEDIATION_SELECTED: 'Tracking started', REMEDIATION_UPDATED: 'Remediation saved',
      RETEST_RECORDED: 'Analyst retest recorded',
      FINDING_REVIEW_SAVED: 'Analyst finding review saved',
    })[action] || 'Recorded';
    state.activity.unshift({
      id: makeId('ACT'),
      actor: 'Assessment analyst',
      action,
      details: String(details).slice(0, 800),
      result,
      timestamp: new Date().toISOString(),
    });
    state.activity = state.activity.slice(0, 300);
    saveStore(KEYS.activity, state.activity);
    renderActivity();
    renderMetrics();
  }

  function navigate(pageName) {
    const page = $(`#page-${pageName}`);
    if (!page) return;
    $$('.page').forEach((node) => node.classList.toggle('active', node === page));
    $$('.nav-item').forEach((node) => node.classList.toggle('active', node.dataset.page === pageName));
    const label = $(`.nav-item[data-page="${pageName}"]`);
    $('#pageTitle').textContent = label ? (label.dataset.title || label.textContent.trim()) : 'Assessment';
    if (pageName === 'findings') renderFindings();
    if (pageName === 'activity') renderActivity();
    if (pageName === 'saved-pdfs') loadSavedPdfs();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function activeScope() {
    const selected = $('#targetSelect')?.value || state.activeScopeId;
    return availableScopes().find((scope) => scope.id === selected) || null;
  }

  function availableScopes() {
    return state.scopes.filter((scope) => !scope.deletedAt);
  }

  function normalizeOrigin(input) {
    const value = String(input || '').trim();
    if (!value || /\s/.test(value)) throw new Error('Enter the exact authorized lab URL origin.');
    let url;
    try { url = new URL(value); } catch (_) { throw new Error('Enter a valid URL such as https://lab.example.test.'); }
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Only HTTP and HTTPS lab origins are supported.');
    if (url.username || url.password) throw new Error('Do not put credentials in a target URL.');
    if (url.pathname !== '/' || url.search || url.hash) throw new Error('Enter the origin only: scheme, host, and optional port.');
    return url.origin.toLowerCase();
  }

  function normalizePath(value) {
    let path = String(value || '/').trim().replace(/\\/g, '/');
    for (let attempt = 0; attempt < 4; attempt += 1) {
      try {
        const decoded = decodeURIComponent(path);
        if (decoded === path) break;
        path = decoded;
      } catch (_) { break; }
    }
    if (!path.startsWith('/')) path = `/${path}`;
    path = path.replace(/\/+/g, '/');
    const parts = [];
    for (const part of path.split('/')) {
      if (!part || part === '.') continue;
      if (part === '..') parts.pop();
      else parts.push(part);
    }
    return `/${parts.join('/')}`.toLowerCase();
  }

  function pathExcluded(path, exclusions) {
    const candidate = normalizePath(path);
    return (exclusions || []).some((item) => {
      const prefix = normalizePath(item).replace(/\/$/, '') || '/';
      return prefix === '/' || candidate === prefix || candidate.startsWith(`${prefix}/`)
        || candidate.startsWith(`${prefix}?`) || candidate.startsWith(`${prefix};`);
    });
  }

  function isLocalLabOrigin(origin) {
    try {
      const hostname = new URL(origin).hostname.toLowerCase().replace(/^\[|\]$/g, '');
      return ['localhost', '127.0.0.1', '::1'].includes(hostname);
    } catch (_) { return false; }
  }

  function authorizationLabel(scope) {
    return scope?.environment === 'self-owned-local-lab' ? 'Self-owned local practice lab'
      : scope?.environment === 'organizer-designated-lab' ? 'Organizer-approved lab' : 'Unrecognized authorization basis';
  }

  function renderAuthorizationControls() {
    const local = $('#scopeAuthorizationType').value === 'self-owned-local-lab';
    $('#scopeReferenceLabel').textContent = local ? 'Local ownership / authorization reference' : 'Organizer lab ID or written approval reference';
    $('#scopeReference').placeholder = local ? 'For example: self-owned local Juice Shop practice lab' : 'Short approval reference only — never paste credentials';
    $('#scopeAuthorizationHelp').textContent = local
      ? 'Use your own running lab on this computer. This option accepts localhost, 127.0.0.1 or ::1 only.'
      : 'Use the exact target and actions explicitly approved by the organizer. Record the actual approval reference.';
    $('#scopeAttestationText').textContent = local
      ? 'I control this local lab instance and authorize the selected actions for this exact target.'
      : 'I confirm this exact target and the selected actions are explicitly authorized by the organizer.';
  }

  function fillLocalJuiceShopScope() {
    $('#scopeAuthorizationType').value = 'self-owned-local-lab';
    $('#scopeLabel').value = 'Local Juice Shop';
    $('#scopeOrigin').value = 'http://127.0.0.1:3000';
    $('#scopeReference').value = 'Self-owned local Juice Shop practice lab';
    $('#scopeExclusions').value = '';
    $('#scopeAttestation').checked = false;
    $$('input[name="permission"]', $('#scopeForm')).forEach((input) => {
      input.checked = ['Web checks', 'Scanner result import'].includes(input.value);
    });
    renderAuthorizationControls();
    toast('Check that your local Juice Shop is running, then confirm ownership and save.');
  }

  function checkScope(target, scope, actions = []) {
    if (!scope) return { allowed: false, reason: 'No authorized lab scope is selected.' };
    let url;
    try { url = new URL(target); } catch (_) { return { allowed: false, reason: 'Enter a valid target URL.' }; }
    if (!['http:', 'https:'].includes(url.protocol) || url.origin.toLowerCase() !== scope.origin.toLowerCase()) {
      return { allowed: false, reason: 'The target origin does not match the registered lab.' };
    }
    if (pathExcluded(url.pathname, scope.exclusions)) {
      return { allowed: false, reason: 'This path is listed as excluded for the selected lab.' };
    }
    const denied = actions.filter((action) => !scope.permissions.includes(action));
    if (denied.length) return { allowed: false, reason: `This lab record does not permit: ${denied.join(', ')}.` };
    if (!['organizer-designated-lab', 'self-owned-local-lab'].includes(scope.environment) || !scope.attested || !scope.approvalReference) {
      return { allowed: false, reason: 'The authorization basis, confirmation or reference is missing.' };
    }
    if (scope.environment === 'self-owned-local-lab' && !isLocalLabOrigin(scope.origin)) {
      return { allowed: false, reason: 'A self-owned local lab must use localhost, 127.0.0.1 or ::1.' };
    }
    return { allowed: true, reason: 'Exact lab origin, authorization record and selected permissions match.' };
  }

  function renderScopeOptions() {
    const select = $('#targetSelect');
    const currentValue = select.value || state.activeScopeId;
    const scopes = availableScopes();
    select.innerHTML = '<option value="">Choose a registered lab</option>' + scopes.map((scope) =>
      `<option value="${escapeHTML(scope.id)}">${escapeHTML(scope.label)} · ${escapeHTML(scope.origin)}</option>`
    ).join('');
    if (scopes.some((scope) => scope.id === currentValue)) select.value = currentValue;
    else if (scopes.length === 1) select.value = scopes[0].id;
    state.activeScopeId = select.value;
    const scope = activeScope();
    $('#gettingStarted').hidden = Boolean(scope);
    const scannerScopeStatus = $('#integrationScopeStatus');
    if (scannerScopeStatus) {
      scannerScopeStatus.textContent = scope
        ? `Selected lab: ${scope.label} · ${scope.origin}. Only actions allowed for this lab can be used.`
        : 'Add or select an approved lab first. Scanning and imports stay locked until then.';
    }
    const planFoldout = $('#overviewPlan');
    const scopeKey = scope?.id || '';
    if (planFoldout.dataset.scopeId !== scopeKey) {
      planFoldout.open = Boolean(scope);
      planFoldout.dataset.scopeId = scopeKey;
      $('#plannerCloudConsent').checked = false;
      $('#excludeFlaggedText').checked = true;
      state.plannerRequestId += 1;
      if (state.lastPlan?.scopeId === scopeKey) renderPlan(state.lastPlan);
      else {
        $('#planResult').className = 'plan-result empty-state';
        $('#planResult').innerHTML = '<span class="empty-icon">✳</span><strong>Your planner response will appear here</strong><p>Choose the provider and ask about this lab’s available evidence.</p>';
      }
    }
    const canImport = Boolean(scope && checkScope(scope.origin, scope, ['Scanner result import']).allowed);
    const canZapScan = Boolean(scope && checkScope(scope.origin, scope, ['Web checks', 'Scanner result import']).allowed);
    $('#integrationsImportButton').disabled = !canImport;
    $('#zapScanButton').disabled = !canZapScan || state.zapBusy;
    $('#reportButton').disabled = !scope;
    const summary = $('#scopeSummary');
    if (!scope) {
      summary.className = 'scope-empty';
      summary.innerHTML = '<span class="scope-ring">◎</span><strong>No lab scope registered</strong><p>Add your own local lab or an organizer-approved target, authorization reference, excluded paths, and allowed actions.</p><button class="secondary-button" data-goto="scope">Manage scope</button>';
      summary.querySelector('[data-goto]')?.addEventListener('click', () => navigate('scope'));
    } else {
      summary.className = 'scope-active';
      summary.innerHTML = `<div class="scope-state"><i class="status-dot"></i><strong>Registered lab scope</strong><span>REFERENCE RECORDED</span></div><div class="scope-origin">${escapeHTML(scope.origin)}</div><div class="scope-summary-meta"><span>Lab</span><b>${escapeHTML(scope.label)}</b><span>Permitted</span><b>${escapeHTML(scope.permissions.join(', ') || 'None')}</b><span>Exclusions</span><b>${escapeHTML(scope.exclusions.join(', ') || 'None')}</b></div>`;
    }
    renderScopes();
    renderMetrics();
    renderPlannerControls();
  }

  function renderScopes() {
    const scopes = availableScopes();
    $('#scopeCount').textContent = String(scopes.length);
    $('#scopeTrash').innerHTML = state.scopes.filter((scope) => scope.deletedAt).map((scope) => `
      <article class="scope-card"><div class="scope-card-head"><div><h3>${escapeHTML(scope.label)}</h3><div class="origin">${escapeHTML(scope.origin)}</div></div>
      <button type="button" class="secondary-button compact" data-restore-scope="${escapeHTML(scope.id)}">Restore</button></div></article>
    `).join('') || '<p class="muted-note">Scope Trash is empty.</p>';
    const list = $('#scopeList');
    if (!scopes.length) {
      list.innerHTML = '<div class="empty-list">No scope records yet. Register your own running local lab or an organizer-approved target to unlock scoped imports.</div>';
      return;
    }
    list.innerHTML = scopes.map((scope) => {
      const isActive = scope.id === state.activeScopeId;
      return `
      <article class="scope-card${isActive ? ' active' : ''}">
        <div class="scope-card-head"><div><h3>${escapeHTML(scope.label)}</h3><div class="origin">${escapeHTML(scope.origin)}</div></div><span class="status-tag ${isActive ? 'live' : 'import'}">${isActive ? 'CURRENT SCOPE' : 'ATTESTATION SAVED'}</span></div>
        <div class="scope-meta"><span>Authorization basis</span><b>${escapeHTML(authorizationLabel(scope))}</b><span>Reference</span><b>${escapeHTML(scope.approvalReference)}</b><span>Registered</span><b>${escapeHTML(formatDate(scope.createdAt))}</b><span>Excluded paths</span><b>${escapeHTML(scope.exclusions.join(', ') || 'None')}</b><span class="scope-permissions">Permissions: <b>${escapeHTML(scope.permissions.join(', ') || 'None')}</b></span></div>
        <div class="scope-actions"><button class="secondary-button" data-select-scope="${escapeHTML(scope.id)}" ${isActive ? 'disabled' : ''}>${isActive ? 'Selected' : 'Use this lab'}</button><button class="delete-button" data-remove-scope="${escapeHTML(scope.id)}">Delete scope</button></div>
      </article>`;
    }).join('');
    $$('[data-select-scope]').forEach((button) => button.addEventListener('click', () => selectScope(button.dataset.selectScope)));
    $$('[data-remove-scope]').forEach((button) => button.addEventListener('click', () => setScopeTrash(button.dataset.removeScope, true)));
  }

  function selectScope(id) {
    const scope = availableScopes().find((item) => item.id === id);
    if (!scope) return;
    state.activeScopeId = scope.id;
    $('#targetSelect').value = scope.id;
    saveActiveScope();
    renderScopeOptions();
    recordActivity('SCOPE_SELECTED', `${scope.origin} · ${scope.label}`);
    toast(`${scope.label} is now the active lab.`);
    navigate('overview');
  }

  function renderMetrics() {
    const scopes = availableScopes();
    const ids = new Set(scopes.map((scope) => scope.id));
    const origins = new Set(scopes.map((scope) => scope.origin));
    const findings = state.findings.filter((item) => ids.has(item.scopeId));
    $('#metricScopes').textContent = String(scopes.length);
    $('#metricFindings').textContent = String(findings.length);
    $('#metricHigh').textContent = String(findings.filter((item) => ['High', 'Critical'].includes(item.severity)).length);
    $('#metricDecisions').textContent = String(state.approvals.filter((item) => origins.has(item.target)).length);
    $('#navFindingCount').textContent = String(findings.length);
    $('#activityCount').textContent = String(state.activity.length);
    const scope = activeScope();
    $('#activeTargetChip').textContent = scope ? scope.origin : 'No active lab selected';
    renderApprovalOptions();
    renderEvidenceCoverage();
    renderPlannerWarnings(scope);
  }

  function toolForName(value) {
    const name = String(value || '').toLowerCase();
    return IMPORT_TOOLS.find((tool) => tool.aliases.some((alias) => name.includes(alias))) || null;
  }

  function findingReviewStatus(finding) {
    const status = findingReviewFor(finding)?.status;
    return Object.hasOwn(FINDING_REVIEW_STATUS_LABELS, status) ? status : 'needs_review';
  }

  function findingUsesTool(finding, toolName) {
    return (finding.evidence_records || []).some((record) => toolForName(record.source_tool)?.name === toolName);
  }

  function buildEvidenceCoverage(scope, request = '', reportFindings) {
    const scopeImports = scope ? state.imports.filter((run) => run.scopeId === scope.id) : [];
    const scopeFindings = scope ? state.findings.filter((finding) => finding.scopeId === scope.id) : [];
    const coverageFindings = reportFindings ?? scopeFindings;
    const files = scopeImports.flatMap((run) => (run.files || []).map((file) => ({ ...file, checkedAt: run.startedAt })));
    const tools = IMPORT_TOOLS.map((tool) => {
      const toolFiles = files.filter((file) => toolForName(file.tool)?.name === tool.name)
        .sort((a, b) => new Date(b.checkedAt || 0) - new Date(a.checkedAt || 0));
      const latest = toolFiles[0] || null;
      const acceptedRecords = toolFiles.reduce((sum, file) => sum + (Number(file.acceptedRecords) || 0), 0);
      const findingGroups = coverageFindings.filter((finding) => findingUsesTool(finding, tool.name)).length;
      const permission = checkScope(scope?.origin, scope, ['Scanner result import', tool.action]);
      const usable = toolFiles.some((file) => Number(file.acceptedRecords) > 0 || file.outcome === 'no_observations')
        || scopeFindings.some((finding) => findingUsesTool(finding, tool.name));
      let label = 'No report imported';
      let tone = 'neutral';
      let detail = scope ? 'No file from this tool is recorded for this lab.' : 'Register an approved lab to see its report status.';
      if (scope && !permission.allowed && !latest) {
        label = 'Not permitted';
        detail = permission.reason;
        tone = 'warning';
      } else if (latest) {
        const resultLabel = {
          imported: ['Evidence imported', 'accepted'],
          partial: ['Partly in scope', 'warning'],
          no_observations: ['Report read · no observations', 'neutral'],
          out_of_scope: ['No in-scope records', 'warning'],
          blocked: ['Blocked by saved rules', 'error'],
          failed: ['Latest file could not be read', 'error'],
        }[latest.outcome] || ['File reviewed', 'neutral'];
        [label, tone] = resultLabel;
        if (latest.outcome === 'imported') detail = `${latest.acceptedRecords || 0} in-scope source record(s) in the latest file.`;
        else if (latest.outcome === 'partial') detail = `${latest.acceptedRecords || 0} accepted and ${latest.excludedRecords || 0} excluded in the latest file.`;
        else if (latest.outcome === 'no_observations') detail = 'A file was read, but it contained no reportable observations.';
        else if (latest.outcome === 'out_of_scope') detail = `${latest.excludedRecords || 0} record(s) did not match this lab scope.`;
        else detail = latest.message || 'Check the import history for the reason.';
      }
      return { ...tool, label, tone, detail, fileCount: toolFiles.length, acceptedRecords, findingGroups, latest, permission, usable };
    });

    const webService = scopeFindings.find((finding) => {
      if (findingReviewStatus(finding) === 'false_positive') return false;
      const text = `${finding.title} ${finding.affected_asset}`.toLowerCase();
      return /open.{0,30}(http|https|web)/.test(text) || /:(80|443|3000|8000|8080|8443)(?:\/|$)/.test(text);
    });
    const next = selectCoverageNextStep(scope, request, scopeFindings, tools, webService, scopeImports[0]?.files || []);
    return { scopeId: scope?.id || '', tools, fileCount: files.length, next, webService };
  }

  function selectCoverageNextStep(scope, request, findings, tools, webService, latestFiles) {
    if (!scope) {
      return {
        title: 'Register the approved lab',
        reason: 'The planner needs the authorized lab address, authorization reference, and permitted actions before it can make a scope-specific suggestion.',
        status: 'WAITING',
      };
    }
    const scopeCheck = checkScope(scope.origin, scope);
    if (!scopeCheck.allowed) return { title: 'Review lab authorization', reason: scopeCheck.reason, status: 'LOCKED' };

    const ordered = [...findings].sort((a, b) => (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0) || compareReviewPriority(a, b));
    const pending = ordered.find((finding) => findingReviewStatus(finding) === 'needs_review');
    const reviewStep = (finding) => ({
      title: `Review finding: ${finding.title}`,
      reason: `${finding.sources?.join(', ') || finding.source_tool || 'Imported scanner evidence'} reported ${finding.severity} for ${finding.finding_id}. Its analyst status is Needs review. Check the source evidence and record your decision.`,
      status: 'REVIEW',
      findingId: finding.finding_id,
    });
    if (pending && ['Critical', 'High'].includes(pending.severity)) return reviewStep(pending);

    const requestedWeb = matchText(request, WEB_WORDS);
    const requestedNetwork = matchText(request, NETWORK_WORDS);
    const relevantAreas = new Set();
    if (requestedNetwork) relevantAreas.add('Network');
    if (requestedWeb || webService) relevantAreas.add('Web');
    if (!relevantAreas.size && !tools.some((tool) => tool.usable)) {
      relevantAreas.add(scope.permissions.includes('Network diagnostics') && !scope.permissions.includes('Web checks') ? 'Network' : 'Web');
    }
    const importNeedsReview = (file) => ['failed', 'out_of_scope', 'blocked'].includes(file?.outcome);
    const failedTool = tools.find((tool) => !tool.usable && tool.permission.allowed
      && (relevantAreas.size === 0 || relevantAreas.has(tool.area)) && importNeedsReview(tool.latest));
    const failedFile = failedTool?.latest || latestFiles.find((file) => !toolForName(file.tool) && importNeedsReview(file));
    if (failedFile) return {
      title: 'Check the latest import result',
      reason: `${failedFile.fileName} was marked ${String(failedFile.outcome).replaceAll('_', ' ')}. Review its import history and saved scope before trying another approved export.`,
      status: 'REVIEW',
      toolName: failedTool?.name,
    };

    for (const area of relevantAreas) {
      const candidates = tools.filter((tool) => tool.area === area);
      if (candidates.some((tool) => tool.usable)) continue;
      const tool = area === 'Web' ? candidates.find((candidate) => candidate.name === 'OWASP ZAP') : candidates[0];
      const context = area === 'Web' && webService ? `Imported evidence points to a web service at ${webService.affected_asset}. ` : '';
      if (!tool.permission.allowed) return {
        title: `Confirm ${area.toLowerCase()} review permission`,
        reason: `${context}${tool.permission.reason}`,
        status: 'LOCKED',
      };
      return {
        title: `Import an approved ${tool.name} report`,
        reason: `${context}There is no usable ${area.toLowerCase()} scanner report recorded for this lab. An approved ${tool.name} export can fill that evidence gap.`,
        status: 'RECOMMENDED',
        toolName: tool.name,
      };
    }

    if (pending) return reviewStep(pending);
    const confirmed = ordered.find((finding) => findingReviewStatus(finding) === 'confirmed');
    if (confirmed) return {
      title: `Follow up on confirmed finding: ${confirmed.title}`,
      reason: `The analyst marked ${confirmed.finding_id} Confirmed issue. Review its remediation and retest record for the final report.`,
      status: 'REVIEW',
      findingId: confirmed.finding_id,
    };
    return {
      title: 'Review scope limits and prepare the report',
      reason: 'There are no findings waiting for analyst review in the current evidence. Document what the recorded reports covered and any areas that still need testing.',
      status: 'REVIEW',
    };
  }

  function coverageToolDecision(tool, next) {
    if (!tool.permission.allowed) return { choice: 'Skip for now', reason: tool.permission.reason };
    if (tool.usable) return { choice: 'Use recorded evidence', reason: 'This lab already has usable evidence from this scanner. Another run or import is not the current priority.' };
    if (tool.name === next.toolName) return { choice: next.status === 'REVIEW' ? 'Review the import' : 'Suggested export', reason: next.reason };
    return { choice: 'Hold for now', reason: 'This tool has no usable evidence recorded. Follow the current next step before deciding whether to collect more.' };
  }

  function renderEvidenceCoverage() {
    const scope = activeScope();
    const request = $('#requestText')?.value.trim() || '';
    const coverage = buildEvidenceCoverage(scope, request);
    const grid = $('#coverageToolGrid');
    const next = $('#coverageNextStep');
    if (!grid || !next) return;
    grid.innerHTML = coverage.tools.map((tool) => `
      <article class="coverage-tool-card">
        <div class="coverage-tool-top"><strong>${escapeHTML(tool.name)}</strong><span>${escapeHTML(tool.area)}</span></div>
        <span class="coverage-status ${tool.tone}">${escapeHTML(tool.label)}</span>
        <p>${escapeHTML(tool.detail)}</p>
        <small>${tool.fileCount} file(s) reviewed · ${tool.findingGroups} finding group(s) linked</small>
      </article>`).join('');
    next.innerHTML = `<div class="coverage-next-icon">→</div><div><span class="eyebrow">WHY THIS NEXT?</span><strong>${escapeHTML(coverage.next.title)}</strong><p>${escapeHTML(coverage.next.reason)}</p></div><span class="status-tag ${coverage.next.status === 'LOCKED' ? 'planned' : 'import'}">${escapeHTML(coverage.next.status)}</span>`;
    const reviewButton = $('#coverageReviewFindingButton');
    reviewButton.hidden = !coverage.next.findingId;
    reviewButton.dataset.findingId = coverage.next.findingId || '';
    $('#coverageToolChoices').hidden = !scope;
    $('#coverageToolChoicesList').innerHTML = coverage.tools.map((tool) => {
      const { choice, reason } = coverageToolDecision(tool, coverage.next);
      return `<li><strong>${escapeHTML(`${tool.name} · ${choice}`)}</strong><small>${escapeHTML(reason)}</small></li>`;
    }).join('');
    $('#coverageRefreshPlanButton').disabled = !scope || state.plannerBusy;
    updatePlannerFreshness();
  }

  function formatDate(value) {
    if (!value) return 'Not recorded';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
  }

  function setScopeTrash(id, deleted) {
    const scopes = readStore(KEYS.scopes, []);
    const scope = scopes.find((item) => item.id === id);
    if (!scope || Boolean(scope.deletedAt) === deleted) return;
    if (deleted && !window.confirm(`Move ${scope.origin} and its assessment records to Scope Trash?`)) return;
    const updated = scopes.map((item) => item.id === id
      ? { ...item, deletedAt: deleted ? new Date().toISOString() : null }
      : item);
    if (!saveStore(KEYS.scopes, updated)) return;
    state.scopes = updated;
    renderAll();
    saveActiveScope();
    recordActivity(deleted ? 'SCOPE_REMOVED' : 'SCOPE_RESTORED', `${scope.origin} · ${scope.label}`);
    toast(deleted ? 'Scope moved to Trash. Restore it from Scope Trash.' : 'Scope and assessment records restored.');
  }

  function submitScope(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const environment = $('#scopeAuthorizationType').value;
    if (!['self-owned-local-lab', 'organizer-designated-lab'].includes(environment)) return toast('Choose a supported authorization basis.', true);
    const attested = $('#scopeAttestation').checked;
    if (!attested) return toast('Confirm that you control this local lab or have organizer authorization for the selected actions.', true);
    const label = $('#scopeLabel').value.trim();
    if (!label) return toast('Enter a lab or assessment name.', true);
    let origin;
    try { origin = normalizeOrigin($('#scopeOrigin').value); } catch (error) { return toast(error.message, true); }
    if (environment === 'self-owned-local-lab' && !isLocalLabOrigin(origin)) {
      return toast('Choose your own local lab at localhost, 127.0.0.1 or ::1. The OWASP information website and public demo are not your local instance.', true);
    }
    const approvalReference = $('#scopeReference').value.trim();
    if (!approvalReference || approvalReference.length > 160 || /[\u0000-\u001f\u007f]/.test(approvalReference)) {
      return toast('Enter a short local ownership or organizer approval reference. Do not paste credentials or multiline text.', true);
    }
    const registered = state.scopes.find((scope) => scope.origin === origin);
    if (registered) return toast(registered.deletedAt ? 'This origin is in Scope Trash. Restore it to use it again.' : 'This exact origin is already registered.', true);
    const permissions = $$('input[name="permission"]:checked', form).map((input) => input.value);
    if (!permissions.length) return toast('Select at least one permitted action.', true);
    const allowedPermissions = new Set(['Web checks', 'Network diagnostics', 'Scanner result import', 'Layer review']);
    if (permissions.some((permission) => !allowedPermissions.has(permission))) return toast('The permission list contains an unsupported action.', true);
    if (!permissions.includes('Scanner result import') || !permissions.some((permission) => ['Web checks', 'Network diagnostics'].includes(permission))) {
      return toast('For this prototype, select Scanner result import and at least one permitted source area: Web checks or Network diagnostics.', true);
    }
    const rawExclusions = $('#scopeExclusions').value.split(',').map((value) => value.trim()).filter(Boolean);
    if (rawExclusions.length > 20) return toast('Add no more than 20 excluded paths to one scope.', true);
    if (rawExclusions.some((path) => !path.startsWith('/') || /[?#\s]|:\/\//.test(path) || /%(?![0-9a-f]{2})/i.test(path))) {
      return toast('Each excluded path must start with / and cannot contain a full URL, query, fragment, space, or malformed percent escape.', true);
    }
    const exclusions = [...new Set(rawExclusions.map(normalizePath))];
    if (exclusions.includes('/')) return toast('The path / excludes the whole site. Remove it or choose a narrower path.', true);
    const scope = {
      id: makeId('LAB'),
      label,
      origin,
      environment,
      approvalReference,
      exclusions,
      permissions,
      attested: true,
      createdAt: new Date().toISOString(),
    };
    const updatedScopes = [...state.scopes, scope];
    if (!saveStore(KEYS.scopes, updatedScopes)) return;
    state.scopes = updatedScopes;
    state.activeScopeId = scope.id;
    renderScopeOptions();
    $('#targetSelect').value = scope.id;
    state.activeScopeId = scope.id;
    saveActiveScope();
    form.reset();
    renderAuthorizationControls();
    $$('input[name="permission"]').forEach((input) => { input.checked = ['Web checks', 'Scanner result import'].includes(input.value); });
    recordActivity('SCOPE_REGISTERED', `${origin} · ${authorizationLabel(scope)} · reference ${approvalReference} · ${permissions.join(', ')}`);
    toast('Authorized lab scope saved in this browser.');
    navigate('overview');
  }

  function matchText(text, words) {
    const lower = String(text || '').toLowerCase();
    return words.some((word) => lower.includes(word));
  }

  const PLANNER_STEP_REQUIREMENTS = {
    review_existing_evidence: [],
    import_approved_web_report: ['Scanner result import', 'Web checks'],
    run_zap_passive_crawl: ['Scanner result import', 'Web checks'],
    import_approved_network_report: ['Scanner result import', 'Network diagnostics'],
    record_human_review: ['Layer review'],
  };
  const PLANNER_STEP_LABELS = {
    review_existing_evidence: 'Review the evidence already collected',
    import_approved_web_report: 'Import an approved web scanner report',
    run_zap_passive_crawl: 'Run the approved ZAP crawl with passive checks',
    import_approved_network_report: 'Import an approved network scanner report',
    record_human_review: 'Record a human review decision',
  };

  function plannerStepAllowed(step, scope) {
    const required = PLANNER_STEP_REQUIREMENTS[step];
    return Boolean(required && required.every((permission) => scope.permissions.includes(permission)));
  }

  function instructionLikeExcerpt(value) {
    const text = String(value ?? '');
    for (const pattern of INSTRUCTION_PATTERNS) {
      const match = pattern.exec(text);
      if (!match) continue;
      const start = Math.max(0, match.index - 40);
      const end = Math.min(text.length, match.index + Math.min(match[0].length, 100) + 40);
      return `${start ? '…' : ''}${text.slice(start, end)}${end < text.length ? '…' : ''}`;
    }
    return '';
  }

  function renderPlannerControls() {
    const cloud = $('#plannerProvider').value === 'groq';
    $('#plannerCloudNotice').hidden = !cloud;
    $('#plannerCloudConsent').required = cloud;
    $('#plannerCloudConsent').disabled = state.plannerBusy;
    $('#excludeFlaggedText').disabled = state.plannerBusy;
    $('#plannerProvider').disabled = state.plannerBusy;
    $('#requestText').disabled = state.plannerBusy;
    $('#askPlannerButton').disabled = state.plannerBusy || !activeScope();
    $('#askPlannerButton').querySelector('span').textContent = state.plannerBusy
      ? 'Reviewing…' : cloud ? 'Ask Groq' : 'Ask planner';
    $('#planForm').setAttribute('aria-busy', String(state.plannerBusy));
    $('#coverageRefreshPlanButton').disabled = state.plannerBusy || !activeScope();
    $('#plannerProviderHint').textContent = cloud
      ? 'Groq needs internet access and a configured server key. Only the selected summary is shared after your consent; a failure shows rule-based fallback.'
      : 'Local Ollama stays on this computer. If it is unavailable, the app clearly labels its rule-based backup.';
    renderPlannerWarnings(activeScope());
  }

  function selectPlannerSources(records) {
    const selected = [];
    const tools = new Set();
    for (const record of records) {
      const name = String(record.source_tool || 'Unknown scanner').trim().toLowerCase();
      if (!tools.has(name)) {
        selected.push(record);
        tools.add(name);
      }
      if (selected.length === 3) break;
    }
    for (const record of records) {
      if (selected.length === 3) break;
      if (!selected.includes(record)) selected.push(record);
    }
    return selected;
  }

  function plannerEvidence(scope, provider, excludeFlagged = false) {
    const cloud = provider === 'groq';
    const warnings = [];
    const evidence = state.findings.filter((finding) => finding.scopeId === scope.id)
      .sort((a, b) => Number(findingReviewStatus(b) === 'needs_review') - Number(findingReviewStatus(a) === 'needs_review') || compareReviewPriority(a, b))
      .slice(0, cloud ? 10 : 25)
      .map((finding) => {
        const records = finding.evidence_records || [];
        const firstRecord = records[0] || evidenceRecord(finding);
        const summary = finding.description || finding.supporting_evidence || '';
        const summaryRecord = finding.description ? firstRecord
          : records.find((record) => record.supporting_evidence === summary) || firstRecord;
        const field = (label, value, limit, record) => {
          const excerpt = cloud ? instructionLikeExcerpt(value) : '';
          if (excerpt) {
            const source = [record.source_tool, record.source_file, record.raw_reference].filter(Boolean).join(' · ');
            warnings.push({ findingId: finding.finding_id, label, source, excerpt });
            if (excludeFlagged) return '[Flagged scanner text omitted]';
          }
          return String(value ?? '').slice(0, limit);
        };
        return {
          id: finding.finding_id,
          title: cloud ? field('Finding title', finding.title, 240, firstRecord) : finding.title,
          asset: cloud ? field('Affected asset', finding.affected_asset, 240, firstRecord) : finding.affected_asset,
          sources: finding.sources,
          severity: finding.severity,
          cvss: finding.cvss,
          summary: field('Finding summary', summary, 240, summaryRecord),
          validation: finding.validation_status,
          review_status: findingReviewStatus(finding),
          source_reports: selectPlannerSources(records).map((record) => ({
            tool: String(record.source_tool || 'Unknown scanner').slice(0, 80),
            severity: String(record.source_severity || 'Unknown').slice(0, 30),
            cvss: record.source_cvss ?? null,
            excerpt: field('Source excerpt', record.supporting_evidence || record.source_description, 180, record),
          })),
        };
      });
    return { evidence, warnings };
  }

  function renderPlannerWarnings(scope) {
    const panel = $('#plannerEvidenceWarnings');
    const cloud = $('#plannerProvider').value === 'groq';
    const warnings = cloud && scope ? plannerEvidence(scope, 'groq').warnings : [];
    panel.hidden = warnings.length === 0;
    const warningKey = JSON.stringify(warnings);
    if (state.plannerWarningKey === warningKey) return;
    state.plannerWarningKey = warningKey;
    $('#plannerCloudConsent').checked = false;
    $('#excludeFlaggedText').checked = true;
    $('#plannerWarningDetails').open = false;
    $('#plannerWarningCount').textContent = `${warnings.length} flagged scanner ${warnings.length === 1 ? 'field' : 'fields'} in this review`;
    $('#plannerWarningList').innerHTML = warnings.map(({ findingId, label, source, excerpt }) =>
      `<li><b>${escapeHTML(findingId)} · ${escapeHTML(label)}</b><small>${escapeHTML(source || 'Imported scanner report')}</small><pre>${escapeHTML(excerpt)}</pre></li>`
    ).join('');
  }

  function plannerEvidenceVersion(scopeId) {
    const imports = state.imports.filter((run) => run.scopeId === scopeId).map((run) => run.id);
    const reviews = state.findingReviews.filter((review) => review.scopeId === scopeId && review.status !== 'needs_review')
      .map((review) => [review.finding_id, review.status]).sort(([a], [b]) => a.localeCompare(b));
    return JSON.stringify([imports, reviews]);
  }

  function updatePlannerFreshness() {
    const notice = $('#plannerStaleNotice');
    const plan = state.lastPlan;
    if (notice && plan) notice.hidden = plan.evidenceVersion === plannerEvidenceVersion(plan.scopeId);
  }

  async function requestPlanner(scope, request, evidence, coverage, provider, cloudConsent) {
    if (provider === 'groq' && cloudConsent !== true) throw new Error('Allow sharing this lab’s summary before requesting Groq analysis.');
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 65000);
    let response;
    try {
      response = await fetch('/api/planner/suggest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify({ provider, cloudConsent, scope: {
          origin: scope.origin,
          environment: scope.environment,
          attested: scope.attested,
          approvalReference: scope.approvalReference,
          permissions: scope.permissions,
          exclusions: scope.exclusions,
        }, request, evidence, tool_coverage: coverage.tools.map((tool) => ({
          tool: tool.name,
          status: !tool.permission.allowed ? 'blocked' : tool.usable ? 'usable' : 'missing',
        })) }),
      });
    } catch (error) {
      throw new Error(error.name === 'AbortError' ? 'The selected AI provider timed out. Retry when it is available.' : 'Could not reach the planner service. Check that the project server is running.');
    } finally {
      window.clearTimeout(timeout);
    }
    let result;
    try { result = await response.json(); } catch (_) { throw new Error('The planner service returned an unreadable response.'); }
    if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('The planner service returned an invalid response.');
    if (!response.ok) throw new Error(result.error || 'The selected AI provider is unavailable.');
    const suggestion = result.suggestion;
    const suggestionKeys = suggestion && typeof suggestion === 'object' ? Object.keys(suggestion) : [];
    if (result.mode !== provider || !suggestion || !suggestionKeys.includes('next_step') || !suggestionKeys.includes('reason')
      || suggestionKeys.some((key) => !['next_step', 'reason', 'attempts'].includes(key))
      || ('attempts' in suggestion && (!Number.isInteger(suggestion.attempts) || suggestion.attempts < 1 || suggestion.attempts > 2))
      || !plannerStepAllowed(suggestion.next_step, scope)
      || typeof suggestion.reason !== 'string' || suggestion.reason.length < 20 || suggestion.reason.length > 360) {
      throw new Error('The model response did not pass planner checks.');
    }
    if (provider === 'groq') {
      const analysis = result.analysis;
      const knownIds = new Set(evidence.map((item) => item.id));
      const seenIds = new Set();
      const validText = (value, min, max) => typeof value === 'string' && value.trim().length >= min && value.length <= max;
      if (!analysis || typeof analysis !== 'object' || Array.isArray(analysis)
        || Object.keys(analysis).sort().join(',') !== 'limitations,observations,summary'
        || !validText(analysis.summary, 20, 1200)
        || !Array.isArray(analysis.observations) || analysis.observations.length > 10
        || !Array.isArray(analysis.limitations) || analysis.limitations.length > 5
        || !analysis.limitations.every((item) => validText(item, 10, 400))
        || !Number.isInteger(result.evidence_count) || result.evidence_count !== evidence.length
        || !validText(result.model, 1, 120)) throw new Error('Groq returned an incomplete evidence analysis.');
      for (const observation of analysis.observations) {
        if (!observation || typeof observation !== 'object' || Array.isArray(observation)
          || Object.keys(observation).sort().join(',') !== 'explanation,finding_id,next_review'
          || !knownIds.has(observation.finding_id) || seenIds.has(observation.finding_id)
          || !validText(observation.explanation, 20, 600) || !validText(observation.next_review, 10, 400)) {
          throw new Error('Groq cited evidence that was not supplied for this review.');
        }
        seenIds.add(observation.finding_id);
      }
    }
    return result;
  }

  async function generatePlan(event) {
    event.preventDefault();
    if (state.plannerBusy) return;
    const scope = activeScope();
    if (!scope) return toast('Register or select an authorized lab scope first.', true);
    const provider = $('#plannerProvider').value;
    const cloudConsent = $('#plannerCloudConsent').checked;
    if (!['ollama', 'groq'].includes(provider)) return toast('Choose a supported AI provider.', true);
    if (provider === 'groq' && !cloudConsent) {
      $('#plannerCloudConsent').focus();
      return toast('Review the sharing notice and allow this lab’s summary before asking Groq.', true);
    }
    const request = $('#requestText').value.trim() || 'Review the authorized lab evidence and summarize its security posture.';
    const webRequested = matchText(request, WEB_WORDS);
    const networkRequested = matchText(request, NETWORK_WORDS);
    const scopeFindings = state.findings.filter((finding) => finding.scopeId === scope.id);
    const coverage = buildEvidenceCoverage(scope, request);
    const adaptiveWebFollowup = !webRequested && networkRequested && Boolean(coverage.webService);
    const requestedActions = ['Scanner result import'];
    if (webRequested || !networkRequested || adaptiveWebFollowup) requestedActions.push('Web checks');
    if (networkRequested) requestedActions.push('Network diagnostics');
    const scopeCheck = checkScope(scope.origin, scope, requestedActions);
    const plan = [];
    const add = (title, reason, status = 'IMPORT-ONLY') => plan.push({ title, reason, status });
    add('Confirm lab scope', `Match the exact registered origin ${scope.origin}, approval reference, exclusions, and permitted actions before importing evidence.`, scopeCheck.allowed ? 'READY' : 'LOCKED');
    add(`Next step: ${coverage.next.title}`, coverage.next.reason, coverage.next.status);
    coverage.tools.filter((tool) => tool.usable && tool.permission.allowed).forEach((tool) => {
      add(`Reuse ${tool.name} evidence`, coverageToolDecision(tool, coverage.next).reason, 'READY');
    });
    add('Normalize and correlate', 'Merge only exact normalized title-and-asset matches. Preserve each source’s severity, CVSS, confidence, timestamp, reference, and evidence.');
    add('Analyst review and report', 'Include source evidence, analyst decisions, and remediation in the final report.');
    if (scopeFindings.some((finding) => ['Critical', 'High'].includes(finding.severity) && findingReviewStatus(finding) === 'needs_review')) {
      add('Human review checkpoint', 'High or Critical scanner findings are awaiting analyst review. The saved scope and any required human approval govern validation.', 'REVIEW');
    }
    const planContext = [];
    const sameScopeFindings = scopeFindings;
    if (sameScopeFindings.length) planContext.push(`Using ${sameScopeFindings.length} imported finding group(s) for this registered lab.`);
    if (adaptiveWebFollowup) planContext.push(`Imported evidence identifies a web-associated service at ${coverage.webService.affected_asset}.`);
    planContext.push(`Evidence coverage: ${coverage.next.reason}`);
    if (!scopeCheck.allowed) planContext.push(`Run/import gate locked: ${scopeCheck.reason}`);
    planContext.push('A scan starts only after a separate confirmation. The available ZAP mode is a scoped Spider crawl with passive checks; other tools remain import-only.');
    let plannerMode = 'fallback';
    let llmSuggestion = null;
    let analysis = null;
    let model = '';
    let evidenceCount = 0;
    const { evidence } = plannerEvidence(scope, provider, $('#excludeFlaggedText').checked);
    const evidenceVersion = plannerEvidenceVersion(scope.id);
    const evidenceSnapshot = evidence.map((item) => ({ id: item.id, title: item.title, asset: item.asset }));
    let fallbackReason = `${provider === 'groq' ? 'Groq' : 'Local Ollama'} is unavailable; the rule-based planner was used.`;
    const requestId = ++state.plannerRequestId;
    state.plannerBusy = true;
    $('#plannerCloudConsent').checked = false;
    $('#excludeFlaggedText').checked = true;
    renderPlannerControls();
    $('#planResult').className = 'plan-result empty-state';
    $('#planResult').innerHTML = `<span class="empty-icon">✳</span><strong>${provider === 'groq' ? 'Groq is reviewing the selected evidence…' : 'Asking local Ollama…'}</strong><p>No scan is started by this request.</p>`;
    try {
      const result = await requestPlanner(scope, request, evidence, coverage, provider, cloudConsent);
      llmSuggestion = result.suggestion;
      plannerMode = result.mode;
      model = result.model || '';
      analysis = result.analysis || null;
      evidenceCount = provider === 'groq' ? result.evidence_count : evidence.length;
      fallbackReason = '';
    } catch (error) {
      fallbackReason = String(error.message || fallbackReason).slice(0, 300);
      planContext.push(`FALLBACK MODE: ${fallbackReason} The rule-based plan is shown below.`);
    } finally {
      state.plannerBusy = false;
      renderPlannerControls();
    }
    if (requestId !== state.plannerRequestId || activeScope()?.id !== scope.id) {
      recordActivity('PLAN_RESULT_DISCARDED', `${scope.origin} · selected lab changed during the request; result was not attached to another lab.`);
      return;
    }
    if (evidenceVersion !== plannerEvidenceVersion(scope.id)) {
      if (state.lastPlan?.scopeId === scope.id) renderPlan(state.lastPlan);
      else $('#planResult').innerHTML = '<span class="empty-icon">✳</span><strong>Evidence changed during this request</strong><p>Ask the planner again to review the current evidence.</p>';
      recordActivity('PLAN_RESULT_DISCARDED', `${scope.origin} · evidence changed while the planner was responding`);
      return;
    }
    state.lastPlan = { id: makeId('PLAN'), scopeId: scope.id, target: scope.origin, request, createdAt: new Date().toISOString(), steps: plan, context: planContext, coverage, plannerMode, llmSuggestion, fallbackReason, provider, model, analysis, evidenceCount, evidenceSnapshot, evidenceVersion, totalFindings: scopeFindings.length };
    renderPlan(state.lastPlan);
    recordActivity('PLAN_CREATED', `${scope.origin} · ${plannerMode === 'groq' ? `Groq evidence review accepted · ${model} · ${evidenceCount} finding summaries shared with consent` : plannerMode === 'ollama' ? 'Local Ollama suggestion accepted' : `${provider} unavailable · rule fallback used`} · ${request}`);
  }

  function aiAnalysisMarkup(plan, forPrint = false) {
    if (plan.plannerMode !== 'groq' || !plan.analysis) return '';
    const { summary, observations, limitations } = plan.analysis;
    const snapshots = new Map((plan.evidenceSnapshot || []).map((item) => [item.id, item]));
    const observationRows = observations.map((item) => {
      const source = snapshots.get(item.finding_id);
      const title = source?.title || item.finding_id;
      const reference = `${item.finding_id} · ${title}`;
      return `<article class="ai-observation"><div class="ai-observation-reference">${forPrint
        ? `<b>${escapeHTML(reference)}</b>`
        : `<button type="button" class="text-button ai-source-link" data-ai-finding-id="${escapeHTML(item.finding_id)}">${escapeHTML(reference)} <span aria-hidden="true">↗</span></button>`}</div>${source?.asset ? `<p class="ai-asset">${escapeHTML(source.asset)}</p>` : ''}<p>${escapeHTML(item.explanation)}</p><p class="ai-next-review"><b>Next review:</b> ${escapeHTML(item.next_review)}</p></article>`;
    }).join('');
    return `<section class="ai-analysis" aria-label="Groq evidence analysis"><div class="ai-analysis-heading"><strong>Evidence review</strong><span class="status-tag import">AI INTERPRETATION</span></div><p class="ai-analysis-summary">${escapeHTML(summary)}</p><p class="ai-analysis-provenance">Provider: Groq cloud · Model: ${escapeHTML(plan.model || 'not recorded')} · ${Number(plan.evidenceCount) || 0} of ${Number(plan.totalFindings) || 0} finding group(s) shared with consent at ${escapeHTML(formatDate(plan.createdAt))}. Up to 3 source excerpts per finding were supplied; full files were not shared.</p>${observationRows || '<p>No finding-level interpretation was returned. The summary may identify missing evidence.</p>'}${limitations.length ? `<div class="ai-limitations"><b>Evidence gaps & limitations</b><ul>${limitations.map((line) => `<li>${escapeHTML(line)}</li>`).join('')}</ul></div>` : ''}<p class="ai-analysis-note">Verify each interpretation against source evidence. Source links identify the supplied findings. AI explanations and suggested review steps are not independent vulnerability validation.</p></section>`;
  }

  function openFindingReference(scopeId, findingId) {
    if (activeScope()?.id !== scopeId || !state.findings.some((item) => item.scopeId === scopeId && item.finding_id === findingId)) {
      return toast('This finding is no longer available in the selected lab.', true);
    }
    $('#severityFilter').value = 'all';
    $('#findingSearch').value = '';
    navigate('findings');
    const card = $$('.finding-card').find((node) => node.dataset.findingId === findingId);
    if (!card) return;
    const evidence = card.querySelector('.finding-evidence');
    if (evidence) evidence.open = true;
    card.tabIndex = -1;
    card.focus({ preventScroll: true });
    card.scrollIntoView({ behavior: 'smooth', block: 'start' });
    card.classList.add('ai-highlight');
    window.setTimeout(() => card.classList.remove('ai-highlight'), 2500);
  }

  function renderPlan(plan) {
    const root = $('#planResult');
    const scope = availableScopes().find((item) => item.id === plan.scopeId);
    root.className = 'plan-result';
    const usesAI = ['ollama', 'groq'].includes(plan.plannerMode) && plan.llmSuggestion;
    const plannerResult = usesAI
      ? `<div class="planner-answer${plan.plannerMode === 'groq' ? ' groq-answer' : ''}"><span class="status-tag live">${plan.plannerMode === 'groq' ? 'GROQ CLOUD' : 'LOCAL OLLAMA'}</span><strong>Suggested next step: ${escapeHTML(PLANNER_STEP_LABELS[plan.llmSuggestion.next_step] || 'Review existing evidence')}</strong><p>${escapeHTML(plan.llmSuggestion.reason)}</p><small>The suggestion was checked against this lab’s saved permissions. It does not start a scan.</small></div>`
      : `<div class="planner-answer fallback"><span class="status-tag planned">FALLBACK MODE</span><strong>Using the rule-based suggestion</strong><p>${escapeHTML(plan.coverage.next.title)} — ${escapeHTML(plan.coverage.next.reason)}</p><small>${escapeHTML(plan.fallbackReason || 'The selected AI provider is unavailable; no AI suggestion was used.')}</small></div>`;
    const plannerNote = plan.plannerMode === 'groq'
      ? 'Planner: Groq cloud evidence interpretation with checked finding references · No scan started'
      : plan.plannerMode === 'ollama'
        ? 'Planner: local Ollama JSON suggestion checked against saved permissions · No scan started'
        : `Planner: local rule fallback · ${plan.provider === 'groq' ? 'Groq' : 'Ollama'} unavailable or response invalid · No scan started`;
    root.innerHTML = `<div class="plan-card"><div class="plan-card-head"><div><h3>Planner response</h3><p class="plan-subtitle">${escapeHTML(plan.target)} · ${escapeHTML(formatDate(plan.createdAt))}</p></div><span class="status-tag import">NO SCAN STARTED</span></div>
      <p id="plannerStaleNotice" class="planner-stale" role="status" hidden>Earlier planner response. This lab’s imports or review statuses have changed. See Live next step or ask the planner again.</p>
      ${plannerResult}${aiAnalysisMarkup(plan)}
      ${plan.steps.map((step, index) => `<div class="plan-step"><span class="plan-index">${String(index + 1).padStart(2, '0')}</span><div><strong>${escapeHTML(step.title)}</strong><p>${escapeHTML(step.reason)}</p></div><span class="status-tag ${step.status === 'LOCKED' ? 'planned' : ''}">${escapeHTML(step.status)}</span></div>`).join('')}
      ${plan.context.map((line) => `<div class="plan-context">${escapeHTML(line)}</div>`).join('')}
      <p class="plan-note">${escapeHTML(plannerNote)}</p>
      <div class="plan-actions"><button class="secondary-button" id="planImportButton" ${scope?.permissions.includes('Scanner result import') ? '' : 'disabled'}>Import approved results</button><button class="text-button" id="planReportButton" ${state.findings.some((item) => item.scopeId === plan.scopeId) ? '' : 'disabled'}>View findings →</button></div>
      </div>`;
    $('#planImportButton')?.addEventListener('click', () => openImport(plan.scopeId));
    $('#planReportButton')?.addEventListener('click', () => navigate('findings'));
    $$('[data-ai-finding-id]', root).forEach((button) => button.addEventListener('click', () => openFindingReference(plan.scopeId, button.dataset.aiFindingId)));
    updatePlannerFreshness();
  }

  function openImport(scopeId) {
    const scope = availableScopes().find((item) => item.id === scopeId) || activeScope();
    if (!scope) return toast('Select an authorized lab first.', true);
    const check = checkScope(scope.origin, scope, ['Scanner result import']);
    if (!check.allowed) return toast(check.reason, true);
    state.importScopeId = scope.id;
    state.fileAction = 'import';
    $('#fileInput').value = '';
    $('#fileInput').click();
  }

  function saveImportRun(run) {
    state.imports.unshift(run);
    state.imports = state.imports.slice(0, 100);
    saveStore(KEYS.imports, state.imports);
  }

  function renderImportHistory() {
    const scope = activeScope();
    const panel = $('#importHistoryPanel');
    const root = $('#importHistoryList');
    const entries = state.imports
      .filter((run) => run.scopeId === scope?.id)
      .flatMap((run) => run.files.map((file) => ({ ...file, checkedAt: run.startedAt })))
      .slice(0, 12);
    panel.hidden = !entries.length;
    if (!entries.length) return;
    const labels = {
      imported: ['IMPORTED', 'accepted'],
      partial: ['PARTIAL', 'warning'],
      no_observations: ['NO OBSERVATIONS', 'neutral'],
      out_of_scope: ['OUT OF SCOPE', 'warning'],
      blocked: ['BLOCKED', 'error'],
      failed: ['FAILED', 'error'],
    };
    root.innerHTML = entries.map((entry) => {
      const [label, tone] = labels[entry.outcome] || ['REVIEWED', 'neutral'];
      const counts = `${entry.acceptedRecords || 0} accepted · ${entry.excludedRecords || 0} excluded`;
      const details = entry.message || counts;
      return `<article class="import-history-item"><div class="import-history-main"><strong>${escapeHTML(entry.fileName)}</strong><span>${escapeHTML(entry.tool || 'Tool not identified')} · ${escapeHTML(counts)}</span><small>${escapeHTML(details)}</small></div><div class="import-history-meta"><span class="import-state ${tone}">${label}</span><time>${escapeHTML(formatDate(entry.checkedAt))}</time></div></article>`;
    }).join('');
  }

  function parseXML(text) {
    const xml = new DOMParser().parseFromString(text, 'application/xml');
    if (xml.querySelector('parsererror')) throw new Error('The XML file could not be parsed.');
    return xml;
  }

  function allByLocalName(node, name) {
    return Array.from(node.getElementsByTagName('*')).filter((item) => item.localName?.toLowerCase() === name.toLowerCase());
  }

  function firstText(node, names, fallback = '') {
    for (const name of names) {
      const found = allByLocalName(node, name)[0];
      if (found && found.textContent.trim()) return found.textContent.trim();
    }
    return fallback;
  }

  function childText(node, name, fallback = '') {
    const found = Array.from(node.children || []).find((item) => item.localName?.toLowerCase() === name.toLowerCase());
    return found?.textContent?.trim() || fallback;
  }

  function csvCves(text) {
    return [...new Set(String(text || '').match(/CVE-\d{4}-\d{4,}/gi) || [])].map((item) => item.toUpperCase());
  }

  function baseFinding({ tool, title, asset, severity = 'Unknown', cvss = null, cve = [], cwe = '', description = '', evidence = '', confidence = 'Unknown', recommendation = '', reference = '', timestamp = '', validation = 'Scanner-reported; unvalidated' }) {
    const numericCvss = cvss === null || cvss === '' || !Number.isFinite(Number(cvss)) ? null : Number(cvss);
    const parsedSeverity = capitalizeSeverity(severity);
    return {
      source_tool: tool,
      title: String(title || 'Untitled finding').trim(),
      affected_asset: String(asset || 'Unknown asset').trim(),
      severity: parsedSeverity,
      cvss: numericCvss,
      cve: Array.isArray(cve) ? cve : csvCves(cve),
      cwe: String(cwe || '').trim(),
      description: String(description || '').trim(),
      supporting_evidence: String(evidence || '').trim(),
      confidence: String(confidence || 'Unknown').trim(),
      recommendation: String(recommendation || '').trim(),
      raw_reference: String(reference || ''),
      timestamp: timestamp || new Date().toISOString(),
      timestamp_basis: timestamp ? 'Scanner timestamp when present' : 'Import time; file metadata is applied after parsing',
      validation_status: validation,
    };
  }

  function capitalizeSeverity(value) {
    const text = String(value || 'Unknown').trim().toLowerCase();
    const lookup = { critical: 'Critical', high: 'High', medium: 'Medium', moderate: 'Medium', low: 'Low', info: 'Info', informational: 'Info', none: 'Info', 0: 'Info', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical' };
    return lookup[text] || 'Unknown';
  }

  function scanTimestamp(file, value = '') {
    if (value && /^\d{10,13}$/.test(String(value))) {
      const number = Number(value);
      return new Date(String(value).length === 13 ? number : number * 1000).toISOString();
    }
    return new Date(file.lastModified || Date.now()).toISOString();
  }

  function parseNmap(xml, file) {
    const findings = [];
    const root = xml.documentElement;
    const timestamp = scanTimestamp(file, root.getAttribute('start') || '');
    allByLocalName(root, 'host').forEach((host, hostIndex) => {
      const hostname = allByLocalName(host, 'hostname').map((item) => item.getAttribute('name')).find(Boolean);
      const address = allByLocalName(host, 'address').map((item) => item.getAttribute('addr')).find(Boolean);
      const hostName = hostname || address || 'Unknown host';
      allByLocalName(host, 'port').forEach((port, portIndex) => {
        const state = allByLocalName(port, 'state')[0];
        if (state?.getAttribute('state') !== 'open') return;
        const service = allByLocalName(port, 'service')[0];
        const serviceName = service?.getAttribute('name') || 'unknown service';
        const number = port.getAttribute('portid') || 'unknown';
        const protocol = port.getAttribute('protocol') || 'tcp';
        const banner = [service?.getAttribute('product'), service?.getAttribute('version')].filter(Boolean).join(' ');
        findings.push(baseFinding({
          tool: 'Nmap', title: `Open ${serviceName} service (${protocol}/${number})`,
          asset: `${hostName}:${number}/${protocol}`, severity: 'Info',
          description: 'Observed open service. This observation alone does not establish a vulnerability.',
          evidence: `Nmap reports ${protocol}/${number} open; service=${serviceName}${banner ? `; banner=${banner}` : ''}${address ? `; address=${address}` : ''}`,
          confidence: 'Unknown', reference: `host[${hostIndex + 1}]/port[${portIndex + 1}]`, timestamp,
          validation: 'Observed by scanner; not vulnerability-validated',
        }));
      });
    });
    return findings;
  }

  function parseNessus(xml, file) {
    const findings = [];
    allByLocalName(xml, 'ReportHost').forEach((host, hostIndex) => {
      const properties = allByLocalName(host, 'tag');
      const hostName = properties.find((item) => ['host-fqdn', 'host-ip'].includes(item.getAttribute('name')))?.textContent?.trim() || host.getAttribute('name') || 'Unknown host';
      allByLocalName(host, 'ReportItem').forEach((issue, issueIndex) => {
        const severity = capitalizeSeverity(issue.getAttribute('severity'));
        const port = issue.getAttribute('port');
        const protocol = issue.getAttribute('protocol') || 'tcp';
        const asset = port && port !== '0' ? `${hostName}:${port}/${protocol}` : hostName;
        const cve = allByLocalName(issue, 'cve').map((item) => item.textContent.trim()).filter(Boolean);
        findings.push(baseFinding({
          tool: 'Nessus', title: issue.getAttribute('pluginName') || 'Nessus finding', asset, severity,
          cvss: childText(issue, 'cvss3_base_score') || childText(issue, 'cvss_base_score'), cve,
          cwe: childText(issue, 'cwe'), description: childText(issue, 'description') || childText(issue, 'synopsis'),
          evidence: childText(issue, 'plugin_output') || childText(issue, 'synopsis'),
          reference: `ReportHost[${hostIndex + 1}]/ReportItem[${issueIndex + 1}]`, timestamp: scanTimestamp(file),
          recommendation: childText(issue, 'solution'),
        }));
      });
    });
    return findings;
  }

  function parseGreenbone(xml, file) {
    return allByLocalName(xml, 'result').map((result, index) => {
      const nvt = allByLocalName(result, 'nvt')[0];
      const host = childText(result, 'host', 'Unknown host');
      const portText = childText(result, 'port');
      const portNumber = portText.match(/\d+/)?.[0];
      const asset = portNumber ? `${host}:${portNumber}` : host;
      const cve = csvCves(childText(nvt || result, 'cve'));
      return baseFinding({
        tool: 'OpenVAS / Greenbone', title: childText(nvt || result, 'name', 'Greenbone finding'), asset,
        severity: childText(result, 'threat') || childText(nvt || result, 'severity') || 'Unknown',
        cvss: childText(nvt || result, 'cvss_base'), cve, cwe: childText(nvt || result, 'cwe'),
        description: childText(nvt || result, 'summary'), evidence: childText(result, 'description') || childText(result, 'specific_result'),
        reference: `result[${index + 1}]`, timestamp: scanTimestamp(file),
        recommendation: childText(nvt || result, 'solution'),
      });
    });
  }

  function parseNikto(xml, file, scope) {
    const findings = [];
    const scanDetails = allByLocalName(xml, 'scandetails')[0];
    const host = scanDetails?.getAttribute('targethostname') || scanDetails?.getAttribute('targetip') || new URL(scope.origin).hostname;
    const port = scanDetails?.getAttribute('targetport');
    const rootAsset = port ? `${host}:${port}` : host;
    allByLocalName(xml, 'item').forEach((item, index) => {
      const uri = childText(item, 'uri') || item.getAttribute('uri') || '';
      let asset = rootAsset;
      if (uri) {
        try { asset = new URL(uri, scope.origin).href; } catch (_) { /* retain the parsed host and port */ }
      }
      findings.push(baseFinding({
        tool: 'Nikto', title: childText(item, 'description') || item.getAttribute('id') || 'Nikto observation', asset,
        severity: childText(item, 'severity') || 'Unknown',
        description: childText(item, 'description'), evidence: childText(item, 'description'),
        reference: `item[${index + 1}]${item.getAttribute('id') ? ` · ${item.getAttribute('id')}` : ''}`,
        timestamp: scanTimestamp(file), validation: 'Scanner observation; analyst validation required',
      }));
    });
    return findings;
  }

  function parseZap(data, file) {
    const sites = Array.isArray(data?.site) ? data.site : [];
    const findings = [];
    sites.forEach((site, siteIndex) => {
      (Array.isArray(site.alerts) ? site.alerts : []).forEach((alert, alertIndex) => {
        const instances = Array.isArray(alert.instances) && alert.instances.length ? alert.instances : [{}];
        instances.forEach((instance, instanceIndex) => {
          findings.push(baseFinding({
            tool: 'OWASP ZAP', title: alert.name || alert.alert || 'ZAP alert',
            asset: instance.uri || site['@name'] || 'Unknown asset',
            severity: String(alert.riskdesc || alert.risk || 'Unknown').split(/\s+/)[0],
            cwe: alert.cweid || '', description: alert.desc || alert.description || '',
            evidence: [instance.evidence, instance.method && `method=${instance.method}`, instance.param && `parameter=${instance.param}`].filter(Boolean).join(' · '),
            confidence: alert.confidence || 'Unknown', recommendation: alert.solution || '',
            reference: `site[${siteIndex + 1}]/alert[${alertIndex + 1}]/instance[${instanceIndex + 1}]`, timestamp: scanTimestamp(file),
          }));
        });
      });
    });
    return findings;
  }

  function parseBurp(xml, file, scope) {
    return allByLocalName(xml, 'issue').map((issue, index) => {
      const hostNode = allByLocalName(issue, 'host')[0];
      const hostText = hostNode?.textContent?.trim() || '';
      const path = childText(issue, 'path');
      let asset = hostText || scope.origin;
      if (hostNode?.getAttribute('ip') && !hostText) asset = hostNode.getAttribute('ip');
      if (path) {
        try { asset = new URL(path, asset.includes('://') ? asset : scope.origin).href; } catch (_) { /* keep parsed host */ }
      }
      return baseFinding({
        tool: 'Burp Suite', title: childText(issue, 'name') || 'Burp issue', asset,
        severity: childText(issue, 'severity'),
        description: childText(issue, 'issueDetail') || childText(issue, 'issueBackground'),
        evidence: childText(issue, 'issueDetail') || childText(issue, 'confidence'),
        confidence: childText(issue, 'confidence') || 'Unknown',
        recommendation: childText(issue, 'remediationBackground') || childText(issue, 'remediationDetail'),
        reference: `issue[${index + 1}]${childText(issue, 'type') ? ` · ${childText(issue, 'type')}` : ''}`,
        timestamp: scanTimestamp(file),
      });
    });
  }

  async function parseScannerFile(file, scope) {
    const text = await file.text();
    const extension = file.name.split('.').pop().toLowerCase();
    if (extension === 'json') return { tool: 'OWASP ZAP', findings: parseZap(JSON.parse(text), file) };
    if (!['xml', 'nessus'].includes(extension)) throw new Error(`Unsupported file type: ${file.name}`);
    const xml = parseXML(text);
    const rootName = xml.documentElement.localName.toLowerCase();
    if (rootName === 'nmaprun') return { tool: 'Nmap', findings: parseNmap(xml, file) };
    if (allByLocalName(xml, 'ReportHost').length) return { tool: 'Nessus', findings: parseNessus(xml, file) };
    if (rootName.includes('nikto') || allByLocalName(xml, 'scandetails').length) return { tool: 'Nikto', findings: parseNikto(xml, file, scope) };
    if (allByLocalName(xml, 'issue').length && rootName !== 'result') return { tool: 'Burp Suite', findings: parseBurp(xml, file, scope) };
    if (allByLocalName(xml, 'result').length) return { tool: 'OpenVAS / Greenbone', findings: parseGreenbone(xml, file) };
    throw new Error('This XML does not match a supported scanner export.');
  }

  function normalizeHost(host) {
    return String(host || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  }

  function hostFromAsset(asset) {
    const value = String(asset || '').trim();
    if (!value) return null;
    if (/^https?:\/\//i.test(value)) {
      try { return normalizeHost(new URL(value).hostname); } catch (_) { return null; }
    }
    const hostPort = value.split('/')[0];
    if (hostPort.startsWith('[') && hostPort.includes(']')) return normalizeHost(hostPort.slice(1, hostPort.indexOf(']')));
    return normalizeHost(hostPort.includes(':') ? hostPort.slice(0, hostPort.lastIndexOf(':')) : hostPort);
  }

  function findingInScope(finding, scope) {
    const target = String(finding.affected_asset || '').trim();
    if (!target || hostFromAsset(target) !== normalizeHost(new URL(scope.origin).hostname)) return false;
    if (/^https?:\/\//i.test(target)) {
      let url;
      try { url = new URL(target); } catch (_) { return false; }
      if (url.origin.toLowerCase() !== scope.origin.toLowerCase() || pathExcluded(url.pathname, scope.exclusions)) return false;
      return true;
    }
    const portMatch = target.match(/:(\d+)(?:\/(?:tcp|udp))?$/i);
    if (portMatch && !scope.permissions.includes('Network diagnostics')) return false;
    return true;
  }

  function canonicalAsset(asset) {
    const value = String(asset || '').trim();
    if (/^https?:\/\//i.test(value)) {
      try {
        const url = new URL(value);
        url.hash = '';
        url.pathname = url.pathname.replace(/\/+$/, '') || '/';
        return url.href.replace(/\/$/, '');
      } catch (_) { return value.toLowerCase(); }
    }
    return value.replace(/\s+/g, '').toLowerCase().replace(/\/$/, '');
  }

  function normalizedTitle(title) {
    return String(title || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
  }

  function findingKey(finding) {
    return `${canonicalAsset(finding.affected_asset)}|${normalizedTitle(finding.title)}`;
  }

  function makeFindingId(key) {
    let hash = 0x811c9dc5;
    for (let i = 0; i < key.length; i += 1) {
      hash ^= key.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193);
    }
    return `F-${(hash >>> 0).toString(16).toUpperCase().padStart(8, '0')}`;
  }

  function evidenceRecord(finding) {
    return {
      source_tool: finding.source_tool,
      reported_title: finding.title,
      affected_asset: finding.affected_asset,
      source_severity: finding.severity,
      source_cvss: finding.cvss,
      source_cve: finding.cve,
      source_cwe: finding.cwe,
      source_description: finding.description,
      timestamp: finding.timestamp,
      timestamp_basis: finding.timestamp_basis,
      raw_reference: finding.raw_reference,
      source_file: finding.source_file || '',
      supporting_evidence: finding.supporting_evidence,
      confidence: finding.confidence,
      validation_status: finding.validation_status,
      recommendation: finding.recommendation,
    };
  }

  function correlate(imported, scope) {
    const groups = new Map();
    for (const raw of imported) {
      const finding = { ...raw, scopeId: scope.id };
      const key = findingKey(finding);
      const record = evidenceRecord(finding);
      if (!groups.has(key)) {
        groups.set(key, {
          ...finding,
          finding_id: makeFindingId(key),
          sources: [finding.source_tool],
          evidence_records: [record],
        });
        continue;
      }
      const item = groups.get(key);
      if (item.evidence_records.some((existing) => JSON.stringify(existing) === JSON.stringify(record))) continue;
      if (!item.sources.includes(finding.source_tool)) item.sources.push(finding.source_tool);
      item.evidence_records.push(record);
      if ((SEVERITY_ORDER[finding.severity] || 0) > (SEVERITY_ORDER[item.severity] || 0)) item.severity = finding.severity;
      if (item.cvss === null && finding.cvss !== null) item.cvss = finding.cvss;
      if (finding.cve.length) item.cve = [...new Set([...(item.cve || []), ...finding.cve])].sort();
      if (!item.cwe && finding.cwe) item.cwe = finding.cwe;
      if (!item.recommendation && finding.recommendation) item.recommendation = finding.recommendation;
      const confidences = [...new Set(item.evidence_records.map((record) => String(record.confidence || 'Unknown')))]
        .filter((value) => value.toLowerCase() !== 'unknown');
      item.confidence = confidences.length === 1 ? confidences[0] : confidences.length ? 'Mixed' : 'Unknown';
      if (!item.supporting_evidence && finding.supporting_evidence) item.supporting_evidence = finding.supporting_evidence;
    }
    return [...groups.values()].sort((a, b) =>
      (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0)
      || a.affected_asset.localeCompare(b.affected_asset)
      || a.title.localeCompare(b.title)
    );
  }

  async function importFiles(event) {
    const files = Array.from(event.target.files || []);
    const scope = availableScopes().find((item) => item.id === state.importScopeId);
    event.target.value = '';
    if (!files.length || !scope) return;
    const check = checkScope(scope.origin, scope, ['Scanner result import']);
    if (!check.allowed) return toast(check.reason, true);
    const all = [];
    const run = { id: makeId('IMP'), scopeId: scope.id, startedAt: new Date().toISOString(), files: [] };
    let excluded = 0;
    for (const file of files) {
      try {
        const parsed = await parseScannerFile(file, scope);
        const toolAction = ['Nmap', 'Nessus', 'OpenVAS / Greenbone'].includes(parsed.tool)
          ? 'Network diagnostics' : 'Web checks';
        const toolCheck = checkScope(scope.origin, scope, ['Scanner result import', toolAction]);
        if (!toolCheck.allowed) {
          excluded += parsed.findings.length;
          run.files.push({ fileName: file.name, tool: parsed.tool, outcome: 'blocked', acceptedRecords: 0, excludedRecords: parsed.findings.length, message: toolCheck.reason });
          continue;
        }
        parsed.findings.forEach((finding) => {
          finding.source_file = file.name;
          if (!finding.timestamp || finding.timestamp_basis === 'Import time; file metadata is applied after parsing') {
            const modifiedAt = Number(file.lastModified);
            if (Number.isFinite(modifiedAt) && modifiedAt > 0) {
              finding.timestamp = new Date(modifiedAt).toISOString();
              finding.timestamp_basis = 'File modification time; scanner timestamp unavailable';
            } else {
              finding.timestamp = new Date().toISOString();
              finding.timestamp_basis = 'Import time; file modification time unavailable';
            }
          }
        });
        const matched = parsed.findings.filter((finding) => findingInScope(finding, scope));
        const fileExcluded = parsed.findings.length - matched.length;
        excluded += fileExcluded;
        all.push(...matched);
        const outcome = matched.length
          ? (fileExcluded ? 'partial' : 'imported')
          : (parsed.findings.length ? 'out_of_scope' : 'no_observations');
        run.files.push({
          fileName: file.name,
          tool: parsed.tool,
          outcome,
          acceptedRecords: matched.length,
          excludedRecords: fileExcluded,
          message: parsed.findings.length === 0 ? 'File format recognized; no reportable observations were present.' : '',
        });
      } catch (error) {
        const fileType = file.name.split('.').pop().toLowerCase();
        const recovery = fileType === 'xml' || fileType === 'nessus'
          ? 'Recovery: re-export valid XML from the source scanner, then import again.'
          : fileType === 'json'
            ? 'Recovery: export a valid ZAP JSON report, then import again.'
            : 'Recovery: choose a supported .xml, .nessus, or .json report.';
        run.files.push({ fileName: file.name, tool: '', outcome: 'failed', acceptedRecords: 0, excludedRecords: 0, message: `${String(error.message || 'Could not read this file.').slice(0, 260)} ${recovery}` });
      }
    }
    if (!availableScopes().some((item) => item.id === scope.id)) return toast('This scope moved to Trash before the import completed.', true);
    saveImportRun(run);
    if (!all.length) {
      const failed = run.files.filter((item) => item.outcome === 'failed').length;
      const outOfScope = run.files.some((item) => ['out_of_scope', 'blocked'].includes(item.outcome));
      recordActivity('IMPORT_REVIEWED', `${scope.origin} · ${files.length} file(s) reviewed · no in-scope records · ${excluded} excluded · ${failed} failed`);
      renderAll();
      navigate('findings');
      return toast(
        failed || outOfScope
          ? `${files.length} file(s) reviewed; no in-scope records imported. Findings shows the reason and a recovery step.`
          : `${files.length} file(s) reviewed; no findings were reported for this lab. An empty result does not prove it is safe.`,
        Boolean(failed || outOfScope)
      );
    }
    const existing = state.findings.filter((item) => item.scopeId === scope.id);
    const merged = correlate([...existing.flatMap((item) => item.evidence_records.map((record) => ({
      source_tool: record.source_tool,
      title: record.reported_title || item.title,
      affected_asset: record.affected_asset || item.affected_asset,
      severity: record.source_severity || 'Unknown',
      cvss: record.source_cvss ?? null,
      cve: record.source_cve || [], cwe: record.source_cwe || '',
      description: record.source_description || item.description || '', supporting_evidence: record.supporting_evidence || '',
      confidence: record.confidence || 'Unknown', recommendation: record.recommendation || '',
      raw_reference: record.raw_reference || '', source_file: record.source_file || '', timestamp: record.timestamp || '',
      timestamp_basis: record.timestamp_basis || 'Unknown', validation_status: record.validation_status || 'Scanner-reported; unvalidated',
    }))), ...all], scope);
    const otherScopes = state.findings.filter((item) => item.scopeId !== scope.id);
    state.findings = [...otherScopes, ...merged];
    saveStore(KEYS.findings, state.findings);
    const failed = run.files.filter((item) => item.outcome === 'failed').length;
    recordActivity('RESULTS_IMPORTED', `${scope.origin} · ${all.length} in-scope source records · ${run.files.map((item) => item.tool).filter(Boolean).join(', ')} · ${excluded} out-of-scope records excluded · ${failed} failed`);
    renderAll();
    toast(`Imported ${all.length} in-scope record(s); ${excluded} excluded; ${failed} file(s) failed. Findings shows any recovery steps.`);
    navigate('findings');
  }

  function setZapScanStatus(message, tone = '') {
    const status = $('#zapScanStatus');
    status.textContent = message;
    status.className = `zap-scan-status${tone ? ` ${tone}` : ''}`;
  }

  function zapRecoveryHint(message) {
    const text = String(message || '').toLowerCase();
    if (text.includes('zap_api_key')) return 'Reopen the app with Start ScopeWeave.cmd to connect to local ZAP.';
    if (text.includes('could not reach zap') || text.includes('127.0.0.1:8080')) return 'Give ZAP a minute to start, then retry. If it is still unavailable, reopen Start ScopeWeave.cmd.';
    if (text.includes('timeout') || text.includes('time limit')) return 'Check that the approved lab is reachable and try the bounded crawl again when allowed.';
    return 'Check the local ZAP setup and the saved lab permissions, then retry only if your recorded authorization allows it.';
  }

  async function fetchZapJSON(url, options) {
    const response = await fetch(url, options);
    let payload;
    try { payload = await response.json(); } catch (_) { throw new Error('The local scan service returned an unreadable response.'); }
    if (!response.ok) throw new Error(payload.error || 'The local scan service could not start the scan.');
    return payload;
  }

  async function scanWithZap() {
    const scope = activeScope();
    if (!scope) return toast('Register your own local lab or an organizer-approved scope first.', true);
    const scopeCheck = checkScope(scope.origin, scope, ['Web checks', 'Scanner result import']);
    if (!scopeCheck.allowed) return toast(scopeCheck.reason, true);
    const confirmed = window.confirm(
      `Start a ZAP Spider crawl and passive checks for ${scope.origin}?\n\n` +
      'This sends normal web requests to the approved lab. The run follows saved exclusions and does not use active attack rules. Continue only if you control this local lab or this activity is explicitly allowed by its organizer.'
    );
    if (!confirmed) return;

    state.zapBusy = true;
    renderScopeOptions();
    setZapScanStatus(`Connecting to local ZAP for ${scope.origin}…`, 'running');
    try {
      const started = await fetchZapJSON('/api/zap/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scope }),
      });
      if (!started.jobId) throw new Error('The local scan service did not return a job ID.');
      recordActivity('ZAP_SCAN_STARTED', `${scope.origin} · scoped Spider + passive checks`);
      while (true) {
        await new Promise((resolve) => window.setTimeout(resolve, 1200));
        const job = await fetchZapJSON(`/api/zap/jobs/${encodeURIComponent(started.jobId)}`);
        if (job.state === 'failed') throw new Error(job.error || 'The ZAP scan could not finish.');
        if (job.state === 'completed') {
          if (!job.report || !Array.isArray(job.report.site)) throw new Error('ZAP completed without a readable report.');
          if (!availableScopes().some((item) => item.id === scope.id)) {
            setZapScanStatus('The scan finished while its scope was in Trash. Restore the scope to use it again.', 'error');
            return;
          }
          state.importScopeId = scope.id;
          state.activeScopeId = scope.id;
          $('#targetSelect').value = scope.id;
          const fileName = `zap-live-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
          const reportFile = new File([JSON.stringify(job.report)], fileName, { type: 'application/json' });
          await importFiles({ target: { files: [reportFile], value: '' } });
          recordActivity('ZAP_SCAN_COMPLETED', `${scope.origin} · ${job.alertCount || 0} ZAP alert(s) returned${job.partial ? ' · partial coverage' : ''}`);
          setZapScanStatus(
            `ZAP crawl finished. ${job.alertCount || 0} alert(s) were passed through the existing scope filter and finding importer.${job.partial ? ' Some alerts may be missing from these results.' : ''}`,
            'complete'
          );
          return;
        }
        setZapScanStatus(`${job.phase || 'ZAP scan in progress'}${Number.isFinite(job.progress) ? ` · ${job.progress}%` : ''}`, 'running');
      }
    } catch (error) {
      const message = error.message || 'The ZAP scan failed.';
      const recovery = zapRecoveryHint(message);
      recordActivity('ZAP_SCAN_FAILED', `${scope.origin} · ${message} · ${recovery}`);
      setZapScanStatus(`Scan stopped: ${message}\nRecovery: ${recovery}`, 'error');
      toast(`ZAP could not finish. ${recovery}`, true);
    } finally {
      state.zapBusy = false;
      renderScopeOptions();
    }
  }

  function contextForFinding(finding) {
    return state.riskContexts.find((item) => item.scopeId === finding.scopeId && item.finding_id === finding.finding_id)
      || { scopeId: finding.scopeId, finding_id: finding.finding_id, exposure: 'unknown', impact: 'unknown', exploitability: 'unknown', exposureScore: '', exploitabilityScore: '', impactScore: '', note: '' };
  }

  function weightedRiskScore(finding, context = contextForFinding(finding)) {
    const cvssValues = (finding.evidence_records || [])
      .map((record) => record.source_cvss)
      .filter((value) => value !== null && value !== undefined && value !== '')
      .map(Number)
      .filter((value) => Number.isFinite(value) && value >= 0 && value <= 10);
    const readRating = (value) => value !== '' && value !== null && value !== undefined
      && Number.isFinite(Number(value)) && Number(value) >= 0 && Number(value) <= 10 ? Number(value) : null;
    const parts = {
      cvss: cvssValues.length ? Math.max(...cvssValues) : null,
      exposure: readRating(context.exposureScore),
      exploitability: readRating(context.exploitabilityScore),
      assetImpact: readRating(context.impactScore),
    };
    const complete = Object.values(parts).every((value) => value !== null);
    const score = complete
      ? parts.cvss * 0.4 + parts.exposure * 0.2 + parts.exploitability * 0.2 + parts.assetImpact * 0.2
      : null;
    return { parts, score: score === null ? null : Math.round(score * 10) / 10 };
  }

  function reviewAssessment(finding, context = contextForFinding(finding)) {
    const hasExploitEvidence = context.exploitability === 'evidence';
    const hasExternalExposure = context.exposure === 'external';
    const hasHighImpact = context.impact === 'high';
    const hasContextSignal = hasExploitEvidence || hasExternalExposure || hasHighImpact;
    const severity = finding.severity || 'Unknown';
    let label = 'Needs context';
    let rank = 0;
    let basis = 'Source severity and analyst context are insufficient for a review tier.';
    if (severity === 'Critical' || hasExploitEvidence || (hasExternalExposure && hasHighImpact)) {
      label = 'Review now';
      rank = 5;
      basis = severity === 'Critical' ? 'A source reported Critical severity.'
        : hasExploitEvidence ? 'The analyst cited source evidence about exploitability.'
          : 'The analyst marked both external exposure and high asset impact.';
    } else if (severity === 'Unknown') {
      if (hasContextSignal) {
        label = 'Context review';
        rank = 4;
        basis = 'Scanner severity is unknown; an analyst-entered risk factor needs review.';
      }
    } else if (severity === 'High' || hasContextSignal) {
      label = 'High review';
      rank = 4;
      basis = severity === 'High' ? 'A source reported High severity.' : 'An analyst-entered context factor raised review priority.';
    } else if (severity === 'Medium') {
      label = 'Moderate review';
      rank = 3;
      basis = 'A source reported Medium severity.';
    } else if (['Low', 'Info'].includes(severity)) {
      label = 'Routine review';
      rank = 2;
      basis = `A source reported ${severity} severity.`;
    }
    const needsEvidenceReview = finding.evidence_records.some((record) => {
      const confidence = String(record.confidence || 'Unknown').trim().toLowerCase();
      return !confidence || ['unknown', 'low', 'mixed'].includes(confidence);
    });
    const cvssValues = finding.evidence_records
      .map((record) => record.source_cvss)
      .filter((value) => value !== null && value !== undefined && Number.isFinite(Number(value)))
      .map(Number);
    return { label, rank, basis, needsEvidenceReview, cvssTieBreak: cvssValues.length ? Math.max(...cvssValues) : -1 };
  }

  function compareReviewPriority(a, b) {
    const first = reviewAssessment(a);
    const second = reviewAssessment(b);
    return second.rank - first.rank
      || (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0)
      || Number(second.needsEvidenceReview) - Number(first.needsEvidenceReview)
      || second.cvssTieBreak - first.cvssTieBreak
      || a.title.localeCompare(b.title);
  }

  function sourceAgreement(finding) {
    const distinctSources = new Map();
    for (const record of finding.evidence_records || []) {
      const source = String(record.source_tool || '').trim();
      const key = source.toLocaleLowerCase();
      if (key && !distinctSources.has(key)) distinctSources.set(key, source);
    }
    const sources = [...distinctSources.values()].sort((a, b) => a.localeCompare(b));
    const count = sources.length;
    return {
      sources,
      count,
      level: count >= 2 ? 'Medium' : count === 1 ? 'Low' : 'Unknown',
      label: count >= 2 ? `${count} tools · Medium agreement`
        : count === 1 ? '1 tool · Low agreement' : 'No source agreement data',
    };
  }

  function sourceInstructionWarnings(record) {
    return [
      ['Reported title', record.reported_title],
      ['Affected asset', record.affected_asset],
      ['Source description', record.source_description],
      ['Supporting evidence', record.supporting_evidence],
      ['Recommendation', record.recommendation],
    ].map(([label, value]) => ({ label, excerpt: instructionLikeExcerpt(value) })).filter(({ excerpt }) => excerpt);
  }

  function evidenceTraceMarkup(record, warnings = sourceInstructionWarnings(record)) {
    const description = String(record.source_description || '');
    const excerpt = record.supporting_evidence || description || 'The export did not include a source excerpt.';
    const timestamp = record.timestamp ? formatDate(record.timestamp) : 'Timestamp not supplied';
    const timeBasis = record.timestamp_basis || 'Timestamp basis not recorded';
    const sourceFile = record.source_file || 'Source filename unavailable';
    const reference = record.raw_reference || 'Structured source reference unavailable';
    return `<article class="source-row">
      <div class="source-row-heading"><strong>${escapeHTML(record.source_tool || 'Unknown scanner')}</strong><span class="observed-tag">OBSERVED IN IMPORTED REPORT</span></div>
      <div class="source-row-meta">File: ${escapeHTML(sourceFile)} · Time: ${escapeHTML(timestamp)} · ${escapeHTML(timeBasis)}</div>
      <div class="source-row-meta">Report reference: ${escapeHTML(reference)} · Line number: not captured by this importer</div>
      <div class="source-row-meta">Reported ${escapeHTML(record.source_severity || 'Unknown')} · CVSS ${record.source_cvss !== null && record.source_cvss !== undefined ? escapeHTML(record.source_cvss) : 'not supplied'} · confidence ${escapeHTML(record.confidence || 'Unknown')} · ${escapeHTML(record.validation_status || 'Scanner-reported; unvalidated')}</div>
      ${description && description !== excerpt ? `<div class="source-snippet"><b>Scanner description</b><pre>${escapeHTML(description.slice(0, 1200))}</pre></div>` : ''}
      <div class="source-snippet"><b>Parsed evidence text</b><pre>${escapeHTML(String(excerpt).slice(0, 1200))}</pre></div>
      ${warnings.map(({ label, excerpt }) => `<div class="source-snippet instruction-warning"><b>Possible AI instruction · ${escapeHTML(label)}</b><pre>${escapeHTML(excerpt)}</pre></div>`).join('')}
    </article>`;
  }

  function groupReportEvidence(records, compact) {
    const groups = new Map();
    for (const record of records) {
      const observation = compact ? JSON.stringify([
        record.source_tool, record.reported_title, record.affected_asset, record.source_severity,
        record.source_cvss, record.source_cve, record.source_cwe, record.source_description,
        record.supporting_evidence, record.confidence, record.validation_status, record.recommendation,
      ]) : Symbol();
      const provenance = [record.source_file, record.raw_reference, record.timestamp, record.timestamp_basis];
      const group = groups.get(observation) || { record, provenance: new Map(), count: 0 };
      group.count += 1;
      group.provenance.set(JSON.stringify(provenance), provenance);
      groups.set(observation, group);
    }
    return [...groups.values()];
  }

  function reportEvidenceMarkup(groups) {
    return groups.map(({ record, provenance, count }) => {
      const excerpt = record.supporting_evidence || record.source_description || 'No parsed evidence text supplied.';
      const references = [...provenance.values()].map(([file, reference, timestamp, basis]) =>
        `<li>File ${escapeHTML(file || 'not supplied')} · Report reference ${escapeHTML(reference || 'not available')} · Time ${escapeHTML(timestamp ? formatDate(timestamp) : 'not supplied')} · ${escapeHTML(basis || 'timestamp basis not recorded')}</li>`
      ).join('');
      return `<div class="trace">
        <b>${escapeHTML(record.source_tool || 'Unknown scanner')} · OBSERVED IN IMPORTED REPORT</b><br>
        ${escapeHTML(record.reported_title || 'Source title not supplied')}<br>
        ${count > 1 ? `<b class="repeated-evidence">Repeated evidence</b> · ${count} matching records shown in one evidence block.<br>` : ''}
        <b>Source asset</b> ${escapeHTML(record.affected_asset || 'Not supplied')}<br>
        Reported ${escapeHTML(record.source_severity || 'Unknown')} · CVSS ${escapeHTML(record.source_cvss ?? 'not supplied')} · Confidence ${escapeHTML(record.confidence || 'Unknown')}<br>
        ${escapeHTML(record.validation_status || 'Scanner-reported; unvalidated')}<br>
        <b>Parsed evidence text</b><pre class="trace-excerpt">${escapeHTML(String(excerpt).slice(0, 1200))}</pre>
        <b>Source references</b><ul class="trace-provenance">${references}</ul>
      </div>`;
    }).join('');
  }

  function bugReportSource(finding, scope) {
    const tools = IMPORT_TOOLS.map((tool) => tool.name).filter((name) => finding.sources?.includes(name));
    const severity = Object.hasOwn(SEVERITY_ORDER, finding.severity) ? finding.severity : 'Unknown';
    return [
      `Finding ID ${finding.finding_id}`,
      `Registered origin ${scope.origin}`,
      `Scanner source ${tools.join(', ') || 'Unknown'}`,
      `Scanner-reported severity ${severity === 'Info' ? 'Informational' : severity}`,
    ];
  }

  function openBugReport(findingId) {
    const scope = activeScope();
    const finding = state.findings.find((item) => item.scopeId === scope?.id && item.finding_id === findingId);
    if (!scope || !finding || !checkScope(scope.origin, scope).allowed) {
      toast('Select an authorized lab and a finding to draft a report.', true);
      return;
    }

    const dialog = $('#bugReportDialog');
    const form = $('#bugReportForm');
    const title = form.elements.namedItem('title');
    form.reset();
    title.value = String(finding.title || '').replace(/\s+/g, ' ').trim().slice(0, title.maxLength);
    $('#bugReportContext').textContent = bugReportSource(finding, scope).join(' · ');
    $('#bugReportStatus').textContent = '';
    const records = (finding.evidence_records || []).filter(Boolean);
    const preview = records.slice(0, 3).map((record) => evidenceTraceMarkup(record)).join('');
    $('#bugReportEvidence').innerHTML = preview || '<p>This finding has no source records to preview.</p>';
    if (records.length > 3) {
      $('#bugReportEvidence').insertAdjacentHTML('afterbegin', '<p>Showing the first 3 source records. Open the finding to see the rest.</p>');
    }
    $('.bug-report-sources', dialog).open = false;
    state.bugReportSelection = { scopeId: scope.id, findingId };
    dialog.showModal();
    title.focus();
  }

  async function exportBugReport(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const status = $('#bugReportStatus');
    const selection = state.bugReportSelection;
    const scope = activeScope();
    const finding = selection && scope?.id === selection.scopeId && state.findings.find((item) =>
      item.scopeId === selection.scopeId && item.finding_id === selection.findingId);
    if (!scope || !finding || !checkScope(scope.origin, scope).allowed) {
      status.textContent = 'Open the finding again from its authorized lab.';
      return;
    }

    const values = new FormData(form);
    const sections = [];
    for (const [name, label] of BUG_REPORT_FIELDS) {
      const value = String(values.get(name) || '').trim();
      if (!value) {
        status.textContent = `Complete ${label.toLowerCase()} before exporting.`;
        form.elements.namedItem(name).focus();
        return;
      }
      sections.push(`${label}\n${value}`);
    }
    const evidence = String(values.get('evidence') || '').trim();
    if (evidence) sections.push(`Evidence\n${evidence}`);
    sections.push(`Source reference\n${bugReportSource(finding, scope).join('\n')}`);
    const report = `${sections.join('\n\n')}\n`;

    if (event.submitter?.value === 'download') {
      const link = document.createElement('a');
      const fileId = String(finding.finding_id).replace(/[^a-z0-9-]/gi, '').slice(0, 50) || 'finding';
      const url = URL.createObjectURL(new Blob([report], { type: 'text/plain;charset=utf-8' }));
      link.href = url;
      link.download = `bug-report-${fileId}.txt`;
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      status.textContent = 'Download started.';
      return;
    }

    try {
      await navigator.clipboard.writeText(report);
      if (state.bugReportSelection === selection) status.textContent = 'Bug report copied.';
    } catch (_) {
      if (state.bugReportSelection === selection) status.textContent = 'Clipboard unavailable. Use Download .txt.';
    }
  }

  function riskContextMarkup(finding, context, assessment) {
    const option = (value, label, selected) => `<option value="${value}"${selected === value ? ' selected' : ''}>${label}</option>`;
    const weighted = weightedRiskScore(finding, context);
    const weightedValue = (value, factor) => value === null ? 'Not supplied' : `${value.toFixed(1)} × ${factor} = ${(value * factor).toFixed(2)}`;
    const scoreInputs = [context.exposureScore, context.exploitabilityScore, context.impactScore].map((value) => value !== '' && value !== null && value !== undefined).some(Boolean);
    return `<details class="risk-context"><summary>Analyst context & priority · ${escapeHTML(assessment.label)}</summary>
      <div class="risk-priority-box"><div><span class="eyebrow">REVIEW PRIORITY</span><strong>${escapeHTML(assessment.label)}</strong><p>${escapeHTML(assessment.basis)}</p></div><span class="confidence-review ${assessment.needsEvidenceReview ? 'needs-review' : ''}">${assessment.needsEvidenceReview ? 'VERIFY SOURCE CONFIDENCE' : 'SOURCE CONFIDENCE RECORDED'}</span></div>
      <section class="weighted-score-box" aria-label="Weighted risk score components"><div class="weighted-score-head"><strong>Weighted review score</strong><b>${weighted.score === null ? 'Incomplete' : `${weighted.score.toFixed(1)} / 10`}</b></div><div class="weighted-score-parts"><span>Source CVSS</span><b>${weightedValue(weighted.parts.cvss, '0.4')}</b><span>Exposure</span><b>${weightedValue(weighted.parts.exposure, '0.2')}</b><span>Exploitability</span><b>${weightedValue(weighted.parts.exploitability, '0.2')}</b><span>Asset impact</span><b>${weightedValue(weighted.parts.assetImpact, '0.2')}</b></div><small>Formula: CVSS × 0.4 + exposure × 0.2 + exploitability × 0.2 + asset impact × 0.2. CVSS comes from the source report; enter and cite the other values. No score is shown until all four are available.</small></section>
      <form class="risk-context-form" data-finding-id="${escapeHTML(finding.finding_id)}">
        <label>Exposure<select name="exposure">${option('unknown', 'Unknown', context.exposure)}${option('external', 'Externally reachable within approved lab', context.exposure)}${option('internal', 'Lab / internal only', context.exposure)}</select></label>
        <label>Asset impact<select name="impact">${option('unknown', 'Unknown', context.impact)}${option('high', 'High', context.impact)}${option('medium', 'Medium', context.impact)}${option('low', 'Low', context.impact)}</select></label>
        <label>Exploitability<select name="exploitability">${option('unknown', 'Unknown', context.exploitability)}${option('evidence', 'Imported source describes exploit evidence', context.exploitability)}${option('none-observed', 'No exploit evidence in imported files', context.exploitability)}</select></label>
        <label>Exposure score (0–10)<input name="exposureScore" type="number" min="0" max="10" step="0.1" value="${escapeHTML(context.exposureScore ?? '')}" placeholder="Optional"></label>
        <label>Exploitability score (0–10)<input name="exploitabilityScore" type="number" min="0" max="10" step="0.1" value="${escapeHTML(context.exploitabilityScore ?? '')}" placeholder="Optional"></label>
        <label>Asset impact score (0–10)<input name="impactScore" type="number" min="0" max="10" step="0.1" value="${escapeHTML(context.impactScore ?? '')}" placeholder="Optional"></label>
        <label class="risk-note">Analyst note or evidence reference<textarea name="note" maxlength="400" placeholder="Briefly cite the approved lab context or imported source">${escapeHTML(context.note || '')}</textarea></label>
        <div class="risk-context-actions"><span>Context is analyst-entered and is not independently verified.</span><button class="secondary-button compact" type="submit">Save context</button></div>
      </form>
      <p class="risk-rule-note">The numeric score is a project-specific review aid, not a confirmed vulnerability or a replacement for source severity. ${scoreInputs && weighted.score === null ? 'Some score inputs or source CVSS are still missing.' : ''} Review priority remains separate and source severity is never lowered.</p>
    </details>`;
  }

  function saveRiskContext(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const scope = activeScope();
    const finding = state.findings.find((item) => item.scopeId === scope?.id && item.finding_id === form.dataset.findingId);
    if (!finding) return toast('Select the lab that contains this finding.', true);
    const data = new FormData(form);
    const exposure = String(data.get('exposure') || 'unknown');
    const impact = String(data.get('impact') || 'unknown');
    const exploitability = String(data.get('exploitability') || 'unknown');
    const scoreValue = (name) => String(data.get(name) || '').trim() === '' ? '' : Number(data.get(name));
    const exposureScore = scoreValue('exposureScore');
    const exploitabilityScore = scoreValue('exploitabilityScore');
    const impactScore = scoreValue('impactScore');
    const note = String(data.get('note') || '').trim();
    if (!['unknown', 'external', 'internal'].includes(exposure)
      || !['unknown', 'high', 'medium', 'low'].includes(impact)
      || !['unknown', 'evidence', 'none-observed'].includes(exploitability)) {
      return toast('Choose one of the listed context values.', true);
    }
    if ([exposureScore, exploitabilityScore, impactScore].some((value) => value !== '')
      && [exposureScore, exploitabilityScore, impactScore].some((value) => value !== '' && (!Number.isFinite(value) || value < 0 || value > 10))) {
      return toast('Score components must be numbers from 0 to 10.', true);
    }
    if ([exposure !== 'unknown', impact !== 'unknown', exploitability !== 'unknown', exposureScore !== '', exploitabilityScore !== '', impactScore !== ''].some(Boolean) && !note) {
      return toast('Add a short analyst note or source reference for the selected context.', true);
    }
    const context = { scopeId: finding.scopeId, finding_id: finding.finding_id, exposure, impact, exploitability, exposureScore, exploitabilityScore, impactScore, note, updatedAt: new Date().toISOString() };
    state.riskContexts = state.riskContexts.filter((item) => !(item.scopeId === context.scopeId && item.finding_id === context.finding_id));
    state.riskContexts.unshift(context);
    state.riskContexts = state.riskContexts.slice(0, 500);
    if (!saveStore(KEYS.riskContexts, state.riskContexts)) return;
    const assessment = reviewAssessment(finding, context);
    recordActivity('RISK_CONTEXT_UPDATED', `${finding.finding_id} · ${assessment.label} · exposure ${exposure} · impact ${impact} · exploitability ${exploitability} · ${note || 'context cleared'}`);
    renderFindings();
    toast(`Analyst context saved. Review tier: ${assessment.label}.`);
  }

  function remediationForFinding(finding) {
    return state.remediations.find((item) => item.scopeId === finding.scopeId && item.finding_id === finding.finding_id);
  }

  function saveRemediationRecords(records) {
    if (!saveStore(KEYS.remediations, records)) return false;
    state.remediations = records;
    return true;
  }

  function remediationFindings(scope) {
    if (!checkScope(scope?.origin, scope).allowed) return [];
    return state.findings.filter((finding) => finding.scopeId === scope.id && findingInScope(finding, scope));
  }

  function activeRemediationFindings() {
    const scope = activeScope();
    return scope?.id === $('#remediationDialog').dataset.scopeId ? remediationFindings(scope) : [];
  }

  function selectedRemediationFinding() {
    const id = $('#remediationFindingSelect').value;
    return activeRemediationFindings().find((finding) => finding.finding_id === id);
  }

  function openRemediation() {
    const scope = activeScope();
    if (!remediationFindings(scope).length) return;
    const dialog = $('#remediationDialog');
    if (dialog.open) return;
    state.remediations = readStore(KEYS.remediations, []);
    dialog.dataset.scopeId = scope.id;
    $('#remediationSelectionStatus').textContent = '';
    renderRemediationChoices();
    dialog.showModal();
  }

  function renderRemediationChoices(preferredId) {
    const findings = activeRemediationFindings().sort(compareReviewPriority);
    const tracked = findings.filter(remediationForFinding);
    $('#remediationFindingChoices').innerHTML = findings.map((finding) => {
      const record = remediationForFinding(finding);
      const status = record ? ` · ${REMEDIATION_STATUS_LABELS[record.status] || 'Selected for tracking'}` : '';
      return `<label><input type="checkbox" name="remediationFinding" value="${escapeHTML(finding.finding_id)}"${record ? ' checked disabled' : ''}><span><strong>${escapeHTML(finding.title)}</strong><small>${escapeHTML(`${finding.severity} · ${finding.finding_id} · ${finding.affected_asset}${status}`)}</small></span></label>`;
    }).join('');
    $('#remediationSelectionForm button[type="submit"]').disabled = tracked.length === findings.length;
    const select = $('#remediationFindingSelect');
    select.innerHTML = tracked.map((finding) => `<option value="${escapeHTML(finding.finding_id)}">${escapeHTML(`${finding.title} · ${finding.finding_id}`)}</option>`).join('');
    if (tracked.some((finding) => finding.finding_id === preferredId)) select.value = preferredId;
    $('#remediationTracking').hidden = !tracked.length;
    renderRemediationDetails();
  }

  function renderRemediationDetails() {
    const finding = selectedRemediationFinding();
    const record = finding && remediationForFinding(finding);
    const form = $('#retestForm');
    form.reset();
    form.hidden = true;
    $('#retestButton').disabled = record?.status !== 'fix_reported';
    $('#retestButton').setAttribute('aria-expanded', 'false');
    $('#remediationStatus').value = record?.status || 'planned';
    $('#remediationNotes').value = record?.notes || '';
    $('#remediationSaveStatus').textContent = '';
    $('#remediationSummary').innerHTML = finding ? `<strong>${escapeHTML(finding.title)}</strong><small>${escapeHTML(`${finding.finding_id} · ${finding.affected_asset}`)}</small><p><b>Suggested fix</b> ${escapeHTML(finding.recommendation || 'Use the finding evidence to document a suitable fix.')}</p><p><b>Saved remediation</b> ${escapeHTML(record?.updatedAt ? `${REMEDIATION_STATUS_LABELS[record.status]} · ${formatDate(record.updatedAt)}` : 'Awaiting fix notes')}</p>` : '';
    const retest = record?.retest;
    $('#remediationRetestStatus').textContent = retest
      ? `${retest.stale ? 'Previous analyst retest · New retest pending' : 'Latest analyst retest'} · ${RETEST_RESULT_LABELS[retest.result]} · ${formatDate(retest.testedAt)} · ${retest.evidence}`
      : record?.status === 'fix_reported' ? 'Retest pending.' : '';
  }

  function selectRemediations(event) {
    event.preventDefault();
    const selected = new Set(new FormData(event.currentTarget).getAll('remediationFinding'));
    const feedback = $('#remediationSelectionStatus');
    state.remediations = readStore(KEYS.remediations, []);
    const findings = activeRemediationFindings().filter((finding) => selected.has(finding.finding_id) && !remediationForFinding(finding));
    if (!findings.length) {
      feedback.textContent = 'Select at least one bug that is not already tracked.';
      return;
    }
    const selectedAt = new Date().toISOString();
    const entries = findings.map(({ scopeId, finding_id }) => ({ scopeId, finding_id, selectedAt }));
    if (!saveRemediationRecords([...state.remediations, ...entries])) {
      feedback.textContent = 'Could not save the selected bugs in this browser.';
      return;
    }
    recordActivity('REMEDIATION_SELECTED', `${activeScope().origin} · ${entries.map((entry) => entry.finding_id).join(', ')}`);
    renderRemediationChoices(entries[0].finding_id);
    feedback.textContent = `${entries.length} ${entries.length === 1 ? 'bug' : 'bugs'} added to tracking.`;
    $('#remediationFindingSelect').focus();
  }

  function saveRemediation(event) {
    event.preventDefault();
    const finding = selectedRemediationFinding();
    const feedback = $('#remediationSaveStatus');
    state.remediations = readStore(KEYS.remediations, []);
    const record = finding && remediationForFinding(finding);
    const status = $('#remediationStatus').value;
    const notes = $('#remediationNotes').value.trim();
    if (!record || !Object.hasOwn(REMEDIATION_STATUS_LABELS, status) || !notes || notes.length > 2000) {
      feedback.textContent = 'Choose a tracked bug and enter fix notes of up to 2,000 characters.';
      return;
    }
    if (status === record.status && notes === record.notes) {
      feedback.textContent = 'These remediation details are already saved.';
      return;
    }
    const retest = record.retest ? { ...record.retest, stale: true } : null;
    const updated = { ...record, status, notes, updatedAt: new Date().toISOString(), retest };
    if (!saveRemediationRecords(state.remediations.map((item) => item === record ? updated : item))) {
      feedback.textContent = 'Could not save remediation details in this browser.';
      return;
    }
    recordActivity('REMEDIATION_UPDATED', `${finding.finding_id} · ${activeScope().origin} · ${REMEDIATION_STATUS_LABELS[status]}`);
    renderRemediationChoices(finding.finding_id);
    feedback.textContent = 'Remediation saved.';
  }

  function retestReady(record) {
    return record?.status === 'fix_reported' && $('#remediationStatus').value === record.status
      && $('#remediationNotes').value.trim() === record.notes;
  }

  function openRetestForm() {
    const finding = selectedRemediationFinding();
    state.remediations = readStore(KEYS.remediations, []);
    const record = finding && remediationForFinding(finding);
    if (!retestReady(record)) {
      $('#remediationRetestStatus').textContent = 'Save the current fix notes as Fix reported before recording a retest.';
      return;
    }
    const form = $('#retestForm');
    form.dataset.remediationVersion = record.updatedAt;
    form.hidden = false;
    $('#retestButton').setAttribute('aria-expanded', 'true');
    $('#retestResult').focus();
  }

  function saveRetest(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const finding = selectedRemediationFinding();
    const feedback = $('#remediationRetestStatus');
    state.remediations = readStore(KEYS.remediations, []);
    const record = finding && remediationForFinding(finding);
    if (form.hidden || !retestReady(record) || record.updatedAt !== form.dataset.remediationVersion) {
      feedback.textContent = 'Open the retest form again after saving the current fix notes.';
      return;
    }
    const result = $('#retestResult').value;
    const evidence = $('#retestEvidence').value.trim();
    if (!Object.hasOwn(RETEST_RESULT_LABELS, result) || !evidence || evidence.length > 2000) {
      feedback.textContent = 'Choose a result and enter retest evidence of up to 2,000 characters.';
      return;
    }
    const updated = { ...record, retest: { result, evidence, testedAt: new Date().toISOString() } };
    if (!saveRemediationRecords(state.remediations.map((item) => item === record ? updated : item))) {
      feedback.textContent = 'Could not save the retest in this browser.';
      return;
    }
    recordActivity('RETEST_RECORDED', `${finding.finding_id} · ${activeScope().origin} · ${RETEST_RESULT_LABELS[result]} · analyst observation`);
    renderRemediationDetails();
    $('#retestButton').focus();
  }

  function findingReviewFor(finding) {
    return state.findingReviews.find((review) => review.scopeId === finding.scopeId && review.finding_id === finding.finding_id);
  }

  function findReviewableFinding(scope, findingId) {
    if (!checkScope(scope?.origin, scope).allowed) return null;
    return state.findings.find((finding) => finding.scopeId === scope.id && finding.finding_id === findingId && findingInScope(finding, scope));
  }

  function renderFindingReviewSummary(finding, review) {
    $('#findingReviewSummary').innerHTML = `<strong>${escapeHTML(finding.title)}</strong>
      <p>${escapeHTML(`${finding.finding_id} · ${finding.affected_asset} · Scanner severity ${finding.severity}`)}</p>
      <p>${review ? escapeHTML(`Last saved ${formatDate(review.updatedAt)} · ${FINDING_REVIEW_STATUS_LABELS[review.status]}`) : 'No analyst review saved yet.'}</p>`;
  }

  function syncFindingReviewEvidenceRequirement() {
    $('#findingReviewEvidenceNote').required = $('#findingReviewStatus').value !== 'needs_review';
  }

  function openFindingReview(findingId) {
    const scope = activeScope();
    const finding = findReviewableFinding(scope, findingId);
    if (!finding) return toast('Select an in-scope finding to review.', true);
    const dialog = $('#findingReviewDialog');
    if (dialog.open) return;
    state.findingReviews = readStore(KEYS.findingReviews, []);
    const review = findingReviewFor(finding);
    renderFindingReviewSummary(finding, review);
    $('#findingReviewEvidence').innerHTML = (finding.evidence_records || []).map((record) => evidenceTraceMarkup(record)).join('')
      || '<p>No imported source records are available for this finding.</p>';
    $('#findingReviewSources').open = false;
    $('#findingReviewStatus').value = review?.status || 'needs_review';
    $('#findingReviewReason').value = review?.reason || '';
    $('#findingReviewEvidenceNote').value = review?.evidence || '';
    $('#findingReviewFeedback').textContent = '';
    syncFindingReviewEvidenceRequirement();
    state.findingReviewSelection = { scopeId: scope.id, findingId };
    dialog.showModal();
    $('#findingReviewStatus').focus();
  }

  function renderFindingReviewBadges() {
    const scopeId = activeScope()?.id;
    $$('#findingList .finding-triage').forEach((badge) => {
      const finding_id = badge.closest('.finding-card').dataset.findingId;
      const status = findingReviewFor({ scopeId, finding_id })?.status || 'needs_review';
      badge.className = `finding-triage ${status}`;
      badge.textContent = `Analyst: ${FINDING_REVIEW_STATUS_LABELS[status]}`;
    });
  }

  function saveFindingReview(event) {
    event.preventDefault();
    const selection = state.findingReviewSelection;
    const scope = activeScope();
    const finding = selection && selection.scopeId === scope?.id && findReviewableFinding(scope, selection.findingId);
    const feedback = $('#findingReviewFeedback');
    if (!finding) {
      feedback.textContent = 'Open the finding again from its authorized lab.';
      return;
    }
    const data = new FormData(event.currentTarget);
    const status = data.get('status');
    const reason = String(data.get('reason') || '').trim();
    const evidence = String(data.get('evidence') || '').trim();
    if (!Object.hasOwn(FINDING_REVIEW_STATUS_LABELS, status) || !reason || reason.length > 1200 || evidence.length > 2000) {
      feedback.textContent = 'Choose a status and enter a reason within the field limits.';
      return;
    }
    if (status !== 'needs_review' && !evidence) {
      feedback.textContent = 'Add the observation or evidence reference that supports this decision.';
      $('#findingReviewEvidenceNote').focus();
      return;
    }
    const saved = readStore(KEYS.findingReviews, []);
    const review = { scopeId: scope.id, finding_id: finding.finding_id, status, reason, evidence, updatedAt: new Date().toISOString() };
    const updated = [...saved.filter((item) => item.scopeId !== scope.id || item.finding_id !== finding.finding_id), review];
    if (!saveStore(KEYS.findingReviews, updated)) {
      feedback.textContent = 'Could not save the review in this browser.';
      return;
    }
    state.findingReviews = updated;
    recordActivity('FINDING_REVIEW_SAVED', `${scope.origin} · ${finding.finding_id} · ${FINDING_REVIEW_STATUS_LABELS[status]}`);
    renderFindingReviewSummary(finding, review);
    renderFindingReviewBadges();
    feedback.textContent = 'Review saved.';
  }

  function renderFindings() {
    const scope = activeScope();
    $('#remediationButton').disabled = !remediationFindings(scope).length;
    renderImportHistory();
    const target = scope ? scope.origin : '';
    $('#activeTargetChip').textContent = target || 'No active lab selected';
    const severityValue = $('#severityFilter').value;
    const query = $('#findingSearch').value.trim().toLowerCase();
    const records = state.findings.filter((finding) => finding.scopeId === scope?.id)
      .filter((finding) => severityValue === 'all' || finding.severity === severityValue)
      .filter((finding) => !query || `${finding.title} ${finding.affected_asset} ${finding.sources.join(' ')} ${finding.supporting_evidence}`.toLowerCase().includes(query))
      .sort(compareReviewPriority);
    const root = $('#findingList');
    if (!records.length) {
      root.innerHTML = `<div class="no-findings"><strong>${scope ? 'No imported findings for this lab yet' : 'Select an authorized lab scope'}</strong>${scope ? 'Import real scanner exports from your authorized lab to populate this view.' : 'Register and select an authorized lab scope before importing evidence.'}</div>`;
      return;
    }
    root.innerHTML = records.map((finding) => {
      const context = contextForFinding(finding);
      const assessment = reviewAssessment(finding, context);
      const weighted = weightedRiskScore(finding, context);
      const agreement = sourceAgreement(finding);
      const severityClass = finding.severity.toLowerCase();
      const cvss = finding.cvss !== null && finding.cvss !== undefined ? `CVSS ${escapeHTML(finding.cvss)}` : 'CVSS not supplied';
      const sources = (finding.evidence_records || []).map((record) => ({ record, warnings: sourceInstructionWarnings(record) }));
      const traces = sources.map(({ record, warnings }) => evidenceTraceMarkup(record, warnings)).join('');
      const instructionWarning = sources.some(({ warnings }) => warnings.length) ? ' · Possible AI instructions' : '';
      const findingId = escapeHTML(finding.finding_id);
      return `<article class="finding-card" data-finding-id="${findingId}">
        <div class="finding-card-head"><div class="finding-name"><span class="severity-mark ${escapeHTML(severityClass)}"></span><div><h3>${escapeHTML(finding.title)}</h3><div class="asset">${escapeHTML(finding.affected_asset)}</div></div></div><span class="severity-pill ${escapeHTML(severityClass)}">${escapeHTML(finding.severity)}</span></div>
        <div class="finding-meta"><span class="meta-pill">${findingId}</span><span class="meta-pill">${escapeHTML(finding.sources.join(' · '))}</span><span class="meta-pill">${cvss}</span><span class="agreement-badge ${agreement.count >= 2 ? 'corroborated' : 'single-source'}" title="Rule-based source count only; not vulnerability confirmation">${escapeHTML(agreement.label)}</span><span class="meta-pill">Review: ${escapeHTML(assessment.label)}</span><span class="meta-pill">Weighted score: ${weighted.score === null ? 'incomplete' : `${weighted.score.toFixed(1)} / 10`}</span><span class="meta-pill">Confidence: ${escapeHTML(finding.confidence)}</span><span class="meta-pill">${escapeHTML(finding.validation_status)}</span><span class="finding-triage"></span></div>
        <details class="finding-evidence"><summary>Evidence · ${sources.length} source record(s)${instructionWarning ? `<span class="instruction-warning">${instructionWarning}</span>` : ''}</summary><div class="evidence-block">${escapeHTML(finding.description || 'No description supplied.')}<br>These are scanner observations. Planner suggestions are not findings. The importer keeps parsed evidence text, not exact raw-file lines.</div>${traces}</details>
        ${riskContextMarkup(finding, context, assessment)}
        <div class="finding-foot"><span class="priority-note">Agreement counts matching source tools only. The analyst review is recorded separately.</span><span>${escapeHTML(formatDate(finding.timestamp))}</span>
          <div class="finding-actions"><button type="button" class="secondary-button compact" aria-haspopup="dialog" data-review-finding="${findingId}">Review finding</button><button type="button" class="secondary-button compact finding-report-action" data-draft-finding="${findingId}">Draft bug report</button></div>
        </div>
      </article>`;
    }).join('');
    renderFindingReviewBadges();
  }

  function renderActivity() {
    $('#activityCount').textContent = String(state.activity.length);
    const root = $('#activityList');
    if (!state.activity.length) {
      root.innerHTML = '<div class="empty-list">No activity recorded yet.</div>';
      return;
    }
    const rows = state.activity.map((entry) => {
      const result = entry.result || 'Recorded';
      const tone = /failed|no in-scope/i.test(result) ? 'warning' : /running/i.test(result) ? 'live' : '';
      return `<tr><td>${escapeHTML(entry.actor || 'Assessment analyst')}</td><td><strong>${escapeHTML(String(entry.action || 'Action').replaceAll('_', ' '))}</strong><small>${escapeHTML(entry.details || '')}</small></td><td>${escapeHTML(formatDate(entry.timestamp))}</td><td><span class="audit-result ${tone}">${escapeHTML(result)}</span></td></tr>`;
    }).join('');
    root.innerHTML = `<div class="table-scroll"><table class="activity-audit-table"><thead><tr><th>WHO</th><th>WHAT</th><th>WHEN</th><th>RESULT</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderApprovalOptions() {
    const select = $('#approvalFinding');
    if (!select) return;
    const previous = select.value;
    const scope = activeScope();
    const findings = state.findings.filter((item) => item.scopeId === scope?.id);
    select.innerHTML = '<option value="">Select a finding</option>' + findings.map((item) => `<option value="${escapeHTML(item.finding_id)}">${escapeHTML(item.severity)} · ${escapeHTML(item.title)}</option>`).join('');
    if (findings.some((item) => item.finding_id === previous)) select.value = previous;
    updateApprovalButtons();
  }

  function updateApprovalButtons() {
    const scope = activeScope();
    const selected = $('#approvalFinding').value;
    const reason = $('#approvalReason').value.trim();
    const scopeCheck = checkScope(scope?.origin, scope, ['Layer review']);
    const authorized = scopeCheck.allowed;
    $('#approvalScopeStatus').textContent = authorized
      ? 'Layer review is allowed for this saved scope. Decisions are recorded locally and nothing is executed.'
      : `Decision gate locked: ${scopeCheck.reason}`;
    const baseReady = Boolean(selected && reason && $('#approvalScopeConfirm').checked && authorized);
    $('#approveValidation').disabled = !baseReady;
    $('#rejectValidation').disabled = !selected || !reason || !authorized;
  }

  function saveDecision(approved) {
    const scope = activeScope();
    const finding = state.findings.find((item) => item.finding_id === $('#approvalFinding').value && item.scopeId === scope?.id);
    const reason = $('#approvalReason').value.trim();
    const scopeCheck = checkScope(scope?.origin, scope, ['Layer review']);
    if (!scopeCheck.allowed) return toast(scopeCheck.reason, true);
    if (!finding || !reason) return toast('Select a finding and enter a reason for review.', true);
    if (approved && (!$('#approvalScopeConfirm').checked || !scope?.attested || !scope?.approvalReference)) return toast('Confirm the approved lab scope before recording approval.', true);
    const decision = {
      id: makeId('DEC'), scopeId: scope.id, finding_id: finding.finding_id,
      action: approved ? 'VALIDATION_APPROVED_NOT_EXECUTED' : 'VALIDATION_REJECTED',
      target: scope.origin, reason, analyst: 'Assessment analyst',
      timestamp: new Date().toISOString(), executor: 'Not configured; no action executed',
    };
    state.approvals.unshift(decision);
    state.approvals = state.approvals.slice(0, 200);
    saveStore(KEYS.approvals, state.approvals);
    recordActivity(decision.action, `${finding.finding_id} · ${scope.origin} · ${reason} · no action executed`);
    $('#approvalReason').value = '';
    $('#approvalScopeConfirm').checked = false;
    updateApprovalButtons();
    toast(approved ? 'Approval decision recorded. Nothing was executed.' : 'Rejection recorded. Nothing was executed.');
  }

  function severityCounts(findings) {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0, Unknown: 0 };
    findings.forEach((item) => { counts[item.severity] = (counts[item.severity] || 0) + 1; });
    return counts;
  }

  function savedPdfSize(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  async function loadSavedPdfs() {
    if (state.loadingSavedPdfs || state.movingSavedPdf) return;
    const refresh = $('#savedPdfsRefresh');
    const status = $('#savedPdfsStatus');
    const list = $('#savedPdfsList');
    const trashList = $('#savedPdfsTrash');
    state.loadingSavedPdfs = true;
    refresh.disabled = true;
    list.setAttribute('aria-busy', 'true');
    status.textContent = 'Looking for saved reports…';
    try {
      const response = await fetch('/api/saved-pdfs', { method: 'POST' });
      if (!response.ok) throw new Error('Could not load saved PDFs.');
      const { reports, trashed = [] } = await response.json();
      list.innerHTML = reports.map((report) => savedPdfRow(report, false)).join('');
      trashList.innerHTML = trashed.map((report) => savedPdfRow(report, true)).join('')
        || '<li class="muted-note">PDF Trash is empty.</li>';
      status.textContent = reports.length
        ? `${reports.length} saved ${reports.length === 1 ? 'report' : 'reports'}`
        : 'No saved reports yet. Open a report preview and choose Save PDF.';
    } catch (_) {
      list.replaceChildren();
      trashList.replaceChildren();
      status.textContent = 'Could not load saved PDFs. Choose Refresh to try again.';
    } finally {
      state.loadingSavedPdfs = false;
      refresh.disabled = false;
      list.setAttribute('aria-busy', 'false');
    }
  }

  function savedPdfRow({ name, size, modifiedAt, library = false }, trashed) {
    const filename = escapeHTML(name);
    const buttons = trashed
      ? `<button class="secondary-button compact" type="button" data-restore-pdf="${filename}" data-library="${library}">Restore</button>`
      : `<button class="secondary-button compact" type="button" data-open-saved-pdf="${filename}" data-library="${library}">Open PDF</button><button class="delete-button" type="button" data-trash-pdf="${filename}" data-library="${library}">Delete</button>`;
    return `<li class="saved-pdf-row"><span class="saved-pdf-icon" aria-hidden="true">PDF</span>
      <div class="saved-pdf-details"><strong>${filename}</strong><small>${escapeHTML(formatDate(modifiedAt))} · ${escapeHTML(savedPdfSize(size))}</small></div>
      <div class="saved-pdf-actions">${buttons}</div></li>`;
  }

  async function changeSavedPdfTrash(button, deleting) {
    if (state.loadingSavedPdfs || state.movingSavedPdf) return;
    const name = deleting ? button.dataset.trashPdf : button.dataset.restorePdf;
    if (deleting && !window.confirm(`Move ${name} to PDF Trash?`)) return;
    state.movingSavedPdf = true;
    button.disabled = true;
    try {
      const response = await fetch(`/api/saved-pdfs/${deleting ? 'trash' : 'restore'}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, library: button.dataset.library === 'true' }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Could not move the PDF.');
      toast(deleting ? 'PDF moved to Trash. Restore it from PDF Trash.' : 'PDF restored to its report folder.');
    } catch (error) {
      toast(error.message || 'Could not move the PDF.', true);
    } finally {
      state.movingSavedPdf = false;
      button.disabled = false;
      loadSavedPdfs();
    }
  }

  async function openSavedPdf(button) {
    const tab = window.open('', '_blank');
    if (!tab) return toast('Allow pop-ups for ScopeWeave to open saved PDFs.', true);
    tab.opener = null;
    tab.document.title = 'Opening saved PDF';
    tab.document.body.textContent = 'Opening saved PDF…';
    button.disabled = true;
    try {
      const response = await fetch('/api/saved-pdfs/open', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: button.dataset.openSavedPdf, library: button.dataset.library === 'true' }),
      });
      if (!response.ok || !response.headers.get('Content-Type')?.startsWith('application/pdf')) throw new Error('PDF unavailable.');
      const file = await response.blob();
      if (tab.closed) return;
      const url = URL.createObjectURL(file);
      tab.location.replace(url);
      const cleanup = window.setInterval(() => {
        if (!tab.closed) return;
        window.clearInterval(cleanup);
        URL.revokeObjectURL(url);
      }, 5000);
    } catch (_) {
      tab.close();
      toast('Could not open this PDF. It may have moved. Refresh the saved reports list and try again.', true);
    } finally {
      button.disabled = false;
    }
  }

  function exactReportEndpoint(finding) {
    const records = finding.evidence_records || [];
    if (!records.length) return '';
    let endpoint = '';
    for (const asset of [finding.affected_asset, ...records.map((record) => record.affected_asset)]) {
      const value = String(asset || '').trim();
      // An origin by itself may be a parser fallback, so require an explicit path.
      if (!/^https?:\/\/[^/?#]+\//i.test(value)) return '';
      let url;
      try { url = new URL(value); } catch (_) { return ''; }
      if (url.username || url.password || (endpoint && url.href !== endpoint)) return '';
      endpoint = url.href;
    }
    return endpoint;
  }

  function groupReportFindings(findings, mergeAliases) {
    const groups = new Map();
    for (const finding of findings) {
      const alias = mergeAliases && REPORT_HEADER_ALIASES.get(normalizedTitle(finding.title));
      const endpoint = alias && exactReportEndpoint(finding);
      const key = endpoint ? JSON.stringify([alias, endpoint]) : finding;
      const existing = groups.get(key);
      if (existing) {
        existing.title = alias;
        existing.members.push(finding);
        existing.evidence_records.push(...(finding.evidence_records || []));
        if ((SEVERITY_ORDER[finding.severity] || 0) > (SEVERITY_ORDER[existing.severity] || 0)) {
          existing.severity = finding.severity;
        }
      } else {
        groups.set(key, {
          title: finding.title,
          severity: finding.severity,
          affected_asset: finding.affected_asset,
          members: [finding],
          evidence_records: [...(finding.evidence_records || [])],
        });
      }
    }
    return [...groups.values()];
  }

  function openReportOptions() {
    const scope = activeScope();
    if (!scope) return toast('Select an authorized lab scope to prepare its report.', true);
    $('#reportOptionsStatus').textContent = '';
    const dialog = $('#reportOptionsDialog');
    if (!dialog.open) dialog.showModal();
  }

  function previewReport(event) {
    event.preventDefault();
    const scope = activeScope();
    const mode = new FormData(event.currentTarget).get('reportMode');
    const status = $('#reportOptionsStatus');
    if (!scope || !Object.hasOwn(REPORT_MODES, mode)) {
      status.textContent = 'Select a lab and report option.';
      return;
    }
    const reportWindow = window.open('', '_blank');
    if (!reportWindow) {
      status.textContent = 'Allow pop-ups for ScopeWeave to open the report preview.';
      return;
    }

    const workspaceFindings = state.findings.filter((item) => item.scopeId === scope.id).sort(compareReviewPriority);
    const compact = mode !== 'all';
    const groups = groupReportFindings(workspaceFindings, compact).map((group) => ({
      ...group,
      evidenceGroups: groupReportEvidence(group.evidence_records, compact),
    }));
    const onlyDuplicates = mode === 'duplicates';
    const findings = onlyDuplicates ? groups.filter((group) =>
      group.members.length > 1 || sourceAgreement(group).count > 1 || group.evidenceGroups.some((evidence) => evidence.count > 1)) : groups;
    const includedIds = new Set(findings.flatMap((group) => group.members.map((finding) => finding.finding_id)));
    const approvals = state.approvals.filter((item) => item.target === scope.origin && (!onlyDuplicates || includedIds.has(item.finding_id)));
    const imports = state.imports.filter((item) => item.scopeId === scope.id);
    const counts = severityCounts(findings);
    const previousPlan = !onlyDuplicates && state.lastPlan?.scopeId === scope.id ? state.lastPlan : null;
    const earlierPlan = Boolean(previousPlan && previousPlan.evidenceVersion !== plannerEvidenceVersion(scope.id));
    const plan = earlierPlan ? null : previousPlan;
    const request = $('#requestText').value.trim();
    const html = buildReportHTML({ scope, findings, approvals, imports, counts, plan, mode, workspaceCount: workspaceFindings.length, earlierPlan, request });
    reportWindow.document.open();
    reportWindow.document.write(html);
    reportWindow.document.close();
    reportWindow.document.getElementById('reportPreviewPrint').addEventListener('click', () => reportWindow.print());
    reportWindow.document.getElementById('reportPreviewSave').addEventListener('click', () => saveReportPdf(reportWindow.document));
    $('#reportOptionsDialog').close();
    recordActivity('REPORT_PREPARED', `${scope.origin} · ${REPORT_MODES[mode]} · ${findings.length} report entries`);
  }

  async function saveReportPdf(preview) {
    const button = preview.getElementById('reportPreviewSave');
    const status = preview.getElementById('reportPreviewSaveStatus');
    button.disabled = true;
    status.textContent = 'Saving PDF…';
    try {
      const response = await fetch('/api/saved-pdfs/export', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          body: preview.querySelector('.report-paper').outerHTML,
          styles: preview.querySelector('style').textContent,
        }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Could not save the report.');
      status.textContent = `Saved in Downloads → ScopeWeave Reports: ${result.name}`;
      button.textContent = 'PDF saved';
      if ($('#page-saved-pdfs').classList.contains('active')) loadSavedPdfs();
    } catch (error) {
      status.textContent = error.message || 'Could not save the report. Try again.';
      button.disabled = false;
    }
  }

  function reportFindingReview(finding, merged) {
    const context = contextForFinding(finding);
    const review = reviewAssessment(finding, context);
    const triage = findingReviewFor(finding);
    const triageStatus = FINDING_REVIEW_STATUS_LABELS[triage?.status] || FINDING_REVIEW_STATUS_LABELS.needs_review;
    const weighted = weightedRiskScore(finding, context);
    const exposure = { external: 'Externally reachable within approved lab', internal: 'Lab / internal only' }[context.exposure] || 'Unknown';
    const impact = { high: 'High', medium: 'Medium', low: 'Low' }[context.impact] || 'Unknown';
    const exploitability = { evidence: 'Imported source describes exploit evidence', 'none-observed': 'No exploit evidence in imported files' }[context.exploitability] || 'Unknown';
    const weightedLabel = weighted.score === null
      ? 'Not calculated · source CVSS or analyst score components are missing.'
      : `${weighted.score.toFixed(1)} / 10 · CVSS ${weighted.parts.cvss.toFixed(1)}×0.4 + exposure ${weighted.parts.exposure.toFixed(1)}×0.2 + exploitability ${weighted.parts.exploitability.toFixed(1)}×0.2 + asset impact ${weighted.parts.assetImpact.toFixed(1)}×0.2`;
    const sourceNames = merged ? sourceAgreement(finding).sources.join(', ') : '';
    return `<section class="finding-review">
      ${merged ? `<h4>${escapeHTML(finding.finding_id)} · ${escapeHTML(finding.title)}${sourceNames ? ` · ${escapeHTML(sourceNames)}` : ''}</h4>` : ''}
      <p><b>Source CVSS</b> ${escapeHTML(finding.cvss ?? 'Not supplied')} · <b>CVE</b> ${escapeHTML((finding.cve || []).join(', ') || 'Not supplied')} · <b>CWE</b> ${escapeHTML(finding.cwe || 'Not supplied')}</p>
      <p><b>Weighted review score</b> ${escapeHTML(weightedLabel)}</p>
      <p><b>Review priority</b> ${escapeHTML(review.label)} — ${escapeHTML(review.basis)} · ${review.needsEvidenceReview ? 'Source confidence needs review.' : 'Source confidence recorded.'}</p>
      <p><b>Analyst context</b> Exposure ${escapeHTML(exposure)} · Asset impact ${escapeHTML(impact)} · Exploitability ${escapeHTML(exploitability)}${context.note ? ` · Note ${escapeHTML(context.note)}` : ''}</p>
      <p><b>Scanner validation</b> ${escapeHTML(finding.validation_status)}</p>
      <div class="finding-triage-record">
        <p><b>Analyst finding review</b> · ${escapeHTML(triageStatus)} · ${triage ? `Recorded ${escapeHTML(formatDate(triage.updatedAt))}` : 'No review recorded'}</p>
        ${triage ? `<p><b>Review reason</b> <span>${escapeHTML(triage.reason)}</span></p>
        <p><b>Review evidence</b> <span>${escapeHTML(triage.evidence || 'No evidence reference recorded.')}</span></p>` : ''}
      </div>
      <p><b>Description</b> ${escapeHTML(finding.description || 'Not supplied')}</p>
      <p><b>Remediation</b> ${escapeHTML(finding.recommendation || 'Analyst should consult source guidance and confirm an appropriate remediation.')}</p>
    </section>`;
  }

  function reportFindingMarkup(group) {
    const merged = group.members.length > 1;
    const heading = merged ? group.title : `${group.members[0].finding_id} · ${group.title}`;
    const agreement = sourceAgreement(group);
    const groupingNote = merged
      ? `<p class="duplicate-note"><b>Merged duplicate</b> · ${group.members.length} workspace findings combined into one report entry. The original findings below name the same missing header at this URL.</p>`
      : agreement.count > 1
        ? '<p class="duplicate-note"><b>Grouped across tools</b> · These scanners already shared one finding in the workspace. Their original records appear below.</p>'
        : '';
    const memberReviews = group.members.map((finding) => {
      const review = reportFindingReview(finding, merged);
      const tracking = remediationForFinding(finding);
      if (!tracking) return review;

      const retest = tracking.retest;
      const retestResult = RETEST_RESULT_LABELS[retest?.result];
      const retestStatus = retest?.stale ? 'Retest pending after remediation update'
        : retestResult || (tracking.status === 'fix_reported' ? 'Pending retest' : 'Retest not started');
      return `${review}<section class="remediation-record">
        <h4>Remediation and retesting${merged ? ` · ${escapeHTML(finding.finding_id)}` : ''}</h4>
        <p><b>Remediation status</b> ${escapeHTML(REMEDIATION_STATUS_LABELS[tracking.status] || 'Not started')}</p>
        ${tracking.updatedAt ? `<p><b>Remediation updated</b> ${escapeHTML(formatDate(tracking.updatedAt))}</p>` : ''}
        <p><b>Remediation notes</b> <span class="remediation-note">${escapeHTML(tracking.notes || 'No fix notes recorded.')}</span></p>
        <p><b>Retest status</b> ${escapeHTML(retestStatus)}${retest && !retest.stale ? ' · Analyst-recorded' : ''}</p>
        ${retest?.stale ? `<p><b>Previous retest</b> ${escapeHTML(retestResult)} · Analyst-recorded</p>` : ''}
        ${retest ? `<p><b>${retest.stale ? 'Previous retest recorded' : 'Retest recorded'}</b> ${escapeHTML(formatDate(retest.testedAt))}</p><p><b>${retest.stale ? 'Previous retest evidence' : 'Retest evidence'}</b> <span class="remediation-note">${escapeHTML(retest.evidence)}</span></p>` : ''}
      </section>`;
    }).join('');
    return `<article class="finding">
      <h3>${escapeHTML(heading)} · ${escapeHTML(group.severity)}</h3>
      <p><b>Affected asset</b> ${escapeHTML(group.affected_asset)}</p>
      ${groupingNote}
      <p><b>Cross-tool agreement</b> ${escapeHTML(agreement.label)} · Sources ${escapeHTML(agreement.sources.join(', ') || 'not recorded')}</p>
      ${memberReviews}
      ${reportEvidenceMarkup(group.evidenceGroups)}
    </article>`;
  }

  function buildReportHTML({ scope, findings, approvals, imports, counts, plan, mode, workspaceCount, earlierPlan = false, request = '' }) {
    const onlyDuplicates = mode === 'duplicates';
    const severityRows = Object.entries(counts).map(([severity, count]) => `<tr><td>${escapeHTML(severity)}</td><td>${count}</td></tr>`).join('');
    const coverage = buildEvidenceCoverage(scope, request, findings);
    const coverageRows = coverage.tools.map((tool) => `<tr><td>${escapeHTML(tool.name)}</td><td>${escapeHTML(tool.label)}</td><td>${tool.fileCount}</td><td>${tool.findingGroups}</td><td>${escapeHTML(tool.detail)}</td></tr>`).join('');
    const priorityCounts = new Map(['Review now', 'High review', 'Context review', 'Moderate review', 'Routine review', 'Needs context'].map((label) => [label, 0]));
    findings.forEach((group) => {
      const priority = reviewAssessment(group.members[0]).label;
      priorityCounts.set(priority, (priorityCounts.get(priority) || 0) + 1);
    });
    const priorityRows = [...priorityCounts].map(([label, count]) => `<tr><td>${escapeHTML(label)}</td><td>${count}</td></tr>`).join('');
    const details = findings.map(reportFindingMarkup).join('') || (onlyDuplicates
      ? '<p class="duplicate-note">No duplicate findings or repeated evidence matched for this lab.</p>'
      : '<p>No normalized findings were available for this registered lab.</p>');
    const members = findings.flatMap((group) => group.members);
    const triageCounts = { needs_review: 0, confirmed: 0, false_positive: 0 };
    for (const finding of members) {
      const status = findingReviewFor(finding)?.status;
      triageCounts[Object.hasOwn(triageCounts, status) ? status : 'needs_review'] += 1;
    }
    const triageSummary = members.length
      ? Object.entries(triageCounts).map(([status, count]) => `${count} ${FINDING_REVIEW_STATUS_LABELS[status]}`).join(' · ')
      : 'No findings to review in this report.';
    const trackedCount = members.filter(remediationForFinding).length;
    const remediationSummary = trackedCount
      ? `Tracking records are included for ${trackedCount} ${trackedCount === 1 ? 'finding' : 'findings'}. Retest results are recorded by the analyst.`
      : 'No remediation or retest records for the findings in this report.';
    const combinedCount = workspaceCount - findings.length;
    const duplicateSummary = {
      all: `${workspaceCount} saved findings included with all their saved source records.`,
      deduplicated: `${workspaceCount} workspace findings → ${findings.length} report entries. ${combinedCount} extra ${combinedCount === 1 ? 'entry' : 'entries'} combined during export.`,
      duplicates: `${findings.length} matching report entries shown from ${workspaceCount} workspace findings.`,
    }[mode];
    const decisions = approvals.length ? approvals.map((item) => `<li>${escapeHTML(formatDate(item.timestamp))} · ${escapeHTML(item.finding_id || 'Finding ID unavailable')} · ${escapeHTML(item.analyst)} · ${escapeHTML(item.action)} · ${escapeHTML(item.reason)} · ${escapeHTML(item.executor)}</li>`).join('') : '<li>No human validation decisions recorded.</li>';
    const importEntries = imports.flatMap((run) => run.files.map((file) => ({ ...file, checkedAt: run.startedAt })));
    const liveZapRuns = importEntries.filter((entry) => /^zap-live-/.test(entry.fileName || '')).length;
    const integrationRows = [
      ['OWASP ZAP', liveZapRuns ? 'Used · local passive crawl' : 'Available · requires local setup', 'Bounded Spider crawl and passive checks; no active scan'],
      ['Nmap', 'Import only', 'Approved XML report'],
      ['Nessus', 'Import only', 'Approved .nessus report'],
      ['OpenVAS / Greenbone', 'Import only', 'Approved XML report'],
      ['Nikto', 'Import only', 'Approved XML report'],
      ['Burp Suite', 'Import only', 'Approved XML issue export'],
      ['Cross-tool agreement', 'Implemented · rule-based', 'Exact workspace matches and recognized header aliases on the same recorded URL. One tool = Low agreement. Two or more = Medium agreement.'],
      ['Local Ollama planner', plan?.plannerMode === 'ollama' ? 'Used · local suggestion' : 'Available · optional local setup', 'On-device next-step suggestion; no scan started'],
      ['Groq cloud analysis', plan?.plannerMode === 'groq' ? `Used · ${plan.evidenceCount} finding summaries shared with consent` : plan?.provider === 'groq' ? 'Requested · rule fallback used' : 'Available · requires server key and consent', 'Source-linked AI interpretation; up to 10 finding summaries and 3 excerpts per finding; no scan started'],
      ['Metasploit', 'Planned', 'No adapter or execution path'],
      ['Imported evidence warning', 'Implemented', 'Pattern-based warning with optional exclusion from Groq review'],
      ['Adaptive tool choices', 'Implemented · local guidance', 'Explain when to reuse evidence, import an approved report, or hold a tool.'],
      ['Source line jump links', 'Planned', 'Jump from a finding to an exact imported-file line'],
    ].map((row) => `<tr>${row.map((cell) => `<td>${escapeHTML(cell)}</td>`).join('')}</tr>`).join('');
    const importLog = importEntries.length ? `<table class="import-log"><thead><tr><th>File</th><th>Tool</th><th>Result</th><th>Accepted / excluded</th><th>Details</th><th>Reviewed</th></tr></thead><tbody>${importEntries.map((entry) => `<tr><td>${escapeHTML(entry.fileName)}</td><td>${escapeHTML(entry.tool || 'Not identified')}</td><td>${escapeHTML(String(entry.outcome || 'reviewed').replaceAll('_', ' ').toUpperCase())}</td><td>${entry.acceptedRecords || 0} / ${entry.excludedRecords || 0}</td><td>${escapeHTML(entry.message || 'File records reviewed against the registered lab scope.')}</td><td>${escapeHTML(formatDate(entry.checkedAt))}</td></tr>`).join('')}</tbody></table>` : '<p>No scanner files have been imported into this scope.</p>';
    const reportPlannerLabel = plan?.plannerMode === 'groq'
      ? `Groq cloud · ${plan.model || 'model not recorded'} · source IDs checked; interpretations require analyst review.`
      : plan?.plannerMode === 'ollama' ? 'Local Ollama JSON suggestion passed permission checks.'
        : `Rule fallback used after the ${plan?.provider === 'groq' ? 'Groq cloud' : 'local Ollama'} request. ${plan?.fallbackReason || ''}`;
    const missingPlanText = earlierPlan ? 'Imports or analyst review statuses changed after the earlier planner response. See the current suggested next review below.' : 'No plan was recorded for this report.';
    const planHtml = plan ? `<h3>Assessment plan</h3><p><b>Request:</b> ${escapeHTML(plan.request)}</p><p><b>Planner mode:</b> ${escapeHTML(reportPlannerLabel)}</p>${plan.llmSuggestion ? `<p><b>AI next-step suggestion:</b> ${escapeHTML(PLANNER_STEP_LABELS[plan.llmSuggestion.next_step] || plan.llmSuggestion.next_step)} — ${escapeHTML(plan.llmSuggestion.reason)}</p>` : ''}${aiAnalysisMarkup(plan, true)}<ol>${plan.steps.map((step) => `<li><b>${escapeHTML(step.title)}</b> — ${escapeHTML(step.reason)} (${escapeHTML(step.status)})</li>`).join('')}</ol>` : `<h3>Assessment plan</h3><p>${escapeHTML(missingPlanText)}</p>`;
    const matchingMethod = mode === 'all'
      ? 'This view shows each saved finding and its source records.'
      : 'The report groups recognized names for the same missing header at matching URLs. Identical evidence appears once with its original file and record references.';
    const coverageSection = onlyDuplicates
      ? '<h2>4. Evidence sources</h2><p>Original source files and references appear under each matching finding.</p>'
      : `<h2>4. Evidence coverage and intake</h2><p>A missing report means no file was recorded here. Coverage reflects the evidence available for this lab.</p><table class="coverage-log"><thead><tr><th>Tool</th><th>Latest status</th><th>Files</th><th>Linked finding groups</th><th>Details</th></tr></thead><tbody>${coverageRows}</tbody></table><p><b>Suggested next review</b> ${escapeHTML(coverage.next.title)} — ${escapeHTML(coverage.next.reason)}</p><h3>File import outcomes</h3>${importLog}`;
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>ScopeWeave VAPT Assessment Report</title><style>
      @page{size:A4;margin:18mm}*{box-sizing:border-box}body{font:11px/1.55 Arial,sans-serif;color:#18222c;margin:0}header{border-bottom:3px solid #188d7b;padding-bottom:14px;margin-bottom:18px}header small{color:#188d7b;font:700 9px monospace;letter-spacing:1.1px}h1{margin:5px 0;font-size:25px}h2{margin:22px 0 8px;padding-bottom:5px;border-bottom:1px solid #cdd8dc;color:#126e67;font-size:15px}h3{margin:16px 0 6px;font-size:12px}p{margin:5px 0}.meta{display:grid;grid-template-columns:150px 1fr;gap:4px 12px;padding:12px;background:#f0f5f4;border-radius:6px}.meta b{color:#50616c}.notice{margin-top:12px;padding:10px;border:1px solid #d8be84;background:#fff9e8;color:#584b2c}.finding{padding:13px 0;border-bottom:1px solid #d4dfe1}.finding h3,.finding h4{break-after:avoid}.finding-review h4{margin:9px 0 3px;color:#28554f}.duplicate-note{padding:7px 9px;border-left:3px solid #514489;background:#ede8f9;color:#3c316b;break-inside:avoid}.trace-provenance{margin:2px 0 0;padding-left:17px}.trace{margin-top:7px;padding:8px;background:#f3f6f7;border-left:3px solid #43a998;overflow-wrap:anywhere}.trace b{color:#28554f}.trace-excerpt{margin:4px 0 0;font:inherit;white-space:pre-wrap;overflow-wrap:anywhere}table{border-collapse:collapse;width:100%;max-width:none;table-layout:fixed;font-size:8px}td,th{padding:6px 8px;border:1px solid #d8e0e2;text-align:left;overflow-wrap:anywhere}th{background:#eff4f4}.ai-analysis{margin:12px 0;padding:10px;border:1px solid #bdced8;background:#f5f8fa}.ai-analysis-heading{font-weight:bold;color:#245b70}.ai-analysis-provenance,.ai-analysis-note{font-size:9px;color:#536a76}.ai-observation{padding:8px 0;border-top:1px solid #cedce3;break-inside:avoid}.ai-limitations{padding:7px;background:#fff8e8}.ai-analysis p{white-space:pre-wrap;overflow-wrap:anywhere}footer{margin-top:24px;padding-top:8px;border-top:1px solid #cdd8dc;color:#667783;font-size:9px}@media print{button{display:none}}
      @media screen{body{background:#f3f1f7;font-size:13px}.report-controls{position:sticky;top:0;z-index:1;display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:10px;padding:12px clamp(14px,4vw,40px);background:#ede8f9;color:#3c316b;border-bottom:1px solid #d3c9e9}.report-controls button{padding:9px 13px;background:#514489;color:#fff;border:0;border-radius:7px;font:inherit;font-weight:bold;cursor:pointer}.report-controls button:focus-visible{outline:2px solid #3c316b;outline-offset:3px}.report-paper{max-width:820px;margin:18px auto;padding:clamp(14px,5vw,38px);background:#fff;overflow-wrap:anywhere}.report-paper table{font-size:11px}}@media print{.report-controls{display:none}}
      .remediation-record{margin:9px 0;padding:8px 10px;border:1px solid #bad6d4;border-left:3px solid #188d7b}.remediation-record h4{margin:0 0 3px;color:#126e67}.remediation-note{white-space:pre-wrap;overflow-wrap:anywhere}
      .finding-triage-record{margin:9px 0;padding:4px 8px;border-left:3px solid #514489;background:#f3f1f7}.finding-triage-record span{white-space:pre-wrap;overflow-wrap:anywhere}
      </style></head><body>
      <div class="report-controls"><b>Report preview · ${escapeHTML(REPORT_MODES[mode])}</b><div><button id="reportPreviewSave" type="button">Save PDF</button> <button id="reportPreviewPrint" type="button">Print</button></div><span id="reportPreviewSaveStatus" role="status"></span></div>
      <main class="report-paper"><header><small>SCOPEWEAVE / EVIDENCE-FIRST VAPT</small><h1>Security Assessment Report</h1><p>Generated ${escapeHTML(new Date().toLocaleString())} · ${escapeHTML(REPORT_MODES[mode])}</p></header>
      <h2>1. Executive summary</h2><p>This report contains ${findings.length} ${findings.length === 1 ? 'finding group' : 'finding groups'} for the registered lab. ${counts.Critical + counts.High} are source-rated High or Critical. Scanner observations, including those marked as false positives by the analyst, are retained for traceability. ${!onlyDuplicates && liveZapRuns ? `${liveZapRuns} local ZAP Spider crawl(s) with passive checks were recorded.` : ''}</p>
      <p class="duplicate-note"><b>Duplicate summary</b> · ${escapeHTML(duplicateSummary)}</p>
      <p><b>Analyst review status for original findings</b> · ${escapeHTML(triageSummary)}</p>
      <p><b>Remediation and retesting</b> · ${escapeHTML(remediationSummary)}</p>
      <h2>2. Scope and authorization</h2><div class="meta"><b>Assessment target</b><span>${escapeHTML(scope.origin)}</span><b>Lab name</b><span>${escapeHTML(scope.label)}</span><b>Authorization basis</b><span>${escapeHTML(authorizationLabel(scope))}</span><b>Authorization reference</b><span>${escapeHTML(scope.approvalReference)}</span><b>Permitted actions</b><span>${escapeHTML(scope.permissions.join(', ') || 'None')}</span><b>Excluded paths</b><span>${escapeHTML(scope.exclusions.join(', ') || 'None')}</span><b>Scope registered</b><span>${escapeHTML(formatDate(scope.createdAt))}</span></div><div class="notice">This is an analyst attestation; the app cannot independently verify local ownership or organizer approval. Imported findings are checked against the registered lab and excluded paths.</div>
      <h2>3. Methodology${onlyDuplicates ? '' : ' and integration matrix'}</h2><p>ZAP uses a bounded Spider crawl and passive checks. Other connected scanners provide report files. ${matchingMethod} One distinct tool is labelled Low agreement. Two or more are labelled Medium agreement.</p>${onlyDuplicates ? '' : `<table class="integration-matrix"><thead><tr><th>Tool or feature</th><th>Status</th><th>Role or limit</th></tr></thead><tbody>${integrationRows}</tbody></table>${planHtml}`}
      ${coverageSection}
      <h2>5. Findings and risk review</h2><p>The project score is calculated only when the source supplied CVSS and the analyst entered all three 0–10 context values: <b>CVSS×0.4 + exposure×0.2 + exploitability×0.2 + asset impact×0.2</b>. It is a review aid; source severity stays visible and is never replaced.</p><h3>Source severity distribution</h3><table><thead><tr><th>Severity</th><th>Finding groups</th></tr></thead><tbody>${severityRows}</tbody></table><h3>Analyst review priority distribution</h3><table><thead><tr><th>Review priority</th><th>Finding groups</th></tr></thead><tbody>${priorityRows}</tbody></table><h3>Detailed findings and evidence traces</h3>${details}
      <h2>6. Approvals and limitations</h2><h3>Human review decisions</h3><ul>${decisions}</ul><p>An approval records the analyst’s decision only. It does not execute a validation.</p><h3>Assessment limitations</h3><ul><li>ZAP may miss routes, authenticated areas, and JavaScript-heavy behavior; passive checks do not test exploitability.</li><li>Nmap, Nessus, Greenbone, Nikto, and Burp adapters only import reports; missing routes or assets may be absent.</li><li>Scanner findings are not independently confirmed. Analyst-entered context is not independently verified.</li><li>Ollama suggestions stay local. Groq analysis sends a bounded evidence summary to its cloud with explicit consent. The report records the provider used and any rule fallback.</li><li>Groq analysis covers only the supplied summary subset. Valid source IDs do not verify the factual accuracy of AI interpretations; compare each explanation with source evidence.</li><li>Local browser storage is not encrypted. Treat the device and exported reports as sensitive.</li></ul>
      <footer>Confidential assessment material · Share only as authorized · ScopeWeave local prototype</footer></main></body></html>`;
  }

  function renderAll() {
    renderAuthorizationControls();
    renderScopeOptions();
    renderFindings();
    renderActivity();
    renderMetrics();
  }

  function bindEvents() {
    $('#enterWorkspace').addEventListener('click', () => {
      try { sessionStorage.setItem('sentinel-desk.entered', 'true'); } catch (_) { /* entry is still available */ }
      showWorkspace();
      $('.nav-item.active')?.focus();
    });
    $('#scopeTrash').addEventListener('click', (event) => {
      const button = event.target.closest('[data-restore-scope]');
      if (button) setScopeTrash(button.dataset.restoreScope, false);
    });
    $$('.nav-item').forEach((button) => button.addEventListener('click', () => navigate(button.dataset.page)));
    $$('[data-goto]').forEach((button) => button.addEventListener('click', () => navigate(button.dataset.goto)));
    $('#planForm').addEventListener('submit', generatePlan);
    $('#plannerProvider').addEventListener('change', () => {
      $('#plannerCloudConsent').checked = false;
      $('#excludeFlaggedText').checked = true;
      renderPlannerControls();
    });
    $('#scopeForm').addEventListener('submit', submitScope);
    $('#scopeAuthorizationType').addEventListener('change', () => {
      $('#scopeAttestation').checked = false;
      $('#scopeReference').value = '';
      renderAuthorizationControls();
    });
    $('#fillJuiceShopScope').addEventListener('click', fillLocalJuiceShopScope);
    $('#zapScanButton').addEventListener('click', scanWithZap);
    $('#coverageRefreshPlanButton').addEventListener('click', () => {
      $('#overviewPlan').open = true;
      generatePlan({ preventDefault() {} });
      $('#overviewPlan').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
    $('#coverageReviewFindingButton').addEventListener('click', (event) => {
      openFindingReference(activeScope()?.id, event.currentTarget.dataset.findingId);
    });
    $('#requestText').addEventListener('input', renderEvidenceCoverage);
    document.addEventListener('submit', (event) => {
      if (event.target.matches('.risk-context-form')) saveRiskContext(event);
    });
    $('#targetSelect').addEventListener('change', (event) => { state.activeScopeId = event.target.value; saveActiveScope(); renderAll(); });
    $('#integrationsImportButton').addEventListener('click', () => openImport(activeScope()?.id));
    $('#fileInput').addEventListener('change', importFiles);
    $('#reportButton').addEventListener('click', openReportOptions);
    $('#reportOptionsForm').addEventListener('submit', previewReport);
    $('#reportOptionsClose').addEventListener('click', () => $('#reportOptionsDialog').close());
    $('#savedPdfsRefresh').addEventListener('click', loadSavedPdfs);
    $('#savedPdfsList').addEventListener('click', (event) => {
      const button = event.target.closest('[data-open-saved-pdf]');
      if (button) openSavedPdf(button);
      const trash = event.target.closest('[data-trash-pdf]');
      if (trash) changeSavedPdfTrash(trash, true);
    });
    $('#savedPdfsTrash').addEventListener('click', (event) => {
      const button = event.target.closest('[data-restore-pdf]');
      if (button) changeSavedPdfTrash(button, false);
    });
    $('#remediationButton').addEventListener('click', openRemediation);
    $('#remediationClose').addEventListener('click', () => $('#remediationDialog').close());
    $('#remediationSelectionForm').addEventListener('submit', selectRemediations);
    $('#remediationFindingSelect').addEventListener('change', renderRemediationDetails);
    $('#remediationForm').addEventListener('submit', saveRemediation);
    $('#retestButton').addEventListener('click', openRetestForm);
    $('#retestForm').addEventListener('submit', saveRetest);
    $('#findingList').addEventListener('click', (event) => {
      const review = event.target.closest('[data-review-finding]');
      if (review) return openFindingReview(review.dataset.reviewFinding);
      const draft = event.target.closest('[data-draft-finding]');
      if (draft) openBugReport(draft.dataset.draftFinding);
    });
    $('#findingReviewForm').addEventListener('submit', saveFindingReview);
    $('#findingReviewStatus').addEventListener('change', syncFindingReviewEvidenceRequirement);
    $('#findingReviewClose').addEventListener('click', () => $('#findingReviewDialog').close());
    $('#findingReviewDialog').addEventListener('close', () => {
      state.findingReviewSelection = null;
      $('#findingReviewEvidence').replaceChildren();
    });
    $('#bugReportForm').addEventListener('submit', exportBugReport);
    $('#bugReportClose').addEventListener('click', () => $('#bugReportDialog').close());
    $('#bugReportDialog').addEventListener('close', () => {
      state.bugReportSelection = null;
      $('#bugReportForm').reset();
      $('#bugReportEvidence').replaceChildren();
    });
    $('#severityFilter').addEventListener('change', renderFindings);
    $('#findingSearch').addEventListener('input', renderFindings);
    $('#approvalFinding').addEventListener('change', updateApprovalButtons);
    $('#approvalReason').addEventListener('input', updateApprovalButtons);
    $('#approvalScopeConfirm').addEventListener('change', updateApprovalButtons);
    $('#approveValidation').addEventListener('click', () => saveDecision(true));
    $('#rejectValidation').addEventListener('click', () => saveDecision(false));
    $('#clearActivityButton').addEventListener('click', () => {
      if (!state.activity.length || !window.confirm('Clear this browser’s local activity log?')) return;
      state.activity = [];
      saveStore(KEYS.activity, state.activity);
      renderActivity();
      renderMetrics();
      toast('Local activity log cleared.');
    });
    $('#helpButton').addEventListener('click', () => $('#helpDialog').showModal());
    $('#closeHelp').addEventListener('click', () => $('#helpDialog').close());
    $('#helpDone').addEventListener('click', () => $('#helpDialog').close());
    document.addEventListener('click', (event) => {
      const goto = event.target.closest('[data-goto]');
      if (goto) navigate(goto.dataset.goto);
      if (event.target.closest('[data-print-report]')) openReportOptions();
    });
    document.addEventListener('keydown', (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'p' && !$('#workspace').hidden && activeScope()) {
        event.preventDefault();
        openReportOptions();
      }
    });
    window.addEventListener('storage', (event) => {
      if (event.key === KEYS.scopes || event.key === null) {
        state.scopes = readStore(KEYS.scopes, []);
        renderAll();
      }
      if (event.key === KEYS.remediations || event.key === null) state.remediations = readStore(KEYS.remediations, []);
      if (event.key === KEYS.findingReviews || event.key === null) {
        state.findingReviews = readStore(KEYS.findingReviews, []);
        renderFindingReviewBadges();
        renderEvidenceCoverage();
        renderPlannerWarnings(activeScope());
      }
    });
  }

  function showWorkspace() {
    $('#workspaceEntry').hidden = true;
    $('#workspace').hidden = false;
  }

  bindEvents();
  renderAll();
  try { if (sessionStorage.getItem('sentinel-desk.entered') === 'true') showWorkspace(); } catch (_) { /* show entry */ }
})();
