const demoReport = {
  repository: 'orchard-api',
  repository_path: 'sample://orchard-api',
  generated_at: '2026-10-26T08:30:00.000Z',
  duration_ms: 1840,
  files_scanned: 248,
  files_skipped: 12,
  dependencies_checked: 18,
  findings_total: 6,
  secrets_found: 2,
  vulnerable_dependencies: 1,
  summary: { critical: 2, high: 1, medium: 2, low: 1, info: 0 },
  notes: [],
  findings: [
    {
      id: 'demo-secret-github', rule_id: 'SECRET-GITHUB-TOKEN', title: 'GitHub token may be exposed',
      severity: 'critical', category: 'secrets', file: '.env', line: 4,
      description: 'A value that resembles a credential was found in repository content. SecretShield stores only redacted evidence.',
      recommendation: 'Revoke or rotate this credential, then load it from a secret manager or an environment variable.',
      evidence: 'GITHUB_TOKEN=[REDACTED]', confidence: 'high',
    },
    {
      id: 'demo-dependency-minimist', rule_id: 'OSV-GHSA-xvch-5gv4-984h', title: 'minimist 1.2.5 · CVE-2021-44906',
      severity: 'high', category: 'dependencies', file: 'package-lock.json', line: null,
      description: 'An older minimist release can be affected by a prototype pollution advisory.',
      recommendation: 'Upgrade minimist to a fixed version (1.2.6).', evidence: 'minimist@1.2.5 (npm)',
      confidence: 'high', url: 'https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h',
    },
    {
      id: 'demo-secret-password', rule_id: 'SECRET-HARDCODED-CREDENTIAL', title: 'Possible hard-coded smtp password',
      severity: 'critical', category: 'secrets', file: 'src/config/mail.py', line: 28,
      description: 'A value that resembles a credential was found in repository content. SecretShield stores only redacted evidence.',
      recommendation: 'Rotate this value if it is active, then read it from an environment variable or secret manager.',
      evidence: 'smtp_password = "[REDACTED]"', confidence: 'high',
    },
    {
      id: 'demo-code-tls', rule_id: 'CODE-TLS-VERIFY-DISABLED', title: 'TLS certificate checks are disabled',
      severity: 'medium', category: 'code', file: 'src/integrations/billing.py', line: 62,
      description: 'TLS certificate checks are disabled here. This can make the application easier to compromise if reachable in production.',
      recommendation: 'Certificate verification is disabled here. Restore verification, or configure a trusted CA bundle for this service.',
      evidence: 'response = requests.get(endpoint, verify=False)', confidence: 'medium',
    },
    {
      id: 'demo-code-cors', rule_id: 'CODE-CORS-WILDCARD', title: 'CORS allows every origin',
      severity: 'medium', category: 'code', file: 'src/app.py', line: 19,
      description: 'CORS allows every origin. This can make the application easier to compromise if reachable in production.',
      recommendation: 'A wildcard origin lets any website make browser requests to this service. Limit access to the origins your app needs.',
      evidence: 'allow_origins = ["*"]', confidence: 'medium',
    },
    {
      id: 'demo-code-eval', rule_id: 'CODE-DYNAMIC-EVAL', title: 'Dynamic code execution is used',
      severity: 'low', category: 'code', file: 'src/tools/formatter.py', line: 41,
      description: 'Dynamic code execution is used. This can make the application easier to compromise if reachable in production.',
      recommendation: 'Review the value passed to eval or exec. Never evaluate content that can be influenced by a user or an external system.',
      evidence: 'result = eval(format_expression)', confidence: 'medium',
    },
  ],
};

const state = { report: demoReport, severity: 'all', query: '', toastTimer: null };
const $ = (selector, parent = document) => parent.querySelector(selector);
const $$ = (selector, parent = document) => [...parent.querySelectorAll(selector)];

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

function iconFor(category) {
  const icons = {
    secrets: '<svg viewBox="0 0 24 24"><circle cx="8" cy="15" r="4.5"/><path d="m11.5 11.5 8-8M16 7l2 2M13 10l2 2"/></svg>',
    dependencies: '<svg viewBox="0 0 24 24"><path d="m12 3 9 16H3l9-16Z"/><path d="M12 9v4M12 16h.01"/></svg>',
    code: '<svg viewBox="0 0 24 24"><path d="m8 8-4 4 4 4M16 8l4 4-4 4M14 5l-4 14"/></svg>',
  };
  return icons[category] || icons.code;
}

function shortPath(path) {
  const parts = String(path || '').replaceAll('\\', '/').split('/');
  return parts.slice(-3).join('/');
}

function renderFinding(finding, index) {
  const expandedId = `detail-${escapeHtml(finding.id || index)}`;
  const severity = SEVERITY_ORDER.includes(finding.severity) ? finding.severity : 'medium';
  const label = CATEGORY_LABELS[finding.category] || 'Code';
  const line = Number.isInteger(finding.line) ? `<span class="location-line">line ${finding.line}</span>` : '';
  const advisory = finding.url && /^https:\/\//i.test(finding.url)
    ? `<a class="finding-advisory-link" href="${escapeHtml(finding.url)}" target="_blank" rel="noreferrer">Read the advisory <svg viewBox="0 0 24 24"><path d="M14 4h6v6M20 4l-9 9"/><path d="M18 13v6a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h6"/></svg></a>`
    : '';
  return `
    <button type="button" class="finding-row" data-id="${escapeHtml(finding.id || index)}" aria-expanded="false" aria-controls="${expandedId}">
      <span class="finding-type-icon ${escapeHtml(finding.category)}">${iconFor(finding.category)}</span>
      <span class="finding-main">
        <span class="finding-title-line"><span class="finding-title">${escapeHtml(finding.title)}</span><span class="finding-rule">${escapeHtml(finding.rule_id)}</span></span>
        <span class="finding-location"><svg viewBox="0 0 24 24"><path d="M6 3.5h8l4 4V20a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4.5a1 1 0 0 1 1-1Z"/><path d="M14 3.5v5h5"/></svg><span>${escapeHtml(shortPath(finding.file))}</span>${line}</span>
      </span>
      <span class="finding-meta"><span class="category-tag">${escapeHtml(label)}</span><span class="severity-tag ${severity}">${severity}</span></span>
      <svg class="row-chevron" viewBox="0 0 24 24"><path d="m7 10 5 5 5-5"/></svg>
    </button>
    <div class="finding-detail" id="${expandedId}" hidden>
      <div class="detail-copy"><strong>What we noticed</strong>${escapeHtml(finding.description)}${finding.evidence ? `<div class="detail-evidence">${escapeHtml(finding.evidence)}</div>` : ''}${advisory}</div>
      <div class="detail-recommendation"><strong>A sensible next step</strong>${escapeHtml(finding.recommendation)}</div>
    </div>`;
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const CATEGORY_LABELS = { secrets: 'Secret', dependencies: 'Dependency', code: 'Code' };

function renderFindings() {
  const findings = state.report.findings || [];
  const filtered = findings.filter((finding) => {
    const severityMatch = state.severity === 'all' || finding.severity === state.severity;
    const haystack = [finding.title, finding.rule_id, finding.file, finding.category, finding.description].join(' ').toLowerCase();
    return severityMatch && haystack.includes(state.query.toLowerCase());
  });
  const list = $('#finding-list');
  if (filtered.length) {
    list.innerHTML = filtered.map(renderFinding).join('');
  } else {
    const noFindings = findings.length === 0;
    list.innerHTML = `<div class="empty-state"><span class="empty-icon"><svg viewBox="0 0 24 24"><path d="m5 12 4.5 4.5L19 7"/></svg></span><strong>${noFindings ? 'Nothing needs your attention.' : 'No findings match this view.'}</strong><p>${noFindings ? 'The checks that completed did not find an issue. A quick human review is still a good habit.' : 'Try another severity or clear your search to see more of this scan.'}</p></div>`;
  }
  const clearFilter = state.severity !== 'all' || state.query !== '';
  $('#clear-filter').hidden = !clearFilter;
  $('#results-caption').textContent = `Showing ${filtered.length} of ${findings.length} finding${findings.length === 1 ? '' : 's'}`;
  const summary = state.report.summary || {};
  $('#nav-count').textContent = String(findings.length);
  $('#total-findings').textContent = String(findings.length);
  $('#heading-count').textContent = String(findings.length);
  $('#tab-all-count').textContent = String(findings.length);
  for (const severity of SEVERITY_ORDER) {
    const count = Number(summary[severity]) || 0;
    const metric = $(`#count-${severity}`);
    if (metric) metric.textContent = String(count);
    const tabMetric = $(`#tab-${severity}-count`);
    if (tabMetric) tabMetric.textContent = String(count);
  }
  $$('.filter-tab').forEach((tab) => tab.classList.toggle('selected', tab.dataset.filterSeverity === state.severity));
  const denominator = Math.max(findings.length, 1);
  for (const severity of SEVERITY_ORDER.slice(0, 4)) {
    const segment = $(`#meter-${severity}`);
    if (segment) segment.style.width = `${(Number(summary[severity]) || 0) / denominator * 100}%`;
  }
  const secretCount = Number(state.report.secrets_found) || 0;
  $('#metric-secrets').textContent = String(secretCount);
  $('#metric-dependencies').textContent = String(Number(state.report.vulnerable_dependencies) || 0);
  $('#metric-code').textContent = String(findings.filter((item) => item.category === 'code').length);
  $('#metric-files').textContent = Number(state.report.files_scanned || 0).toLocaleString();
  $('#metric-secrets-note').textContent = secretCount ? 'Rotate these first' : 'No exposed secrets found';
  const dependencyStatus = state.report.dependency_check_status || (state.report.dependencies_checked ? 'complete' : 'no_locked_dependencies');
  const dependencyNotes = {
    disabled: 'Dependency check turned off',
    no_locked_dependencies: 'No supported lock file found',
    unavailable: 'Advisory service unavailable',
    limit_exceeded: 'Repository is over the package limit',
  };
  $('#metric-dependencies-note').textContent = dependencyStatus === 'complete'
    ? `${Number(state.report.dependencies_checked).toLocaleString()} versions checked`
    : (dependencyNotes[dependencyStatus] || 'Dependency check needs attention');
  $('#metric-code-note').textContent = findings.some((item) => item.category === 'code') ? 'A few things to review' : 'No code concerns found';
  $('#metric-files-note').textContent = `${Number(state.report.files_skipped || 0).toLocaleString()} skipped`;
  $('#repo-name').textContent = state.report.repository || 'Repository';
  $('#repo-meta').textContent = state.report.repository_path?.startsWith('sample://') ? 'Sample repository' : 'Scanned just now';
  $('#repo-card').querySelector('.repo-avatar').textContent = (state.report.repository || 'R').trim().charAt(0).toUpperCase();
  $('#last-scan-title').textContent = state.report.repository_path?.startsWith('sample://') ? 'Sample scan' : state.report.repository;
  $('#last-scan-meta').textContent = `${Number(state.report.files_scanned || 0).toLocaleString()} files · ${Number(state.report.dependencies_found ?? state.report.dependencies_checked ?? 0).toLocaleString()} dependencies`;
  $('#scan-time').textContent = state.report.repository_path?.startsWith('sample://') ? 'Preview' : relativeTime(state.report.generated_at);
  $('#demo-banner').hidden = !state.report.repository_path?.startsWith('sample://');
}

function relativeTime(value) {
  if (!value) return 'Just now';
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return 'Just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return new Date(value).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function showToast(message, isError = false) {
  const toast = $('#toast');
  toast.textContent = message;
  toast.classList.toggle('error', isError);
  toast.classList.add('visible');
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => toast.classList.remove('visible'), 5000);
}

async function scanRepository(event) {
  event.preventDefault();
  const input = $('#repository-path');
  const path = input.value.trim();
  const scope = $('input[name="scan-scope"]:checked').value;
  if (!path) { input.focus(); return; }
  const button = $('#scan-button');
  const progress = $('#scan-progress');
  button.disabled = true;
  $('.button-label', button).textContent = 'Scanning…';
  progress.hidden = false;
  progress.innerHTML = '<span class="spinner" aria-hidden="true"></span><span>Checking files and reading locked dependency versions. This can take a moment…</span>';
  try {
    const response = await fetch('/api/scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path, scope, include_dependencies: $('#dependency-toggle').checked }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'The scan could not be completed.');
    state.report = result;
    state.severity = 'all';
    state.query = '';
    $('#finding-search').value = '';
    renderFindings();
    progress.innerHTML = '<span aria-hidden="true">✓</span><span>Scan complete. Your findings are ready below.</span>';
    const note = result.notes?.length ? ` One note: ${result.notes[0]}` : '';
    showToast(`Scan complete. ${result.findings_total} finding${result.findings_total === 1 ? '' : 's'} across ${Number(result.files_scanned).toLocaleString()} files.${note}`);
    $('#findings-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) {
    showToast(error.message || 'Could not connect to SecretShield. Start the local dashboard with python app.py and try again.', true);
    progress.innerHTML = '<span aria-hidden="true">!</span><span>We couldn’t complete that scan. Check the folder path and try again.</span>';
    return;
  } finally {
    button.disabled = false;
    $('.button-label', button).textContent = scope === 'folder' ? 'Scan folder' : 'Scan repository';
    if (state.report.repository_path?.startsWith('sample://')) progress.hidden = true;
    else setTimeout(() => { progress.hidden = true; }, 4500);
  }
}

function updateScanScope() {
  const isFolder = $('input[name="scan-scope"]:checked').value === 'folder';
  $('#scope-hint').textContent = isFolder
    ? 'No Git repository required; choose any existing folder.'
    : 'Choose a folder inside a Git repository.';
  $('.button-label', $('#scan-button')).textContent = isFolder ? 'Scan folder' : 'Scan repository';
}

function makeSarif(report) {
  const rules = new Map();
  const levels = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
  const results = report.findings.map((finding) => {
    if (!rules.has(finding.rule_id)) rules.set(finding.rule_id, {
      id: finding.rule_id, name: finding.title, shortDescription: { text: finding.title },
    });
    const physicalLocation = { artifactLocation: { uri: finding.file, uriBaseId: '%SRCROOT%' } };
    if (finding.line) physicalLocation.region = { startLine: finding.line };
    return {
      ruleId: finding.rule_id, level: levels[finding.severity] || 'warning',
      message: { text: `${finding.title}: ${finding.description} Fix: ${finding.recommendation}` },
      locations: [{ physicalLocation }],
      properties: { severity: finding.severity, category: finding.category },
    };
  });
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'SecretShield', version: '1.0.0', rules: [...rules.values()] } },
      originalUriBaseIds: { '%SRCROOT%': { uri: './' } }, results,
    }],
  };
}

function downloadReport(format) {
  const report = state.report;
  const payload = format === 'sarif' ? makeSarif(report) : report;
  const filename = `${(report.repository || 'repository').replace(/[^a-zA-Z0-9_-]/g, '-')}-secretshield.${format === 'sarif' ? 'sarif' : 'json'}`;
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  $('#export-popover').hidden = true;
  showToast(`${format.toUpperCase()} report downloaded.`);
}

function openDialog(kind) {
  const dialog = $('#info-dialog');
  const content = $('#dialog-content');
  if (kind === 'integrations') {
    content.innerHTML = `
      <h2 id="dialog-title">Bring SecretShield into your workflow.</h2>
      <p>Run a scan on every pull request, then open the findings right alongside your code in GitHub.</p>
      <pre>permissions:\n  contents: read\n  security-events: write\n\nsteps:\n  - uses: actions/checkout@v7\n  - uses: your-org/secretshield/.github/actions/secretshield@v1\n    with:\n      path: .\n      fail-on: high</pre>
      <p>The composite action and a ready-to-edit workflow are in <strong>.github/</strong>. Create and pin a release tag for your fork, then replace <code>your-org/secretshield</code> above.</p>`;
  } else {
    content.innerHTML = `
      <h2 id="dialog-title">Security checks that feel human.</h2>
      <p>SecretShield looks for common credential formats, a small set of risky code patterns, and advisories for pinned dependencies in popular lock files.</p>
      <p>Source files stay on your computer. If dependency checks are enabled, locked package names and versions are sent to the public OSV API. Findings keep credential values redacted.</p>
      <p>Checks are intentionally focused and can miss issues or report false positives. Review findings in your application context.</p>
      <p><a href="https://osv.dev" target="_blank" rel="noreferrer">About OSV advisories ↗</a></p>`;
  }
  if (!dialog.open) dialog.showModal();
}

$('#scan-form').addEventListener('submit', scanRepository);
$$('input[name="scan-scope"]').forEach((input) => input.addEventListener('change', updateScanScope));
updateScanScope();
$('#finding-search').addEventListener('input', (event) => { state.query = event.target.value.trim(); renderFindings(); });

document.addEventListener('click', (event) => {
  const severityButton = event.target.closest('[data-filter-severity]');
  if (severityButton) {
    state.severity = severityButton.dataset.filterSeverity;
    renderFindings();
    if (severityButton.closest('.severity-legend')) $('#findings-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
    return;
  }

  const row = event.target.closest('.finding-row');
  if (row) {
    const detail = $(`#${CSS.escape(row.getAttribute('aria-controls'))}`);
    const isExpanded = row.getAttribute('aria-expanded') === 'true';
    row.setAttribute('aria-expanded', String(!isExpanded));
    detail.hidden = isExpanded;
    return;
  }

  const exportItem = event.target.closest('[data-export]');
  if (exportItem) { downloadReport(exportItem.dataset.export); return; }

  const action = event.target.closest('[data-action]')?.dataset.action;
  if (action === 'integrations' || action === 'about') { openDialog(action); return; }
  if (action === 'dismiss-demo') { $('#demo-banner').hidden = true; return; }
  if (action === 'close-dialog') { $('#info-dialog').close(); return; }

  const navButton = event.target.closest('[data-scroll]');
  if (navButton) {
    const target = document.getElementById(navButton.dataset.scroll);
    target?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    if (navButton.classList.contains('nav-item')) {
      $$('.nav-item').forEach((item) => item.classList.toggle('active', item === navButton));
    }
    if (navButton.dataset.scroll === 'scan-panel') $('#repository-path').focus({ preventScroll: true });
    return;
  }

  if (!event.target.closest('#export-menu')) $('#export-popover').hidden = true;
});

$('#export-button').addEventListener('click', (event) => {
  event.stopPropagation();
  const popover = $('#export-popover');
  popover.hidden = !popover.hidden;
});

$('#clear-filter').addEventListener('click', () => {
  state.severity = 'all';
  state.query = '';
  $('#finding-search').value = '';
  renderFindings();
});

$('#info-dialog').addEventListener('click', (event) => {
  if (event.target === $('#info-dialog')) $('#info-dialog').close();
});

renderFindings();
