/*
 * Maltix browser-only demo.
 * It never executes, uploads, or claims to malware-scan submitted content.
 * Files are inspected locally for metadata and SHA-256 only; URLs are parsed, not fetched.
 */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const tabs = [...document.querySelectorAll('.tab[data-tab]')];
  const panels = [...document.querySelectorAll('.upload-surface[data-panel]')];
  const form = $('scan-form');
  const fileInput = $('file-upload');
  const appInput = $('app-upload');
  const websiteInput = $('website-url');
  const riskBadge = $('risk-badge');
  const scoreMeter = $('score-meter');
  const reportButton = $('download-report');
  const themeToggle = $('theme-toggle');
  const maxBytes = 25 * 1024 * 1024;

  let activeTab = 'file';
  let selectedFiles = { file: null, app: null };
  let currentReport = null;
  let operation = 0;

  const setText = (id, value) => {
    const node = $(id);
    if (node) node.textContent = value;
  };

  function setBadge(kind, label) {
    if (!riskBadge) return;
    riskBadge.textContent = label;
    riskBadge.className = `risk-badge ${kind}`;
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes)) return 'Not available';
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return `${(bytes / (1024 ** index)).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
  }

  function setTab(name) {
    if (!['file', 'website', 'app'].includes(name)) return;
    activeTab = name;
    tabs.forEach((tab) => {
      const selected = tab.dataset.tab === name;
      tab.classList.toggle('is-active', selected);
      tab.setAttribute('aria-selected', String(selected));
      tab.setAttribute('tabindex', selected ? '0' : '-1');
    });
    panels.forEach((panel) => {
      const selected = panel.dataset.panel === name;
      panel.classList.toggle('is-visible', selected);
      panel.hidden = !selected;
    });
    setText('scan-status', 'Ready · local demo');
  }

  function renderList(id, entries) {
    const list = $(id);
    if (!list) return;
    list.replaceChildren();
    (entries || []).forEach((entry) => {
      const item = document.createElement('li');
      item.textContent = entry;
      list.appendChild(item);
    });
  }

  function renderReport(report) {
    setText('threat-score', report.score == null ? '—' : String(report.score));
    setText('malware-type', report.title);
    setText('report-summary', report.summary);
    setText('danger-level', report.level);
    setText('danger-text', report.danger);
    setText('meta-type', report.type || 'Not available');
    setText('meta-size', report.size || 'Not available');
    setText('meta-hash', report.hash || 'Not available');
    setText('meta-source', report.source || 'Not available');
    setText('scan-status', report.status || 'Local review complete');
    setBadge(report.badge || 'neutral', report.level || 'Not assessed');

    const score = report.score == null ? 0 : Math.max(0, Math.min(100, Number(report.score) || 0));
    if (scoreMeter) scoreMeter.style.width = `${score}%`;
    renderList('malware-details', report.details);
    renderList('device-impact', report.impact);

    currentReport = { ...report, generatedAt: new Date().toISOString() };
    if (reportButton) reportButton.disabled = false;
  }

  function identifyFile(bytes, file) {
    const b = new Uint8Array(bytes.slice(0, 8));
    const hex = [...b].map((x) => x.toString(16).padStart(2, '0')).join(' ');
    const is = (...values) => values.every((value, index) => b[index] === value);
    let detected = 'Unknown / unrecognized signature';

    if (is(0x4d, 0x5a)) detected = 'Windows PE executable (MZ signature)';
    else if (is(0x7f, 0x45, 0x4c, 0x46)) detected = 'ELF executable';
    else if (is(0x50, 0x4b, 0x03, 0x04) || is(0x50, 0x4b, 0x05, 0x06) || is(0x50, 0x4b, 0x07, 0x08)) detected = 'ZIP-based archive or package';
    else if (is(0x25, 0x50, 0x44, 0x46)) detected = 'PDF document';
    else if (is(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)) detected = 'PNG image';
    else if (is(0xff, 0xd8, 0xff)) detected = 'JPEG image';
    else if (is(0x47, 0x49, 0x46, 0x38)) detected = 'GIF image';
    else if (is(0x52, 0x61, 0x72, 0x21, 0x1a, 0x07)) detected = 'RAR archive';
    else if (is(0x1f, 0x8b)) detected = 'GZIP archive';
    else if (is(0x4f, 0x67, 0x67, 0x53)) detected = 'Ogg media';

    return {
      detected,
      declared: file.type || 'Browser did not provide a MIME type',
      signature: hex || 'Empty file'
    };
  }

  async function calculateSha256(file) {
    if (!globalThis.crypto?.subtle) throw new Error('Secure Web Crypto is unavailable. Use HTTPS or localhost.');
    // The UI limits files to 25 MB before this read, so hashing stays bounded.
    const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
    return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  function rememberFile(kind, file) {
    selectedFiles[kind] = file;
    const panel = document.querySelector(`.upload-surface[data-panel="${kind}"]`);
    if (!panel) return;
    let info = panel.querySelector('.selected-file');
    if (!info) {
      info = document.createElement('p');
      info.className = 'selected-file';
      info.setAttribute('aria-live', 'polite');
      panel.appendChild(info);
    }
    info.textContent = `${file.name} · ${formatBytes(file.size)}`;
    setText('scan-status', 'File selected · ready for local metadata review');
    setBadge('neutral', 'Ready');
  }

  async function reviewFile(file, kind) {
    const thisOperation = ++operation;
    if (!file) {
      setText('scan-status', 'Choose a file or app package, or open a sample report.');
      setBadge('warn', 'No file selected');
      return;
    }
    if (file.size > maxBytes) {
      setText('scan-status', `File is ${formatBytes(file.size)}; the local demo limit is 25 MB.`);
      setBadge('warn', 'File too large');
      return;
    }

    setBadge('neutral', 'Local review');
    setText('scan-status', 'Reading file signature and calculating SHA-256 locally…');
    if (scoreMeter) scoreMeter.style.width = '35%';

    try {
      const bytes = await file.arrayBuffer();
      if (thisOperation !== operation) return;
      const fileInfo = identifyFile(bytes, file);
      const hash = await calculateSha256(file);
      if (thisOperation !== operation) return;

      const extension = file.name.includes('.') ? file.name.split('.').pop().toLowerCase() : 'none';
      const isApp = kind === 'app';
      renderReport({
        title: isApp ? 'App package metadata · not security-scanned' : 'File metadata · not security-scanned',
        score: null,
        level: 'No malware verdict',
        badge: 'neutral',
        summary: `Maltix reviewed basic local metadata only. The file appears to be ${fileInfo.detected}; the browser-reported type is ${fileInfo.declared}. No antivirus or sandbox engine analyzed it.`,
        details: [
          `Detected signature: ${fileInfo.detected}.`,
          `File extension: .${extension}; signature prefix: ${fileInfo.signature}.`,
          'A file signature and SHA-256 hash identify properties; neither proves a file is safe or malicious.'
        ],
        impact: [
          'No code was executed and no behavior analysis was performed.',
          isApp ? 'This app package was not installed or inspected for permissions.' : 'Do not open an unknown file based on this metadata-only result.'
        ],
        danger: 'Unknown. This browser demo cannot determine whether the file or app contains malware. Use a reputable security product or isolated professional analysis.',
        type: `${fileInfo.detected} · ${fileInfo.declared}`,
        size: formatBytes(file.size),
        hash,
        source: 'Processed locally in this browser; no upload',
        status: 'Local metadata complete · no malware scan performed'
      });
    } catch (error) {
      if (thisOperation !== operation) return;
      setText('scan-status', error.message || 'Could not read the file in this browser.');
      setBadge('warn', 'Local review failed');
    }
  }

  function inspectUrl(rawValue) {
    ++operation;
    const value = rawValue.trim();
    if (!value) {
      setText('scan-status', 'Enter a complete URL such as https://example.com.');
      setBadge('warn', 'URL required');
      return;
    }

    let url;
    try {
      url = new URL(value);
    } catch {
      setText('scan-status', 'That URL could not be parsed. Include https:// or http://.');
      setBadge('warn', 'Invalid URL');
      return;
    }

    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname) {
      setText('scan-status', 'Only complete http:// and https:// URLs are accepted.');
      setBadge('warn', 'Unsupported URL');
      return;
    }

    const warnings = [];
    if (url.username || url.password) warnings.push('The URL includes embedded user information; remove it and do not share passwords in links.');
    if (url.hostname === 'localhost' || url.hostname.endsWith('.local') || /^(127\.|10\.|192\.168\.|169\.254\.)/.test(url.hostname)) {
      warnings.push('The hostname appears to be local or private. This demo does not connect to it.');
    }

    renderReport({
      title: 'URL parsed · destination not scanned',
      score: null,
      level: warnings.length ? 'Review URL carefully' : 'Not scanned',
      badge: warnings.length ? 'warn' : 'neutral',
      summary: `The browser parsed ${url.origin}. Maltix did not visit, fetch, resolve, or check this address against any reputation service.`,
      details: [
        `Protocol: ${url.protocol.replace(':', '')}; hostname: ${url.hostname}.`,
        ...warnings,
        'A valid URL format is not evidence that a site is safe.'
      ],
      impact: [
        'No web page content or scripts were inspected.',
        'For a real URL reputation check, use a trusted provider; never enter credentials on an unverified site.'
      ],
      danger: warnings.length ? 'The URL has a caution indicator, but no maliciousness verdict was made.' : 'Unknown. This demo performs URL syntax checks only; it cannot tell whether the destination is safe.',
      type: 'Website URL',
      size: 'Not applicable',
      hash: 'Not applicable',
      source: 'URL parsed locally · no network request',
      status: 'URL syntax review complete · destination not visited'
    });
  }

  const sampleReports = {
    file: {
      title: 'Example report · suspicious downloader', score: 82, level: 'High · fictional sample', badge: 'warn',
      summary: 'This example demonstrates how a real report could describe a suspected downloader. It is fictional and is not a detection for your file.',
      details: ['Example signal: retrieves an additional payload.', 'Example signal: attempts to persist after restart.', 'Illustrative score only; no scanner ran.'],
      impact: ['A real downloader may install unwanted software.', 'Impact depends on the payload and whether it executes.'],
      danger: 'Fictional example only. It is not evidence that any submitted file is infected.',
      type: 'Example executable', size: '2.4 MB · sample', hash: 'Fictional · no hash', source: 'Built-in sample', status: 'Fictional sample loaded'
    },
    website: {
      title: 'Example report · phishing indicators', score: 74, level: 'High · fictional sample', badge: 'warn',
      summary: 'This example shows a possible phishing warning. Maltix did not visit or inspect a website.',
      details: ['Example signal: impersonates a known sign-in page.', 'Example signal: asks for account credentials.', 'Illustrative score only; no reputation service ran.'],
      impact: ['A phishing page could steal credentials entered by a visitor.', 'If credentials were exposed, change them through the official service and enable MFA.'],
      danger: 'Fictional example only. No submitted URL has been evaluated.',
      type: 'Example URL', size: 'Not applicable', hash: 'Not applicable', source: 'Built-in sample', status: 'Fictional sample loaded'
    },
    app: {
      title: 'Example report · app permission concerns', score: 68, level: 'Medium · fictional sample', badge: 'warn',
      summary: 'This example demonstrates how a report might explain excessive app permissions. No package was inspected.',
      details: ['Example signal: permissions broader than the stated purpose.', 'Example signal: background activity should be reviewed.', 'Illustrative score only; no package scanner ran.'],
      impact: ['A privacy-invasive app could collect personal data.', 'Review requested permissions and use official app stores.'],
      danger: 'Fictional example only. It is not a verdict on an actual app.',
      type: 'Example app package', size: '18 MB · sample', hash: 'Fictional · no hash', source: 'Built-in sample', status: 'Fictional sample loaded'
    }
  };

  function downloadReport() {
    if (!currentReport) return;
    const lines = [
      'MALTIX LOCAL DEMO REPORT',
      'This report is not a real malware scan or safety verdict.',
      `Generated: ${currentReport.generatedAt}`,
      `Finding: ${currentReport.title}`,
      `Risk label: ${currentReport.level}`,
      `Type: ${currentReport.type || 'Not available'}`,
      `Size: ${currentReport.size || 'Not available'}`,
      `SHA-256: ${currentReport.hash || 'Not available'}`,
      `Source: ${currentReport.source || 'Not available'}`,
      '', currentReport.summary, '', 'Details:',
      ...(currentReport.details || []).map((item) => `- ${item}`), '', 'Potential impact:',
      ...(currentReport.impact || []).map((item) => `- ${item}`), '', currentReport.danger
    ];
    const objectUrl = URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/plain;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = objectUrl;
    link.download = 'maltix-demo-report.txt';
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
  }

  tabs.forEach((tab) => tab.addEventListener('click', () => setTab(tab.dataset.tab)));
  fileInput?.addEventListener('change', () => fileInput.files?.[0] && rememberFile('file', fileInput.files[0]));
  appInput?.addEventListener('change', () => appInput.files?.[0] && rememberFile('app', appInput.files[0]));

  panels.forEach((panel) => {
    panel.addEventListener('dragover', (event) => {
      event.preventDefault();
      panel.classList.add('is-dragging');
    });
    panel.addEventListener('dragleave', (event) => {
      if (!panel.contains(event.relatedTarget)) panel.classList.remove('is-dragging');
    });
    panel.addEventListener('drop', (event) => {
      event.preventDefault();
      panel.classList.remove('is-dragging');
      const file = event.dataTransfer?.files?.[0];
      const kind = panel.dataset.panel;
      if (file && (kind === 'file' || kind === 'app')) rememberFile(kind, file);
    });
  });

  document.querySelectorAll('[data-sample]').forEach((button) => {
    button.addEventListener('click', () => {
      const kind = button.dataset.sample;
      setTab(kind);
      renderReport(sampleReports[kind]);
      $('analysis')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  form?.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (activeTab === 'file') await reviewFile(selectedFiles.file || fileInput?.files?.[0], 'File');
    if (activeTab === 'app') await reviewFile(selectedFiles.app || appInput?.files?.[0], 'App package');
    if (activeTab === 'website') inspectUrl(websiteInput?.value || '');
  });

  reportButton?.addEventListener('click', downloadReport);

  document.querySelectorAll('.faq-question').forEach((button) => {
    button.addEventListener('click', () => {
      const item = button.closest('.faq-item');
      if (!item) return;
      const willOpen = !item.classList.contains('is-open');
      document.querySelectorAll('.faq-item').forEach((entry) => {
        entry.classList.remove('is-open');
        entry.querySelector('.faq-question')?.setAttribute('aria-expanded', 'false');
      });
      if (willOpen) {
        item.classList.add('is-open');
        button.setAttribute('aria-expanded', 'true');
      }
    });
  });

  themeToggle?.addEventListener('click', () => {
    document.body.classList.toggle('light-theme');
    const light = document.body.classList.contains('light-theme');
    themeToggle.textContent = light ? '🌙' : '☀️';
    try { localStorage.setItem('maltix-theme', light ? 'light' : 'dark'); } catch { /* Storage is optional. */ }
  });

  try {
    if (localStorage.getItem('maltix-theme') === 'light') {
      document.body.classList.add('light-theme');
      if (themeToggle) themeToggle.textContent = '🌙';
    }
  } catch { /* Storage is optional. */ }

  document.querySelectorAll('[data-scroll]').forEach((button) => {
    button.addEventListener('click', () => $(button.dataset.scroll)?.scrollIntoView({ behavior: 'smooth' }));
  });

  document.querySelectorAll('.stat-number').forEach((stat) => {
    const target = Number(stat.dataset.target || 0);
    let value = 0;
    const step = Math.max(1, Math.ceil(target / 25));
    const timer = window.setInterval(() => {
      value = Math.min(target, value + step);
      stat.textContent = String(value);
      if (value >= target) window.clearInterval(timer);
    }, 30);
  });

  setTab('file');
  setBadge('neutral', 'Waiting');
  setText('scan-status', 'Ready · local demo');
  if (scoreMeter) scoreMeter.style.width = '0%';
  if (reportButton) reportButton.disabled = true;
})();
