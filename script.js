(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const tabs = [...document.querySelectorAll('.tab[data-tab]')];
  const panels = [...document.querySelectorAll('.upload-surface[data-panel]')];
  const form = $('scan-form');
  const fileInput = $('file-upload');
  const appInput = $('app-upload');
  const urlInput = $('website-url');
  const reportButton = $('download-report');
  const riskBadge = $('risk-badge');
  const meter = $('score-meter');
  const themeToggle = $('theme-toggle');
  const maxBytes = 25 * 1024 * 1024;

  let activeTab = 'file';
  let reported = false;
  let currentReport = null;
  const selectedFiles = { file: null, app: null };

  function setText(id, value) {
    const el = $(id);
    if (el) el.textContent = value;
  }

  function updateBadge(kind, label) {
    riskBadge.textContent = label;
    riskBadge.className = `risk-badge ${kind}`;
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes)) return 'Not available';
    if (bytes < 1024) return `${bytes} B`;

    const units = ['KB', 'MB', 'GB'];
    let value = bytes / 1024;
    let unitIndex = 0;

    while (value >= 1024 && unitIndex < units.length - 1) {
      value /= 1024;
      unitIndex += 1;
    }

    return `${value.toFixed(1)} ${units[unitIndex]}`;
  }

  function setTab(name) {
    activeTab = name;
    tabs.forEach((tab) => {
      const selected = tab.dataset.tab === name;
      tab.classList.toggle('is-active', selected);
      tab.setAttribute('aria-selected', String(selected));
    });

    panels.forEach((panel) => {
      const show = panel.dataset.panel === name;
      panel.classList.toggle('is-visible', show);
      panel.hidden = !show;
    });
  }

  function renderReport(data) {
    setText('threat-score', data.score == null ? '—' : String(data.score));
    setText('malware-type', data.title);
    setText('report-summary', data.summary);
    setText('danger-level', data.level);
    setText('danger-text', data.danger);
    setText('meta-type', data.type || 'Not available');
    setText('meta-size', data.size || 'Not available');
    setText('meta-hash', data.hash || 'Not available');
    setText('meta-source', data.source || 'Not available');
    setText('scan-status', data.status || 'Demo complete');

    const list = $('malware-details');
    list.replaceChildren();
    (data.details || []).forEach((item) => {
      const li = document.createElement('li');
      li.textContent = item;
      list.appendChild(li);
    });

    const impactList = $('device-impact');
    impactList.replaceChildren();
    (data.impact || []).forEach((item) => {
      const li = document.createElement('li');
      li.textContent = item;
      impactList.appendChild(li);
    });

    const score = data.score == null ? 0 : Math.max(0, Math.min(100, Number(data.score)));
    meter.style.width = `${score}%`;

    updateBadge(data.kind || 'neutral', data.level || 'Waiting');
    currentReport = { ...data, generatedAt: new Date().toISOString() };
    reportButton.disabled = false;
    reported = true;
  }

  async function sha256(file) {
    if (!crypto || !crypto.subtle) {
      return 'Browser does not support Web Crypto';
    }

    const buffer = await file.arrayBuffer();
    const digest = await crypto.subtle.digest('SHA-256', buffer);
    return [...new Uint8Array(digest)]
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('');
  }

  function setSelectedFile(kind, file) {
    if (!file) return;
    selectedFiles[kind] = file;
    const panel = document.querySelector(`[data-panel="${kind}"]`);
    if (!panel) return;

    let info = panel.querySelector('.selected-file');
    if (!info) {
      info = document.createElement('p');
      info.className = 'selected-file';
      info.style.marginTop = '12px';
      info.style.color = 'var(--muted)';
      panel.appendChild(info);
    }

    info.textContent = `${file.name} · ${formatBytes(file.size)}`;
  }

  async function reviewFile(file, label) {
    if (!file) {
      setText('scan-status', 'Choose a file or try a sample.');
      updateBadge('warn', 'No file');
      return;
    }

    if (file.size > maxBytes) {
      setText('scan-status', 'File exceeds the 25 MB demo limit.');
      updateBadge('warn', 'Too large');
      return;
    }

    setText('scan-status', 'Calculating local metadata…');
    meter.style.width = '35%';

    let hash = 'Could not calculate hash in this browser';
    try {
      hash = await sha256(file);
    } catch {
      hash = 'Could not calculate hash in this browser';
    }

    renderReport({
      title: 'No malware verdict — demo only',
      score: null,
      level: 'Not scanned',
      kind: 'neutral',
      summary: 'This page calculated local file metadata and a SHA-256 hash in the browser. It did not upload the file, execute it, or perform a real malware check.',
      details: [
        'No antivirus engine or sandbox is connected.',
        'A SHA-256 hash identifies the file, but it is not a safety verdict.',
        'Do not open suspicious files based on this demo alone.'
      ],
      impact: [
        'No behavior analysis was performed.',
        'Use a trusted security product for a real scan and keep unknown files isolated.'
      ],
      danger: 'Unknown. Treat the file as untrusted until a real security product verifies it.',
      type: file.type || label || 'Unknown file type',
      size: formatBytes(file.size),
      hash,
      source: 'File stays in this browser — no upload',
      status: 'Metadata review complete — no real scan performed'
    });
  }

  function reviewUrl(rawUrl) {
    const value = rawUrl.trim();

    if (!value) {
      setText('scan-status', 'Enter a complete URL, such as https://example.com');
      updateBadge('warn', 'Invalid URL');
      return;
    }

    let url;
    try {
      url = new URL(value);
    } catch {
      setText('scan-status', 'URL format is invalid.');
      updateBadge('warn', 'Invalid URL');
      return;
    }

    if (!['http:', 'https:'].includes(url.protocol)) {
      setText('scan-status', 'Only http:// and https:// are supported.');
      updateBadge('warn', 'Unsupported URL');
      return;
    }

    renderReport({
      title: 'URL not scanned — demo only',
      score: null,
      level: 'Not scanned',
      kind: 'neutral',
      summary: `The URL format is valid and its hostname is ${url.hostname}. This page did not fetch the site or perform a live threat lookup.`,
      details: [
        'No retrieval or browser-isolation service is connected.',
        'The page was not fetched; redirects and live content were not inspected.',
        'Never enter credentials on a site you do not trust.'
      ],
      impact: [
        'No page scripts were run or inspected.',
        'A URL alone cannot establish that a site is safe or malicious.'
      ],
      danger: 'Unknown. Treat unfamiliar links cautiously and verify them with a trusted security service.',
      type: 'Website URL',
      size: 'Not applicable',
      hash: 'Not applicable',
      source: url.origin,
      status: 'URL validation complete — no live site analysis performed'
    });
  }

  const sampleReports = {
    file: {
      title: 'Illustrative sample: suspicious downloader',
      score: 82,
      level: 'High · sample only',
      kind: 'warn',
      summary: 'Fictional example showing how a future report might describe downloader behavior. This is not a scan of a real file.',
      details: [
        'Example behavior: attempts to fetch a second-stage payload.',
        'Example behavior: creates an unexpected startup entry.',
        'Illustrative score only — no detector ran.'
      ],
      impact: [
        'A real downloader could fetch additional unwanted software.',
        'Impact depends on the payload and whether it executes.'
      ],
      danger: 'Illustrative example only. It is not evidence that any actual file is malicious.',
      type: 'Example executable',
      size: '2.4 MB · sample',
      hash: 'Example only · no file hash',
      source: 'Built-in fictional sample',
      status: 'Sample report loaded',
    },
    website: {
      title: 'Illustrative sample: possible phishing',
      score: 74,
      level: 'High · sample only',
      kind: 'warn',
      summary: 'Fictional example demonstrating a possible credential-harvesting warning. The page was not visited or inspected.',
      details: [
        'Example signal: a lookalike brand and urgency language.',
        'Example signal: repeated attempts to collect login data.',
        'Illustrative result; no live site analysis occurred.'
      ],
      impact: [
        'A phishing page could steal credentials if entered.',
        'If exposed, change reused passwords and confirm the destination via a trusted source.'
      ],
      danger: 'Illustrative example only. It is not a verdict on a real URL.',
      type: 'Example URL',
      size: 'Not applicable',
      hash: 'Not applicable',
      source: 'Built-in fictional sample',
      status: 'Sample report loaded',
    },
    app: {
      title: 'Illustrative sample: excessive permissions',
      score: 68,
      level: 'Medium · sample only',
      kind: 'warn',
      summary: 'Fictional example describing suspicious app permissions. No app was uploaded or analyzed.',
      details: [
        'Example signal: permissions broader than the app purpose requires.',
        'Example signal: background activity is unusually aggressive.',
        'Illustrative result; no package inspection occurred.'
      ],
      impact: [
        'An invasive app could expose location or personal information.',
        'Review app permissions and install only from trusted sources.'
      ],
      danger: 'Illustrative example only. It is not a verdict on a real app package.',
      type: 'Example app package',
      size: '18 MB · sample',
      hash: 'Example only · no package hash',
      source: 'Built-in fictional sample',
      status: 'Sample report loaded',
    }
  };

  function initCounters() {
    document.querySelectorAll('.stat-number').forEach((el) => {
      const target = Number(el.dataset.target || 0);
      let value = 0;
      const step = Math.max(1, Math.ceil(target / 25));
      const interval = setInterval(() => {
        value += step;
        if (value >= target) {
          value = target;
          clearInterval(interval);
        }
        el.textContent = value;
      }, 28);
    });
  }

  function setupFAQ() {
    document.querySelectorAll('.faq-question').forEach((button) => {
      button.addEventListener('click', () => {
        const item = button.parentElement;
        const wasOpen = item.classList.contains('is-open');

        document.querySelectorAll('.faq-item').forEach((faqItem) => {
          faqItem.classList.remove('is-open');
          faqItem.querySelector('.faq-question').setAttribute('aria-expanded', 'false');
        });

        if (!wasOpen) {
          item.classList.add('is-open');
          button.setAttribute('aria-expanded', 'true');
        }
      });
    });
  }

  tabs.forEach((tab) => {
    tab.addEventListener('click', () => setTab(tab.dataset.tab));
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files && fileInput.files[0]) {
      setSelectedFile('file', fileInput.files[0]);
    }
  });

  appInput.addEventListener('change', () => {
    if (appInput.files && appInput.files[0]) {
      setSelectedFile('app', appInput.files[0]);
    }
  });

  document.querySelectorAll('.upload-surface').forEach((surface) => {
    surface.addEventListener('dragover', (event) => {
      event.preventDefault();
      surface.classList.add('is-dragging');
    });

    surface.addEventListener('dragleave', () => {
      surface.classList.remove('is-dragging');
    });

    surface.addEventListener('drop', (event) => {
      event.preventDefault();
      const file = event.dataTransfer?.files?.[0];
      const kind = surface.dataset.panel;
      if (file && (kind === 'file' || kind === 'app')) {
        setSelectedFile(kind, file);
      }
    });
  });

  document.querySelectorAll('[data-sample]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const type = btn.dataset.sample;
      setTab(type);
      renderReport({ ...sampleReports[type], status: 'Sample report loaded' });
      document.getElementById('analysis').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();

    if (activeTab === 'file') {
      await reviewFile(selectedFiles.file || fileInput.files?.[0], 'File');
    }

    if (activeTab === 'website') {
      reviewUrl(urlInput.value);
    }

    if (activeTab === 'app') {
      await reviewFile(selectedFiles.app || appInput.files?.[0], 'App package');
    }
  });

  reportButton.addEventListener('click', () => {
    if (!currentReport) return;

    const lines = [
      'MALTIX — DEMO SECURITY REPORT',
      'IMPORTANT: This is not a real malware scan or security verdict.',
      `Generated: ${currentReport.generatedAt}`,
      `Result: ${currentReport.title}`,
      `Risk: ${currentReport.level}`,
      `Score: ${currentReport.score == null ? 'Not available' : `${currentReport.score}/100`}`,
      `Type: ${currentReport.type || 'Not available'}`,
      `Size: ${currentReport.size || 'Not available'}`,
      `SHA-256: ${currentReport.hash || 'Not available'}`,
      `Source: ${currentReport.source || 'Not available'}`,
      '',
      currentReport.summary,
      '',
      'Details:',
      ...(currentReport.details || []).map((item) => `- ${item}`),
      '',
      'Potential impact:',
      ...(currentReport.impact || []).map((item) => `- ${item}`),
      '',
      currentReport.danger
    ];

    const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const downloadLink = document.createElement('a');
    downloadLink.href = url;
    downloadLink.download = 'maltix-demo-report.txt';
    downloadLink.click();
    URL.revokeObjectURL(url);
  });

  themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('light-theme');
    const isLight = document.body.classList.contains('light-theme');
    themeToggle.textContent = isLight ? '🌙' : '☀️';
    localStorage.setItem('maltix-theme', isLight ? 'light' : 'dark');
  });

  const savedTheme = localStorage.getItem('maltix-theme');
  if (savedTheme === 'light') {
    document.body.classList.add('light-theme');
    themeToggle.textContent = '🌙';
  }

  document.querySelectorAll('[data-scroll]').forEach((button) => {
    button.addEventListener('click', () => {
      const target = document.getElementById(button.dataset.scroll);
      if (target) {
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });

  setupFAQ();
  initCounters();
  setTab('file');
  updateBadge('neutral', 'Waiting');
  setText('scan-status', 'Ready · demo mode');
  meter.style.width = '0%';
  reportButton.disabled = true;
})();
