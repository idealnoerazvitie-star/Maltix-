(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);

  const tabs = [...document.querySelectorAll('.tab[data-tab]')];
  const panels = [...document.querySelectorAll('.upload-surface[data-panel]')];
  const form = $('scan-form');
  const riskBadge = $('risk-badge');
  const scoreMeter = $('score-meter');
  const reportButton = $('download-report');
  const themeToggle = $('theme-toggle');
  const qaButtons = [...document.querySelectorAll('.faq-question')];
  const statEls = [...document.querySelectorAll('.stat-number')];

  const fileInput = $('file-upload');
  const appInput = $('app-upload');
  const websiteInput = $('website-url');

  let currentReport = null;
  let activeTab = 'file';

  const maxBytes = 25 * 1024 * 1024;

  function setText(id, value) {
    const el = $(id);
    if (el) el.textContent = value;
  }

  function setBadge(type, label) {
    if (!riskBadge) return;
    riskBadge.textContent = label;
    riskBadge.className = `risk-badge ${type}`;
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes <= 0) return 'Not available';
    const units = ['B', 'KB', 'MB', 'GB'];
    let value = bytes;
    let index = 0;
    while (value >= 1024 && index < units.length - 1) {
      value /= 1024;
      index += 1;
    }
    return `${value.toFixed(value >= 10 || index === 0 ? 0 : 1)} ${units[index]}`;
  }

  function setTab(name) {
    activeTab = name;
    tabs.forEach((tab) => {
      const isActive = tab.dataset.tab === name;
      tab.classList.toggle('is-active', isActive);
      tab.setAttribute('aria-selected', String(isActive));
    });

    panels.forEach((panel) => {
      const shouldShow = panel.dataset.panel === name;
      panel.classList.toggle('is-visible', shouldShow);
      panel.hidden = !shouldShow;
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
    setText('scan-status', report.status || 'Demo complete');

    const score = Math.max(0, Math.min(100, Number(report.score ?? 0)));
    scoreMeter.style.width = `${score}%`;
    setBadge(report.badge || 'neutral', report.level || 'Waiting');

    const list = $('malware-details');
    list.innerHTML = '';
    (report.details || []).forEach((entry) => {
      const item = document.createElement('li');
      item.textContent = entry;
      list.appendChild(item);
    });

    const impact = $('device-impact');
    impact.innerHTML = '';
    (report.impact || []).forEach((entry) => {
      const item = document.createElement('li');
      item.textContent = entry;
      impact.appendChild(item);
    });

    currentReport = { ...report, generatedAt: new Date().toISOString() };
    reportButton.disabled = false;
  }

  async function calculateSha256(file) {
    if (!file) return 'Not available';
    const buffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  function setSelectedFile(kind, file) {
    if (!file) return;
    const panel = document.querySelector(`.upload-surface[data-panel="${kind}"]`);
    if (!panel) return;

    const info = panel.querySelector('.selected-file') || document.createElement('p');
    info.className = 'selected-file';
    info.textContent = `${file.name} • ${formatBytes(file.size)}`;
    info.style.marginTop = '12px';
    info.style.color = 'var(--muted)';
    if (!info.parentElement) panel.appendChild(info);
  }

  async function reviewFile(file, label) {
    if (!file) {
      setBadge('warn', 'No file');
      setText('scan-status', 'Choose a file or try a sample.');
      return;
    }

    if (file.size > maxBytes) {
      setBadge('warn', 'Too large');
      setText('scan-status', 'File exceeds the 25 MB demo limit.');
      return;
    }

    const hash = await calculateSha256(file).catch(() => 'Unavailable in this browser');
    renderReport({
      title: 'No malware verdict — demo only',
      score: null,
      level: 'Not scanned',
      badge: 'neutral',
      summary: 'This page reviewed local metadata only. It did not upload the file, sandbox it, or perform a real malware detection step.',
      details: [
        'No real backend sandbox is connected.',
        'The file stayed in the browser for local metadata evaluation.',
        'SHA-256 is only a file identifier, not a safety verdict.'
      ],
      impact: [
        'No behavior analysis was performed.',
        'Treat unknown files as untrusted until verified through official security tooling.'
      ],
      danger: 'Unknown. This demo cannot confirm whether the file is malicious or safe. Use a trusted security analyzer for a real verdict.',
      type: file.type || label || 'Unknown file type',
      size: formatBytes(file.size),
      hash,
      source: 'Local browser-only review',
      status: 'Metadata review complete — no real scan performed'
    });
  }

  function reviewWebsite(urlValue) {
    if (!urlValue.trim()) {
      setBadge('warn', 'Invalid URL');
      setText('scan-status', 'Add a full URL such as https://example.com');
      return;
    }

    try {
      const url = new URL(urlValue);
      if (!['http:', 'https:'].includes(url.protocol)) {
        setBadge('warn', 'Unsupported URL');
        setText('scan-status', 'Only http and https are supported.');
        return;
      }

      renderReport({
        title: 'URL not scanned — demo only',
        score: null,
        level: 'Not scanned',
        badge: 'neutral',
        summary: `The URL format is valid and the host is ${url.hostname}. No live fetch or reputation lookup was performed in this demo.`,
        details: [
          'This page did not request the website content.',
          'No reputation database or web sandbox was consulted.',
          'A valid URL format still does not confirm a site is safe.'
        ],
        impact: [
          'No scripts were executed or inspected.',
          'Unknown websites can still present phishing, scams, or malicious content.'
        ],
        danger: 'Unknown. User caution is still required. Verify the destination independently before submitting credentials or downloading files.',
        type: 'Website URL',
        size: 'Not applicable',
        hash: 'Not applicable',
        source: url.origin,
        status: 'URL validation complete — no live site analysis performed'
      });
    } catch {
      setBadge('warn', 'Invalid URL');
      setText('scan-status', 'The URL format is invalid.');
    }
  }

  const sampleReports = {
    file: {
      title: 'Illustrative sample: suspicious downloader',
      score: 82,
      level: 'High · sample only',
      badge: 'warn',
      summary: 'Example risk summary for a fictional downloader. This is not an actual detection result for a real file.',
      details: [
        'Example signal: downloads a second-stage payload.',
        'Example signal: creates unauthorized startup persistence.',
        'Illustrative risk score only — the file was never scanned.'
      ],
      impact: [
        'Example outcome: unwanted software installation or credential theft.',
        'Impact depends on the actual payload and execution context.'
      ],
      danger: 'This is a demonstration only. It should not be treated as a real security verdict.',
      type: 'Sample executable',
      size: '2.4 MB',
      hash: 'Sample only · no real hash',
      source: 'Built-in fictional report',
      status: 'Sample report loaded'
    },
    website: {
      title: 'Illustrative sample: phishing risk',
      score: 74,
      level: 'High · sample only',
      badge: 'warn',
      summary: 'Example warning for a fake login page intended to imitate a trusted service.',
      details: [
        'Example signal: mimicry of a known brand and login flow.',
        'Example signal: request for credentials and MFA codes.',
        'Illustrative detection pattern only — no live URL analysis occurred.'
      ],
      impact: [
        'Credential theft or account takeover risk.',
        'Victims could lose access to email, banking, or internal systems.'
      ],
      danger: 'This is not a real verdict for any live website. It is only an example report.',
      type: 'Sample website',
      size: 'Not applicable',
      hash: 'Not applicable',
      source: 'Built-in fictional report',
      status: 'Sample report loaded'
    },
    app: {
      title: 'Illustrative sample: excessive permissions',
      score: 68,
      level: 'Medium · sample only',
      badge: 'warn',
      summary: 'Example review for an app package requesting permissions that are broader than expected for its purpose.',
      details: [
        'Example signal: background access and location usage.',
        'Example signal: hidden activity on install or startup.',
        'Illustrative sample only — no app package was inspected.'
      ],
      impact: [
        'Potential privacy or behavioral risk from background monitoring.',
        'Apps with broad access should be reviewed with a real security workflow.'
      ],
      danger: 'This is only a mock scenario, not a real app security report.',
      type: 'Sample app package',
      size: '18 MB',
      hash: 'Sample only · no real hash',
      source: 'Built-in fictional report',
      status: 'Sample report loaded'
    }
  };

  document.querySelectorAll('.tab[data-tab]').forEach((tab) => {
    tab.addEventListener('click', () => setTab(tab.dataset.tab));
  });

  fileInput.addEventListener('change', (event) => {
    const file = event.target.files?.[0];
    if (file) setSelectedFile('file', file);
  });

  appInput.addEventListener('change', (event) => {
    const file = event.target.files?.[0];
    if (file) setSelectedFile('app', file);
  });

  document.querySelectorAll('.sample-button').forEach((button) => {
    button.addEventListener('click', () => {
      const key = button.dataset.sample;
      setTab(key);
      renderReport(sampleReports[key]);
      document.getElementById('analysis').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();

    if (activeTab === 'file') {
      const file = fileInput.files?.[0];
      await reviewFile(file, 'File');
    }

    if (activeTab === 'website') {
      reviewWebsite(websiteInput.value);
    }

    if (activeTab === 'app') {
      const file = appInput.files?.[0];
      await reviewFile(file, 'App package');
    }
  });

  reportButton.addEventListener('click', () => {
    if (!currentReport) return;

    const content = [
      'MALTIX DEMO REPORT',
      'This is not a real malware verdict.',
      `Generated: ${new Date(currentReport.generatedAt).toLocaleString()}`,
      `Result: ${currentReport.title}`,
      `Risk: ${currentReport.level}`,
      `Type: ${currentReport.type || 'Not available'}`,
      `Size: ${currentReport.size || 'Not available'}`,
      `Hash: ${currentReport.hash || 'Not available'}`,
      `Source: ${currentReport.source || 'Not available'}`,
      '',
      currentReport.summary,
      '',
      'Key details:',
      ...(currentReport.details || []).map((item) => `- ${item}`),
      '',
      'Potential impact:',
      ...(currentReport.impact || []).map((item) => `- ${item}`),
      '',
      currentReport.danger
    ].join('\n');

    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'maltix-demo-report.txt';
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  });

  qaButtons.forEach((button) => {
    button.addEventListener('click', () => {
      const item = button.closest('.faq-item');
      const opened = item.classList.contains('is-open');

      document.querySelectorAll('.faq-item').forEach((faqItem) => {
        faqItem.classList.remove('is-open');
        faqItem.querySelector('.faq-question').setAttribute('aria-expanded', 'false');
      });

      if (!opened) {
        item.classList.add('is-open');
        button.setAttribute('aria-expanded', 'true');
      }
    });
  });

  themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('light-theme');
    const light = document.body.classList.contains('light-theme');
    themeToggle.textContent = light ? '🌙' : '☀️';
    localStorage.setItem('maltix-theme', light ? 'light' : 'dark');
  });

  const savedTheme = localStorage.getItem('maltix-theme');
  if (savedTheme === 'light') {
    document.body.classList.add('light-theme');
    themeToggle.textContent = '🌙';
  }

  statEls.forEach((stat) => {
    const target = Number(stat.dataset.target || 0);
    let value = 0;
    const interval = setInterval(() => {
      value += Math.max(1, Math.ceil(target / 25));
      if (value >= target) {
        value = target;
        clearInterval(interval);
      }
      stat.textContent = value;
    }, 30);
  });

  setTab('file');
  setBadge('neutral', 'Waiting');
  setText('scan-status', 'Ready · demo mode');
  scoreMeter.style.width = '0%';
  reportButton.disabled = true;
})();
