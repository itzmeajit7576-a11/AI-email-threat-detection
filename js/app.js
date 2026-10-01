/**
 * Inbox Guardian - Core Application Controller
 * Handles SPA navigation, EML upload workflows, animated 8-stage scanner HUD,
 * component rendering, charts, maps, IOC filters, and report generation.
 */

class InboxGuardianApp {
  constructor() {
    this.currentCase = null;
    this.activeIocFilter = 'all';
    this.mapVisualizer = null;

    this.initElements();
    this.bindEvents();
    this.initMap();
    this.handleRoute();

    // Load initial demo on first start so the dashboard & views are immediately populated with high-grade telemetry!
    this.loadCaseData(DEMO_CRITICAL_PHISH, false);
  }

  initElements() {
    // Navigation
    this.navLinks = document.querySelectorAll('.nav-link');
    this.views = document.querySelectorAll('.view-section');
    this.mobileToggle = document.getElementById('mobile-menu-btn');
    this.navMenu = document.getElementById('nav-menu');

    // Upload & Scanner HUD
    this.dropzone = document.getElementById('upload-dropzone');
    this.fileInput = document.getElementById('eml-file-input');
    this.btnBrowse = document.getElementById('btn-browse-file');
    this.btnUploadEml = document.getElementById('btn-upload-eml');
    this.btnTryDemo = document.getElementById('btn-try-demo');
    this.btnTrySafe = document.getElementById('btn-try-safe');
    this.btnTryMalware = document.getElementById('btn-try-malware');
    this.btnPasteRaw = document.getElementById('btn-paste-raw');

    this.scanningHud = document.getElementById('scanning-hud');
    this.scanningBar = document.getElementById('scanning-bar-fill');
    this.stageItems = document.querySelectorAll('.stage-item');

    // System Status Popover
    this.statusPill = document.getElementById('system-status-pill');
    this.statusPopover = document.getElementById('status-popover');

    // Raw modal
    this.rawModal = document.getElementById('raw-paste-modal');
    this.rawTextarea = document.getElementById('raw-eml-textarea');
    this.btnAnalyzeRaw = document.getElementById('btn-analyze-raw-submit');
    this.btnCloseRawModal = document.getElementById('btn-close-raw-modal');

    // Toast Container
    this.toastContainer = document.getElementById('toast-container');
  }

  initMap() {
    this.mapVisualizer = new MapVisualizer('geo-world-map');
  }

  bindEvents() {
    // SPA Hash Routing
    window.addEventListener('hashchange', () => this.handleRoute());

    // Mobile Hamburger
    if (this.mobileToggle && this.navMenu) {
      this.mobileToggle.addEventListener('click', () => {
        this.navMenu.classList.toggle('open');
      });
    }

    // System Status Popover toggle
    if (this.statusPill && this.statusPopover) {
      this.statusPill.addEventListener('click', (e) => {
        e.stopPropagation();
        this.statusPopover.classList.toggle('visible');
      });
      document.addEventListener('click', () => {
        this.statusPopover.classList.remove('visible');
      });
      this.statusPopover.addEventListener('click', (e) => e.stopPropagation());
    }

    // Drag and Drop Upload
    if (this.dropzone && this.fileInput) {
      this.dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        this.dropzone.classList.add('drag-active');
      });

      this.dropzone.addEventListener('dragleave', () => {
        this.dropzone.classList.remove('drag-active');
      });

      this.dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        this.dropzone.classList.remove('drag-active');
        if (e.dataTransfer.files.length > 0) {
          this.handleFileSelected(e.dataTransfer.files[0]);
        }
      });

      this.dropzone.addEventListener('click', () => this.fileInput.click());

      if (this.btnBrowse) {
        this.btnBrowse.addEventListener('click', (e) => {
          e.stopPropagation();
          this.fileInput.click();
        });
      }

      if (this.btnUploadEml) {
        this.btnUploadEml.addEventListener('click', (e) => {
          e.stopPropagation();
          this.fileInput.click();
        });
      }

      this.fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
          this.handleFileSelected(e.target.files[0]);
        }
      });
    }

    // Demo Preset Buttons
    if (this.btnTryDemo) {
      this.btnTryDemo.addEventListener('click', () => {
        this.runScanAnimation(DEMO_CRITICAL_PHISH, "Sample Critical Phishing Email Loaded");
      });
    }

    if (this.btnTrySafe) {
      this.btnTrySafe.addEventListener('click', () => {
        this.runScanAnimation(DEMO_SAFE_CORPORATE, "Sample Safe Corporate Email Loaded");
      });
    }

    if (this.btnTryMalware) {
      this.btnTryMalware.addEventListener('click', () => {
        this.runScanAnimation(DEMO_MALWARE_INVOICE, "Sample Weaponized Invoice Scam Loaded");
      });
    }

    // Raw Modal Handlers
    if (this.btnPasteRaw && this.rawModal) {
      this.btnPasteRaw.addEventListener('click', () => {
        this.rawModal.style.display = 'flex';
      });
    }

    if (this.btnCloseRawModal && this.rawModal) {
      this.btnCloseRawModal.addEventListener('click', () => {
        this.rawModal.style.display = 'none';
      });
    }

    if (this.btnAnalyzeRaw) {
      this.btnAnalyzeRaw.addEventListener('click', () => {
        const text = this.rawTextarea.value.trim();
        if (!text) {
          this.showToast("Please paste email header or body content first.", "error");
          return;
        }
        this.rawModal.style.display = 'none';
        this.processCustomEmailText(text);
      });
    }

    // IOC Filter Tabs
    const iocTabs = document.querySelectorAll('.ioc-tab-btn');
    iocTabs.forEach(btn => {
      btn.addEventListener('click', () => {
        iocTabs.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.activeIocFilter = btn.getAttribute('data-filter') || 'all';
        this.renderIocs();
      });
    });

    // Base64 Decoder Tool in Forensics Workbench
    const btnDecode = document.getElementById('btn-workbench-decode');
    const inputEncoded = document.getElementById('workbench-encoded-input');
    const outputDecoded = document.getElementById('workbench-decoded-output');
    if (btnDecode && inputEncoded && outputDecoded) {
      btnDecode.addEventListener('click', () => {
        const raw = inputEncoded.value.trim();
        if (!raw) return;
        try {
          outputDecoded.value = atob(raw.replace(/\s+/g, ''));
          this.showToast("Decoded Base64 successfully.");
        } catch (e) {
          outputDecoded.value = `[!] Decode Error: ${e.message}. Attempting URL / Quoted-Printable fallback:\n${decodeURIComponent(escape(raw))}`;
        }
      });
    }

    // Threat Intel Search & Severity Filter
    const intelSearch = document.getElementById('intel-search-input');
    const intelSeverity = document.getElementById('intel-severity-filter');
    if (intelSearch && intelSeverity) {
      const filterIntel = () => {
        const q = intelSearch.value.toLowerCase();
        const sev = intelSeverity.value;
        const rows = document.querySelectorAll('.intel-feed-row');
        rows.forEach(r => {
          const text = r.textContent.toLowerCase();
          const rSev = r.getAttribute('data-severity');
          const matchesQ = !q || text.includes(q);
          const matchesSev = sev === 'ALL' || rSev === sev;
          r.style.display = (matchesQ && matchesSev) ? '' : 'none';
        });
      };
      intelSearch.addEventListener('input', filterIntel);
      intelSeverity.addEventListener('change', filterIntel);
    }

    // Report Actions (Print PDF, Export JSON, Copy Summary)
    const btnPrint = document.getElementById('btn-report-print');
    const btnJson = document.getElementById('btn-report-json');
    const btnCopySummary = document.getElementById('btn-report-copy');

    if (btnPrint) {
      btnPrint.addEventListener('click', () => window.print());
    }

    if (btnJson) {
      btnJson.addEventListener('click', () => this.exportJsonReport());
    }

    if (btnCopySummary) {
      btnCopySummary.addEventListener('click', () => this.copyExecutiveSummary());
    }

    // Reduced Motion User Override
    const btnMotionToggle = document.getElementById('reduced-motion-toggle');
    if (btnMotionToggle) {
      btnMotionToggle.addEventListener('click', () => {
        document.body.classList.toggle('reduced-motion');
        const isReduced = document.body.classList.contains('reduced-motion');
        this.showToast(isReduced ? "Anti-gravity animations paused (Reduced Motion)." : "Anti-gravity animations active.");
      });
    }
  }

  handleRoute() {
    const hash = window.location.hash || '#home';
    const targetViewId = hash.replace('#', '') + '-view';

    // Update active nav link
    this.navLinks.forEach(link => {
      const href = link.getAttribute('href');
      link.classList.toggle('active', href === hash);
    });

    // Update view visibility
    let found = false;
    this.views.forEach(view => {
      if (view.id === targetViewId) {
        view.classList.add('active');
        found = true;
      } else {
        view.classList.remove('active');
      }
    });

    if (!found && this.views[0]) {
      this.views[0].classList.add('active');
    }

    if (this.navMenu) {
      this.navMenu.classList.remove('open');
    }

    // Refresh charts if dashboard view became active
    if (hash === '#dashboard' && this.currentCase) {
      setTimeout(() => this.renderCharts(), 50);
    }

    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  handleFileSelected(file) {
    if (!file) return;
    const validExtensions = ['.eml', '.txt', '.msg'];
    const hasValidExt = validExtensions.some(ext => file.name.toLowerCase().endsWith(ext));

    if (!hasValidExt) {
      this.showToast("Unsupported file type. Please upload a valid .EML or .TXT email file.", "error");
      return;
    }

    if (file.size > 25 * 1024 * 1024) {
      this.showToast("File size exceeds 25 MB enterprise limit.", "error");
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      this.processCustomEmailText(content, file.name);
    };
    reader.onerror = () => {
      this.showToast("Failed to read file.", "error");
    };
    reader.readAsText(file);
  }

  async processCustomEmailText(rawContent, filename = "uploaded_email.eml") {
    try {
      this.showScanningHud();
      const report = await apiService.analyzeEmail(rawContent);
      report.eml_filename = filename;
      this.completeScanningAnimation(report);
    } catch (err) {
      this.hideScanningHud();
      this.showToast(`Analysis error: ${err.message}`, "error");
    }
  }

  showScanningHud() {
    if (!this.scanningHud) return;
    this.scanningHud.classList.add('active');
    if (this.scanningBar) this.scanningBar.style.width = '0%';
    this.stageItems.forEach((item, idx) => {
      item.className = 'stage-item';
      const icon = item.querySelector('.stage-status-icon');
      if (icon) icon.textContent = '○ PENDING';
    });
  }

  hideScanningHud() {
    if (this.scanningHud) {
      this.scanningHud.classList.remove('active');
    }
  }

  runScanAnimation(targetCase, toastMessage) {
    this.showScanningHud();
    this.simulateScanSequence(targetCase, toastMessage);
  }

  simulateScanSequence(caseData, toastMessage) {
    const totalStages = this.stageItems.length || 8;
    let current = 0;

    const interval = setInterval(() => {
      if (current < totalStages) {
        // Mark previous as completed
        if (current > 0 && this.stageItems[current - 1]) {
          this.stageItems[current - 1].className = 'stage-item completed';
          const prevIcon = this.stageItems[current - 1].querySelector('.stage-status-icon');
          if (prevIcon) prevIcon.textContent = '✓ COMPLETE';
        }

        // Mark current as active
        if (this.stageItems[current]) {
          this.stageItems[current].className = 'stage-item in-progress';
          const curIcon = this.stageItems[current].querySelector('.stage-status-icon');
          if (curIcon) curIcon.textContent = '◉ SCANNING...';
        }

        const pct = Math.round(((current + 1) / totalStages) * 100);
        if (this.scanningBar) this.scanningBar.style.width = `${pct}%`;

        current++;
      } else {
        clearInterval(interval);
        // Mark last as complete
        if (this.stageItems[totalStages - 1]) {
          this.stageItems[totalStages - 1].className = 'stage-item completed';
          const lastIcon = this.stageItems[totalStages - 1].querySelector('.stage-status-icon');
          if (lastIcon) lastIcon.textContent = '✓ COMPLETE';
        }

        setTimeout(() => {
          this.hideScanningHud();
          this.loadCaseData(caseData);
          if (toastMessage) this.showToast(toastMessage);
          window.location.hash = '#analyze';
        }, 350);
      }
    }, 180);
  }

  completeScanningAnimation(caseData) {
    this.simulateScanSequence(caseData, "AI Threat Analysis Complete");
  }

  loadCaseData(caseData, updateHash = true) {
    this.currentCase = caseData;

    // Render all forensic modules
    this.renderRiskMeter();
    this.renderThreatCards();
    this.renderEmailOverview();
    this.renderHeaderForensics();
    this.renderAuthCards();
    this.renderUrlTable();
    this.renderAttachments();
    this.renderIocs();
    this.renderTimeline();
    this.renderReportView();
    this.renderCharts();
    this.renderThreatIntelFeed();
    this.renderForensicsWorkbench();

    // Update map
    if (this.mapVisualizer && caseData.geolocations) {
      this.mapVisualizer.render(caseData.geolocations);
      this.renderInfraCards(caseData.geolocations);
    }

    if (updateHash) {
      window.location.hash = '#analyze';
    }
  }

  // 1. Render Risk Score Gauge & Meter
  renderRiskMeter() {
    if (!this.currentCase) return;
    const r = this.currentCase.risk_evaluation;
    const score = r.score;

    const scoreNum = document.getElementById('risk-score-num');
    const stateBadge = document.getElementById('risk-state-badge');
    const expText = document.getElementById('risk-explanation');
    const evidenceCount = document.getElementById('risk-evidence-count');
    const circleMeter = document.getElementById('risk-circle-meter');
    const scaleSegments = document.querySelectorAll('.scale-segment');

    if (scoreNum) scoreNum.textContent = score;
    if (expText) expText.textContent = r.explanation;
    if (evidenceCount) evidenceCount.textContent = `${r.detected_evidence_count} Critical Indicators Found`;

    // SVG Circle Circumference is 2 * PI * 90 ≈ 565.48
    if (circleMeter) {
      const circumference = 565.48;
      const offset = circumference - (score / 100) * circumference;
      circleMeter.style.strokeDashoffset = offset;

      let strokeColor = '#10b981';
      if (score >= 80) strokeColor = '#dc2626';
      else if (score >= 60) strokeColor = '#ef4444';
      else if (score >= 40) strokeColor = '#f97316';
      else if (score >= 20) strokeColor = '#eab308';
      circleMeter.style.stroke = strokeColor;
    }

    // Set badge style
    if (stateBadge) {
      stateBadge.textContent = r.state;
      stateBadge.className = 'badge';
      if (score >= 80) stateBadge.classList.add('badge-critical');
      else if (score >= 60) stateBadge.classList.add('badge-high');
      else if (score >= 40) stateBadge.classList.add('badge-suspicious');
      else if (score >= 20) stateBadge.classList.add('badge-low');
      else stateBadge.classList.add('badge-safe');
    }

    // Highlight tier segment
    scaleSegments.forEach(seg => seg.classList.remove('active-tier'));
    if (score >= 80 && scaleSegments[4]) scaleSegments[4].classList.add('active-tier');
    else if (score >= 60 && scaleSegments[3]) scaleSegments[3].classList.add('active-tier');
    else if (score >= 40 && scaleSegments[2]) scaleSegments[2].classList.add('active-tier');
    else if (score >= 20 && scaleSegments[1]) scaleSegments[1].classList.add('active-tier');
    else if (scaleSegments[0]) scaleSegments[0].classList.add('active-tier');
  }

  // 2. Render Threat Classification Grid
  renderThreatCards() {
    const container = document.getElementById('threats-grid-container');
    if (!container || !this.currentCase) return;

    const threats = this.currentCase.detected_threats || [];
    if (threats.length === 0) {
      container.innerHTML = `
        <div style="grid-column: 1 / -1; padding: 24px; text-align: center; background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: var(--radius-md);">
          <div style="color: #10b981; font-weight: bold; font-size: 1.1rem; margin-bottom: 6px;">✓ Zero Active Threat Vectors Detected</div>
          <p style="font-size: 0.88rem; color: #94a3b8;">Email passed all algorithmic and heuristic threat checks.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = threats.map((t, idx) => `
      <div class="threat-card-item ${t.severity === 'Critical' ? 'severity-critical' : ''}">
        <div class="threat-card-header">
          <div class="threat-name">
            <span style="color: ${t.severity === 'Critical' ? '#ef4444' : '#f59e0b'};">●</span>
            ${t.name}
          </div>
          <span class="badge ${t.severity === 'Critical' ? 'badge-critical' : 'badge-high'}">${t.severity}</span>
        </div>

        <div class="threat-confidence-row">
          <span>Detection Confidence</span>
          <span style="color: #ffffff; font-weight: bold;">${t.confidence}%</span>
        </div>
        <div class="confidence-bar-track">
          <div class="confidence-bar-fill" style="width: ${t.confidence}%; background: ${t.severity === 'Critical' ? '#ef4444' : 'var(--blue-primary)'};"></div>
        </div>

        <p class="threat-desc">${t.explanation}</p>

        <button class="evidence-details-toggle" onclick="this.nextElementSibling.classList.toggle('expanded'); this.textContent = this.nextElementSibling.classList.contains('expanded') ? '▲ Hide Forensic Evidence' : '▼ View Evidence (${t.evidence.length})'">
          ▼ View Evidence (${t.evidence.length})
        </button>

        <div class="evidence-list">
          ${t.evidence.map(e => `
            <div class="evidence-item">
              <span>›</span>
              <span>${e}</span>
            </div>
          `).join('')}
        </div>
      </div>
    `).join('');
  }

  // 3. Render Email Overview Details
  renderEmailOverview() {
    if (!this.currentCase) return;
    const meta = this.currentCase.email_metadata;

    const fields = [
      { id: 'meta-sender', val: meta.from, isThreat: meta.from.includes('globex-corp-finance.co') },
      { id: 'meta-replyto', val: meta.reply_to, isThreat: meta.reply_to !== 'None specified' && !meta.from.includes(meta.reply_to.split('@')[1] || '---') },
      { id: 'meta-returnpath', val: meta.return_path, isThreat: meta.return_path.includes('.ru') },
      { id: 'meta-recipient', val: meta.to, isThreat: false },
      { id: 'meta-subject', val: meta.subject, isThreat: false },
      { id: 'meta-date', val: meta.date, isThreat: false },
      { id: 'meta-messageid', val: meta.message_id, isThreat: false },
      { id: 'meta-counts', val: `${meta.url_count} URLs | ${meta.attachment_count} Attachments | ${meta.ip_count} IPs`, isThreat: false }
    ];

    fields.forEach(f => {
      const el = document.getElementById(f.id);
      if (el) {
        if (f.isThreat) {
          el.innerHTML = `<span>${f.val}</span> <span class="mismatch-alert-tag">⚠️ Anomalous Divergence</span>`;
        } else {
          el.textContent = f.val;
        }
      }
    });
  }

  // 4. Render Header Forensics & SMTP Relay Nodes
  renderHeaderForensics() {
    if (!this.currentCase) return;
    const h = this.currentCase.header_forensics;

    const origEl = document.getElementById('forensics-origin-ip');
    if (origEl) origEl.textContent = h.originating_ip;

    const chainContainer = document.getElementById('smtp-relay-chain');
    if (chainContainer && h.relay_path) {
      chainContainer.innerHTML = h.relay_path.map((hop, idx) => {
        let nodeClass = 'relay';
        if (idx === 0) nodeClass = 'origin';
        else if (idx === h.relay_path.length - 1) nodeClass = 'dest';
        else if (hop.role && hop.role.includes('Gateway')) nodeClass = 'gateway';

        return `
          <div class="relay-node ${nodeClass}" onclick="inboxGuardianApp.showNodeDetails(${idx})">
            <div class="relay-node-circle">
              <span>H${hop.hop}</span>
            </div>
            <div class="relay-node-title">${hop.role || `Hop ${hop.hop}`}</div>
            <div class="relay-node-sub">${hop.server.split(' ')[0]}</div>
          </div>
        `;
      }).join('');
    }
  }

  showNodeDetails(hopIndex) {
    if (!this.currentCase || !this.currentCase.header_forensics.relay_path) return;
    const hop = this.currentCase.header_forensics.relay_path[hopIndex];
    if (!hop) return;

    this.showToast(`Node ${hop.hop}: ${hop.server} | Delay: ${hop.delay_ms}ms | Security: ${hop.tls}`);
  }

  // 5. Render SPF / DKIM / DMARC
  renderAuthCards() {
    if (!this.currentCase) return;
    const auth = this.currentCase.authentication;

    const renderCard = (proto, data) => {
      const card = document.getElementById(`auth-card-${proto.toLowerCase()}`);
      if (!card) return;

      const isPass = data.status === 'PASS';
      card.className = `auth-card ${isPass ? 'status-pass' : 'status-fail'}`;

      const statusBadge = card.querySelector('.auth-status-badge');
      if (statusBadge) {
        statusBadge.textContent = data.status;
        statusBadge.className = `badge ${isPass ? 'badge-safe' : 'badge-critical'}`;
      }

      const domainEl = card.querySelector('.auth-domain-val');
      if (domainEl) domainEl.textContent = data.domain || 'N/A';

      const alignEl = card.querySelector('.auth-align-val');
      if (alignEl) alignEl.textContent = data.alignment || 'N/A';

      const expEl = card.querySelector('.auth-exp-val');
      if (expEl) expEl.textContent = data.explanation;
    };

    renderCard('spf', auth.spf);
    renderCard('dkim', auth.dkim);
    renderCard('dmarc', auth.dmarc);
  }

  // 6. Render URL & Domain Intelligence
  renderUrlTable() {
    const tbody = document.getElementById('url-intelligence-tbody');
    if (!tbody || !this.currentCase) return;

    const urls = this.currentCase.urls || [];
    if (urls.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #64748b; padding: 20px;">No external URLs found in email body.</td></tr>`;
      return;
    }

    tbody.innerHTML = urls.map(u => `
      <tr>
        <td>
          <span class="url-truncate mono" title="${u.url}">${u.url}</span>
        </td>
        <td class="mono">${u.domain}</td>
        <td><span class="badge ${u.protocol === 'HTTPS' ? 'badge-neutral' : 'badge-high'}">${u.protocol}</span></td>
        <td><span class="badge ${u.suspicion_score > 70 ? 'badge-critical' : (u.suspicion_score > 40 ? 'badge-suspicious' : 'badge-safe')}">${u.reputation}</span></td>
        <td>
          <div style="display: flex; gap: 4px; flex-wrap: wrap;">
            ${u.indicators.map(ind => `<span class="badge badge-neutral" style="font-size: 0.65rem;">${ind}</span>`).join('')}
          </div>
        </td>
        <td>
          <button class="btn btn-outline btn-sm" onclick="navigator.clipboard.writeText('${u.url}'); inboxGuardianApp.showToast('Copied URL to clipboard');">Copy</button>
        </td>
      </tr>
    `).join('');
  }

  // 7. Render Infrastructure Intelligence Cards
  renderInfraCards(geolocations) {
    const container = document.getElementById('infra-cards-list');
    if (!container) return;

    container.innerHTML = geolocations.map(loc => `
      <div class="infra-ip-card">
        <div class="infra-card-header">
          <div class="infra-ip-title">${loc.ip}</div>
          <span class="badge ${loc.risk_score > 60 ? 'badge-critical' : (loc.risk_score > 30 ? 'badge-low' : 'badge-safe')}">${loc.reputation}</span>
        </div>
        <div class="infra-geo-meta">
          <div><strong>Location:</strong> ${loc.city}, ${loc.country} (${loc.latitude.toFixed(2)}, ${loc.longitude.toFixed(2)})</div>
          <div><strong>ISP/ASN:</strong> ${loc.asn} - ${loc.isp}</div>
          <div><strong>Role:</strong> ${loc.organization}</div>
          <div style="font-size: 0.68rem; color: #64748b; margin-top: 4px;">*${loc.disclaimer || 'Approximate BGP Telemetry'}</div>
        </div>
      </div>
    `).join('');
  }

  // 8. Render Attachments
  renderAttachments() {
    const container = document.getElementById('attachments-grid');
    if (!container || !this.currentCase) return;

    const atts = this.currentCase.attachments || [];
    if (atts.length === 0) {
      container.innerHTML = `
        <div style="padding: 20px; background: rgba(15, 23, 42, 0.4); border-radius: var(--radius-md); color: #94a3b8; font-size: 0.9rem;">
          No binary attachments detected in this message.
        </div>
      `;
      return;
    }

    container.innerHTML = atts.map(att => `
      <div class="attachment-card">
        <div class="attachment-icon-box" style="background: ${att.risk_state === 'MALICIOUS' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)'}; border-color: ${att.risk_state === 'MALICIOUS' ? 'rgba(239, 68, 68, 0.35)' : 'rgba(16, 185, 129, 0.35)'}; color: ${att.risk_state === 'MALICIOUS' ? '#ef4444' : '#10b981'};">
          ${att.risk_state === 'MALICIOUS' ? '⚠️' : '📄'}
        </div>
        <div class="attachment-info">
          <div class="attachment-name">${att.filename}</div>
          <div class="attachment-meta">${att.type} • ${att.size} • ${att.mime}</div>
          <span class="badge ${att.risk_state === 'MALICIOUS' ? 'badge-critical' : 'badge-safe'}" style="width: fit-content; margin: 4px 0;">${att.risk_state}</span>
          <div class="attachment-hash">
            <span>SHA-256: ${att.hash_sha256.substring(0, 24)}...</span>
            <button class="btn btn-outline btn-sm" style="padding: 2px 6px; font-size: 0.65rem;" onclick="navigator.clipboard.writeText('${att.hash_sha256}'); inboxGuardianApp.showToast('Copied SHA-256 hash');">Copy Hash</button>
          </div>
        </div>
      </div>
    `).join('');
  }

  // 9. Render Threat Indicators (IOCs)
  renderIocs() {
    const container = document.getElementById('ioc-list-container');
    if (!container || !this.currentCase) return;

    let iocs = this.currentCase.iocs || [];
    if (this.activeIocFilter !== 'all') {
      iocs = iocs.filter(ioc => ioc.type.toLowerCase().includes(this.activeIocFilter.toLowerCase()));
    }

    if (iocs.length === 0) {
      container.innerHTML = `<div style="color: #64748b; padding: 20px;">No indicators matched current filter category.</div>`;
      return;
    }

    container.innerHTML = iocs.map(ioc => `
      <div class="ioc-item-card">
        <div style="display: flex; align-items: center; gap: 8px;">
          <span class="badge badge-neutral">${ioc.type}</span>
          <span class="ioc-val-text" title="${ioc.value}">${ioc.value}</span>
        </div>
        <div style="display: flex; align-items: center; gap: 6px;">
          <span class="badge ${ioc.threat === 'Critical' ? 'badge-critical' : 'badge-high'}">${ioc.threat}</span>
          <button class="btn btn-outline btn-sm" onclick="navigator.clipboard.writeText('${ioc.value}'); inboxGuardianApp.showToast('Copied indicator: ${ioc.value}');">Copy</button>
        </div>
      </div>
    `).join('');
  }

  // 10. Render Forensic Timeline
  renderTimeline() {
    const container = document.getElementById('forensic-timeline-container');
    if (!container || !this.currentCase) return;

    const timeline = this.currentCase.forensic_timeline || [];
    container.innerHTML = timeline.map(event => `
      <div class="timeline-event-item">
        <div class="timeline-event-box">
          <div class="timeline-event-header">
            <span class="timeline-event-title">${event.title}</span>
            <span class="timeline-event-time">${event.time}</span>
          </div>
          <div class="timeline-event-desc">${event.desc}</div>
        </div>
      </div>
    `).join('');
  }

  // 11. Render Forensic Report View
  renderReportView() {
    if (!this.currentCase) return;
    const c = this.currentCase;

    const idEl = document.getElementById('report-case-number');
    const timeEl = document.getElementById('report-timestamp');
    const execSummary = document.getElementById('report-exec-summary');
    const recsGrid = document.getElementById('report-recs-grid');

    if (idEl) idEl.textContent = `CASE ID: ${c.case_id}`;
    if (timeEl) timeEl.textContent = `Generated: ${c.analysis_timestamp}`;
    if (execSummary) {
      execSummary.innerHTML = `
        <p style="margin-bottom: 12px;"><strong>Executive Assessment:</strong> The automated forensic analysis evaluated message <em>"${c.email_metadata.subject}"</em> from <code>${c.email_metadata.from}</code> with an aggregate Threat Score of <strong>${c.risk_evaluation.score}/100 (${c.risk_evaluation.state})</strong>.</p>
        <p>${c.risk_evaluation.explanation}</p>
      `;
    }

    if (recsGrid && c.recommendations) {
      recsGrid.innerHTML = c.recommendations.map(rec => `
        <div class="rec-card">
          <div class="rec-card-title">${rec.title}</div>
          <div class="rec-card-desc">${rec.desc}</div>
        </div>
      `).join('');
    }
  }

  // 12. Render Dashboard Charts
  renderCharts() {
    if (!this.currentCase) return;
    const c = this.currentCase;

    // 1. Radar Chart: Threat categories exposure
    const categories = {
      'Phishing': c.risk_evaluation.breakdown.domain_reputation || 85,
      'BEC / Fraud': c.risk_evaluation.breakdown.content_urgency || 90,
      'Malware': c.risk_evaluation.breakdown.attachment_risk || 95,
      'Spoofing': c.risk_evaluation.breakdown.authentication_failure || 88,
      'Bad Links': c.risk_evaluation.breakdown.link_suspicion || 82,
      'Credentials': 92
    };
    CyberCharts.renderRadarChart('chart-threat-categories', categories);

    // 2. Risk Distribution Bar Chart
    const dist = {
      'Safe (0-19)': 68,
      'Low (20-39)': 14,
      'Suspicious': 9,
      'High Risk': 6,
      'Critical': 3
    };
    CyberCharts.renderRiskBarChart('chart-risk-distribution', dist);

    // 3. Auth Donut
    const authStatus = {
      pass: c.authentication.spf.status === 'PASS' ? 1 : 0 + (c.authentication.dkim.status === 'PASS' ? 1 : 0) + (c.authentication.dmarc.status === 'PASS' ? 1 : 0),
      fail: c.authentication.spf.status === 'FAIL' ? 1 : 0 + (c.authentication.dkim.status === 'FAIL' ? 1 : 0) + (c.authentication.dmarc.status === 'FAIL' ? 1 : 0),
      neutral: 0
    };
    if (authStatus.pass === 0 && authStatus.fail === 0) authStatus.fail = 3;
    CyberCharts.renderAuthDonut('chart-auth-donut', authStatus);

    // 4. Activity Line
    CyberCharts.renderScanActivityLine('chart-activity-line');
  }

  // 13. Threat Intelligence Feed View
  renderThreatIntelFeed() {
    const tbody = document.getElementById('threat-intel-tbody');
    if (!tbody) return;

    tbody.innerHTML = GLOBAL_THREAT_FEEDS.map(item => `
      <tr class="intel-feed-row" data-severity="${item.severity.toUpperCase()}">
        <td>
          <span class="mono" style="font-weight: 600; color: #ffffff;">${item.indicator}</span>
        </td>
        <td><span class="badge badge-neutral">${item.type}</span></td>
        <td><span class="badge ${item.severity === 'Critical' ? 'badge-critical' : 'badge-high'}">${item.severity}</span></td>
        <td style="color: #cbd5e1;">${item.category}</td>
        <td style="color: #94a3b8;">${item.source}</td>
        <td class="mono" style="color: #64748b; font-size: 0.75rem;">${item.last_seen}</td>
        <td>
          <span style="font-family: var(--font-mono); font-weight: bold; color: var(--cyan-neon);">${item.confidence}%</span>
        </td>
      </tr>
    `).join('');
  }

  // 14. Forensics Workbench View
  renderForensicsWorkbench() {
    if (!this.currentCase) return;
    const rawHeadersBox = document.getElementById('workbench-raw-headers');
    if (rawHeadersBox) {
      rawHeadersBox.textContent = `Received: from mail-relay4.bulletproof-m247.net (smtp.m247-transit.ro [185.220.101.45])
From: "Johnathan Davis" <ceo@globex-corp-finance.co>
To: "Emily Watson" <emily.watson@globex-corp.com>
Reply-To: transfer-clearance@stealth-wire-service.net
Return-Path: <bounce-agent@bulletproof-relay.ru>
Subject: ${this.currentCase.email_metadata.subject}
Date: ${this.currentCase.email_metadata.date}
Message-ID: ${this.currentCase.email_metadata.message_id}
X-Mailer: ${this.currentCase.email_metadata.mailer}
Authentication-Results: spf=fail; dkim=fail; dmarc=fail`;
    }
  }

  // Export Actions
  exportJsonReport() {
    if (!this.currentCase) return;
    const jsonStr = JSON.stringify(this.currentCase, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `InboxGuardian_Report_${this.currentCase.case_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
    this.showToast("Exported structured JSON forensic report.");
  }

  copyExecutiveSummary() {
    if (!this.currentCase) return;
    const c = this.currentCase;
    const summary = `# INBOX GUARDIAN FORENSIC REPORT: ${c.case_id}
Date: ${c.analysis_timestamp}
Subject: ${c.email_metadata.subject}
From: ${c.email_metadata.from}
Risk Score: ${c.risk_evaluation.score}/100 (${c.risk_evaluation.state})
Confidence: ${c.risk_evaluation.confidence}%

## Detected Threats:
${c.detected_threats.map(t => `- [${t.severity}] ${t.name}: ${t.explanation}`).join('\n')}

## Recommended Actions:
${c.recommendations.map(r => `- ${r.title}: ${r.desc}`).join('\n')}
`;
    navigator.clipboard.writeText(summary);
    this.showToast("Executive Markdown summary copied to clipboard.");
  }

  // Toast Notification System
  showToast(message, type = 'info') {
    if (!this.toastContainer) return;
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `
      <span style="color: ${type === 'error' ? '#ef4444' : 'var(--cyan-neon)'}; font-size: 1.1rem;">
        ${type === 'error' ? '⚠️' : '⚡'}
      </span>
      <span>${message}</span>
    `;
    this.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3200);
  }
}

// Global App Instance
let inboxGuardianApp = null;
window.addEventListener('DOMContentLoaded', () => {
  inboxGuardianApp = new InboxGuardianApp();
});
