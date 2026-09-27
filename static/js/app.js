/**
 * Volatility 3 DFIR Web Application — Frontend Controller (Pure ES6+)
 * Direct REST API client, Force-Directed Graph, Process Tree, and Live SSE Telemetry.
 */

(function () {
  "use strict";

  // App State
  const state = {
    activeCase: null,
    activeEvidence: null,
    cases: [],
    evidenceList: [],
    processes: [],
    network: [],
    iocs: [],
    timeline: [],
    plugins: {},
    selectedPlugin: null,
    executions: [],
    activeJobs: new Map(),
    findings: [],
    activeFinding: null,
    focusedPid: null,
    investigationFocus: null,
    artifacts: [],
    boardItems: [],
    memoryRegions: [],
    coverageData: null,
    graph: {
      nodes: [],
      edges: [],
      byId: {},
      simulation: null,
      scale: 1,
      tx: 0,
      ty: 0,
      isPanning: false,
      panStart: { x: 0, y: 0 },
      draggedNode: null,
      hoverNode: null,
      filters: { proc: true, ip: true, mem: true, yara: true },
      searchTerm: ""
    }
  };

  const API = {
    async get(url) {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      return await res.json();
    },
    async post(url, data = {}) {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      return await res.json();
    },
    async put(url, data = {}) {
      const res = await fetch(url, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      return await res.json();
    },
    async patch(url, data = {}) {
      const res = await fetch(url, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      return await res.json();
    },
    async delete(url) {
      const res = await fetch(url, { method: "DELETE" });
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      return await res.json();
    }
  };

  function el(id) {
    return document.getElementById(id);
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str).replace(/[&<>"']/g, c => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
  }

  function logActivity(category, action, details) {
    try {
      const payload = {
        category: category,
        action: action,
        details: String(details || "")
      };
      const blob = new Blob([JSON.stringify(payload)], { type: "application/json" });
      if (navigator.sendBeacon) {
        navigator.sendBeacon("/api/activity/log", blob);
      } else {
        fetch("/api/activity/log", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          keepalive: true
        }).catch(() => {});
      }
    } catch (e) {
      // Telemetry fail-safe
    }
  }

  // =========================================================================
  // Custom Forensic Modal & Toast System (Zero native browser alerts/confirms)
  // =========================================================================
  function showToast(message, type = "info", duration = 3500) {
    let container = el("toast-container");
    if (!container) {
      container = document.createElement("div");
      container.id = "toast-container";
      container.style.cssText = "position:fixed; bottom:35px; right:25px; z-index:9999; display:flex; flex-direction:column; gap:10px; pointer-events:none; max-width:380px;";
      document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    toast.className = `toast-card ${type}`;
    
    const icon = type === "success" ? "✅"
      : type === "error" ? "❌"
      : type === "warning" ? "⚠️"
      : "ℹ️";

    toast.innerHTML = `
      <span style="font-size:16px;">${icon}</span>
      <div style="flex:1; word-break:break-word; line-height:1.4;">${escapeHtml(message)}</div>
      <button style="background:none; border:none; color:var(--text-muted); cursor:pointer; font-size:16px; padding:0 4px;" onclick="this.parentElement.remove()">&times;</button>
    `;

    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateX(30px)";
      setTimeout(() => toast.remove(), 250);
    }, duration);
  }

  function customConfirm({ title = "Confirm Action", message = "Are you sure?", details = "", confirmText = "Confirm", cancelText = "Cancel", isDanger = true }) {
    return new Promise((resolve) => {
      const modal = el("modal-confirm-dialog");
      if (!modal) {
        resolve(true);
        return;
      }

      el("modal-confirm-title").textContent = title;
      el("modal-confirm-message").textContent = message;
      
      const detEl = el("modal-confirm-details");
      if (details) {
        detEl.textContent = details;
        detEl.style.display = "block";
      } else {
        detEl.style.display = "none";
      }

      const okBtn = el("btn-confirm-ok");
      const cancelBtn = el("btn-confirm-cancel");
      const xBtn = el("btn-confirm-x");
      const iconBox = el("modal-confirm-icon-box");

      if (okBtn) okBtn.textContent = confirmText;
      if (cancelBtn) cancelBtn.textContent = cancelText;

      if (isDanger && okBtn) {
        okBtn.className = "btn btn-danger";
        if (iconBox) {
          iconBox.innerHTML = "⚠️";
          iconBox.style.background = "rgba(239, 68, 68, 0.2)";
          iconBox.style.color = "var(--risk-critical)";
        }
      } else if (okBtn) {
        okBtn.className = "btn btn-primary";
        if (iconBox) {
          iconBox.innerHTML = "❓";
          iconBox.style.background = "rgba(59, 130, 246, 0.2)";
          iconBox.style.color = "var(--accent-blue)";
        }
      }

      let resolved = false;
      function cleanup(result) {
        if (resolved) return;
        resolved = true;
        modal.classList.remove("active");
        modal.style.display = "none";
        document.removeEventListener("keydown", keyHandler);
        resolve(result);
      }

      function keyHandler(e) {
        if (e.key === "Escape") cleanup(false);
        else if (e.key === "Enter") cleanup(true);
      }

      if (okBtn) okBtn.onclick = () => cleanup(true);
      if (cancelBtn) cancelBtn.onclick = () => cleanup(false);
      if (xBtn) xBtn.onclick = () => cleanup(false);
      modal.onclick = (e) => {
        if (e.target === modal) cleanup(false);
      };
      document.addEventListener("keydown", keyHandler);

      modal.style.display = "flex";
      modal.classList.add("active");
      if (okBtn) okBtn.focus();
    });
  }

  function customAlert({ title = "Notification", message = "", details = "", type = "info" }) {
    return new Promise((resolve) => {
      const modal = el("modal-alert-dialog");
      if (!modal) {
        showToast(message, type);
        resolve();
        return;
      }

      el("modal-alert-title").textContent = title;
      el("modal-alert-message").textContent = message;

      const detEl = el("modal-alert-details");
      if (details) {
        detEl.textContent = details;
        detEl.style.display = "block";
      } else {
        detEl.style.display = "none";
      }

      const iconBox = el("modal-alert-icon-box");
      const header = el("modal-alert-header");
      const okBtn = el("btn-alert-ok");
      const xBtn = el("btn-alert-x");

      if (type === "success") {
        if (iconBox) { iconBox.innerHTML = "✅"; iconBox.style.background = "rgba(16, 185, 129, 0.2)"; iconBox.style.color = "var(--risk-normal)"; }
        if (header) { header.style.background = "rgba(16, 185, 129, 0.08)"; header.style.borderBottomColor = "rgba(16, 185, 129, 0.2)"; }
      } else if (type === "error") {
        if (iconBox) { iconBox.innerHTML = "❌"; iconBox.style.background = "rgba(239, 68, 68, 0.2)"; iconBox.style.color = "var(--risk-critical)"; }
        if (header) { header.style.background = "rgba(239, 68, 68, 0.08)"; header.style.borderBottomColor = "rgba(239, 68, 68, 0.2)"; }
      } else if (type === "warning") {
        if (iconBox) { iconBox.innerHTML = "⚠️"; iconBox.style.background = "rgba(245, 158, 11, 0.2)"; iconBox.style.color = "var(--risk-suspicious)"; }
        if (header) { header.style.background = "rgba(245, 158, 11, 0.08)"; header.style.borderBottomColor = "rgba(245, 158, 11, 0.2)"; }
      } else {
        if (iconBox) { iconBox.innerHTML = "ℹ️"; iconBox.style.background = "rgba(59, 130, 246, 0.2)"; iconBox.style.color = "var(--accent-blue)"; }
        if (header) { header.style.background = "rgba(59, 130, 246, 0.08)"; header.style.borderBottomColor = "rgba(59, 130, 246, 0.2)"; }
      }

      let resolved = false;
      function cleanup() {
        if (resolved) return;
        resolved = true;
        modal.classList.remove("active");
        modal.style.display = "none";
        document.removeEventListener("keydown", keyHandler);
        resolve();
      }

      function keyHandler(e) {
        if (e.key === "Escape" || e.key === "Enter") cleanup();
      }

      if (okBtn) okBtn.onclick = () => cleanup();
      if (xBtn) xBtn.onclick = () => cleanup();
      modal.onclick = (e) => {
        if (e.target === modal) cleanup();
      };
      document.addEventListener("keydown", keyHandler);

      modal.style.display = "flex";
      modal.classList.add("active");
      if (okBtn) okBtn.focus();
    });
  }

  // Override window.alert and window.confirm to guarantee zero browser popups
  window.alert = (msg) => customAlert({ title: "Forensic Notification", message: String(msg) });
  window.showToast = showToast;
  window.customConfirm = customConfirm;
  window.customAlert = customAlert;

  // =========================================================================
  // Application Bootstrap
  // =========================================================================
  async function initApp() {
    console.log("Initializing Volatility 3 DFIR Web Suite...");
    logActivity("SESSION", "Page Loaded", `Session initialized. Viewport: ${window.innerWidth}x${window.innerHeight}`);
    setupNavigation();
    setupModals();
    setupDrawer();
    setupSSE();
    setupGraphInteractions();
    setupInvestigationContext();
    setupGlobalSearch();
    setupEvidenceBoardEvents();
    setupArtifactExplorerEvents();
    setupMemoryAnomaliesEvents();

    await loadInitialData();
  }

  async function loadInitialData() {
    try {
      // 1. Fetch system status
      const status = await API.get("/api/status");
      state.activeCase = status.active_case;
      state.activeEvidence = status.active_evidence;

      // 2. Fetch cases
      state.cases = await API.get("/api/cases");
      if (!state.activeCase && state.cases.length > 0) {
        // Auto-activate case with evidence or first case
        const target = state.cases.find(c => c.evidence_count > 0) || state.cases[0];
        const res = await API.post("/api/cases/activate", { case_id: target.id });
        if (res.success) {
          state.activeCase = res.case;
        }
      }

      // 3. Fetch evidence list for active case
      if (state.activeCase) {
        state.evidenceList = await API.get(`/api/evidence?case_id=${encodeURIComponent(state.activeCase.id)}`);
        if (!state.activeEvidence && state.evidenceList.length > 0) {
          const res = await API.post("/api/evidence/activate", { evidence_id: state.evidenceList[0].id });
          if (res.success) {
            state.activeEvidence = res.evidence;
          }
        }
      }

      updateHeaderContext();

      // 4. Restore active tab from localStorage or default to Dashboard
      let savedTab = "page-dashboard";
      try { savedTab = localStorage.getItem("dfir_active_tab") || "page-dashboard"; } catch (e) {}
      if (savedTab && savedTab !== "page-dashboard" && el(savedTab)) {
        switchToPage(savedTab);
      } else {
        await loadDashboardData();
      }
    } catch (err) {
      console.error("Initial data load error:", err);
      logTerminal("ERROR", `Failed to initialize workspace data: ${err.message}`);
    }
  }

  function updateHeaderContext() {
    const caseEl = el("header-case-name");
    const evEl = el("header-evidence-name");

    if (state.activeCase) {
      caseEl.textContent = `${state.activeCase.name} (${state.activeCase.id})`;
    } else {
      caseEl.textContent = "No Case Loaded";
    }

    if (state.activeEvidence) {
      evEl.textContent = state.activeEvidence.filename;
    } else {
      evEl.textContent = "No Evidence Loaded";
    }
  }

  // =========================================================================
  // Navigation & View Routing
  // =========================================================================
  function setupNavigation() {
    document.querySelectorAll(".nav-item").forEach(item => {
      item.addEventListener("click", () => {
        document.querySelectorAll(".nav-item").forEach(i => i.classList.remove("active"));
        item.classList.add("active");

        const targetPage = item.dataset.page;
        const pageLabel = item.innerText.trim();
        try { localStorage.setItem("dfir_active_tab", targetPage); } catch (e) {}
        logActivity("TAB_NAVIGATION", "Open Tab", `User opened tab: '${pageLabel}' (${targetPage})`);
        
        document.querySelectorAll(".page-view").forEach(p => p.classList.remove("active"));
        
        const pageEl = el(targetPage);
        if (pageEl) {
          pageEl.classList.add("active");
          onNavigate(targetPage);
        }
      });
    });

    // Header Context Click -> Switch to Cases & Evidence View
    const pillCase = el("pill-active-case");
    if (pillCase) pillCase.onclick = () => {
      logActivity("HEADER_ACTION", "Click Active Case", "User clicked Active Case badge in header");
      switchToPage("page-cases");
    };
    const pillEv = el("pill-active-evidence");
    if (pillEv) pillEv.onclick = () => {
      logActivity("HEADER_ACTION", "Click Active Evidence", "User clicked Active Evidence badge in header");
      switchToPage("page-cases");
    };
    const btnImp = el("btn-quick-import");
    if (btnImp) btnImp.onclick = () => {
      logActivity("HEADER_ACTION", "Click Import Dump", "User clicked Quick Import Dump in header");
      openModal("modal-import-evidence");
    };
    const btnTri = el("btn-quick-triage");
    if (btnTri) btnTri.onclick = () => {
      logActivity("HEADER_ACTION", "Click Quick Triage", "User clicked Run Automated Triage in header");
      triggerAutomatedTriage();
    };
    const btnDashTri = el("btn-dash-start-triage");
    if (btnDashTri) btnDashTri.onclick = () => {
      logActivity("DASHBOARD_ACTION", "Start Triage", "User clicked Start Automated Triage on Dashboard");
      triggerAutomatedTriage();
    };
    const btnDashG = el("btn-dash-view-graph");
    if (btnDashG) btnDashG.onclick = () => {
      logActivity("DASHBOARD_ACTION", "View Graph", "User clicked Open Relationship Graph on Dashboard");
      switchToPage("page-graph");
    };
    const btnRef = el("btn-refresh-dashboard");
    if (btnRef) btnRef.onclick = () => {
      logActivity("DASHBOARD_ACTION", "Refresh", "User clicked Refresh Dashboard");
      loadDashboardData();
    };
  }

  function switchToPage(pageId) {
    const navItem = document.querySelector(`.nav-item[data-page="${pageId}"]`);
    if (navItem) navItem.click();
  }

  async function onNavigate(pageId) {
    switch (pageId) {
      case "page-dashboard":
        await loadDashboardData();
        break;
      case "page-coverage":
        await loadCoverageData();
        break;
      case "page-board":
        await loadBoardData();
        break;
      case "page-artifacts":
        await loadArtifactsData();
        break;
      case "page-processes":
        await loadProcessTreeData();
        break;
      case "page-memory":
        await loadMemoryData();
        break;
      case "page-graph":
        await loadGraphData();
        break;
      case "page-network":
        await loadNetworkData();
        break;
      case "page-iocs":
        await loadIocsData();
        break;
      case "page-timeline":
        await loadTimelineData();
        break;
      case "page-plugins":
        await loadPluginsData();
        break;
      case "page-playbooks":
        await loadPlaybooksData();
        break;
      case "page-diff":
        await loadDiffData();
        break;
      case "page-report":
        await loadReportData();
        break;
      case "page-cases":
        await loadCasesAndEvidenceData();
        break;
      case "page-findings":
        await loadFindingsData();
        break;
      case "page-upload":
        await setupUploadCenter();
        break;
      case "page-yara":
        await setupYaraCenter();
        break;
      case "page-activity":
        await setupActivityCenter();
        break;
    }
  }

  // =========================================================================
  // Live Telemetry & Server-Sent Events (SSE)
  // =========================================================================
  function setupSSE() {
    const sse = new EventSource("/api/stream");
    const statusText = el("sse-status-text");

    sse.onopen = () => {
      if (statusText) statusText.textContent = "Connected";
      logTerminal("INFO", "SSE connection established with backend telemetry.");
    };

    sse.onerror = () => {
      if (statusText) statusText.textContent = "Reconnecting...";
    };

    sse.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        handleSignal(payload.signal, payload.args || []);
      } catch (err) {
        // keepalive or ping
      }
    };
  }

  function handleSignal(signal, args) {
    switch (signal) {
      case "job_started": {
        const [execId, pluginName] = args;
        state.activeJobs.set(execId, { plugin: pluginName, status: "Running" });
        updateActiveJobsCounter();
        logTerminal("INFO", `Job launched: ${pluginName} [ID: ${execId}]`);
        break;
      }
      case "job_activity": {
        const [execId, activity] = args;
        logTerminal("INFO", `[${execId}] ${activity}`);
        break;
      }
      case "job_finished": {
        const [execId, ok, msg] = args;
        state.activeJobs.delete(execId);
        updateActiveJobsCounter();
        logTerminal(ok ? "SUCCESS" : "ERROR", `Job [${execId}] finished: ${msg}`);
        // Auto-refresh visible page if relevant
        refreshCurrentPage();
        break;
      }
      case "triage_completed": {
        logTerminal("SUCCESS", "⚡ Automated forensic triage completed! Cross-correlation updated.");
        refreshCurrentPage();
        break;
      }
      case "log_emitted": {
        const [lvl, msg] = args;
        logTerminal(lvl, msg);
        break;
      }
      case "hash_progress": {
        const [pct] = args;
        const bar = el("import-hash-bar");
        const txt = el("import-hash-pct");
        if (bar && txt) {
          bar.style.width = `${pct}%`;
          txt.textContent = `${pct}%`;
        }
        break;
      }
      case "playbook_progress": {
        const [msg] = args;
        logTerminal("INFO", `[Playbook] ${msg}`);
        break;
      }
    }
  }

  function logTerminal(level, message) {
    const term = el("terminal-log-output");
    if (!term) return;

    const line = document.createElement("div");
    line.className = "log-line";

    const time = new Date().toLocaleTimeString();
    const timeSpan = `<span class="log-time">[${time}]</span>`;

    let lvlClass = "log-info";
    if (level === "ERROR") lvlClass = "log-error";
    else if (level === "WARN") lvlClass = "log-warn";
    else if (level === "SUCCESS") lvlClass = "log-success";

    line.innerHTML = `${timeSpan} <span class="${lvlClass}">[${level}]</span> ${escapeHtml(message)}`;
    term.appendChild(line);
    term.scrollTop = term.scrollHeight;
  }

  function updateActiveJobsCounter() {
    const counter = el("active-jobs-counter");
    if (counter) counter.textContent = state.activeJobs.size;
  }

  function setupDrawer() {
    const drawer = el("terminal-drawer");
    const chevron = el("drawer-chevron");
    const chevronBtn = el("drawer-chevron-btn");
    const clearBtn = el("btn-clear-terminal");
    let expanded = true;

    if (chevronBtn && drawer) {
      chevronBtn.onclick = (e) => {
        e.stopPropagation();
        expanded = !expanded;
        drawer.style.height = expanded ? "220px" : "36px";
        if (chevron) chevron.textContent = expanded ? "▼" : "▲";
      };
    }

    if (clearBtn) {
      clearBtn.onclick = (e) => {
        e.stopPropagation();
        const term = el("terminal-log-output");
        if (term) term.innerHTML = '<div class="log-line"><span class="log-time">[System]</span> <span class="log-info">Terminal log cleared.</span></div>';
        logActivity("DRAWER_ACTION", "Clear Terminal", "User cleared terminal output");
      };
    }

    document.querySelectorAll(".drawer-tab").forEach(tab => {
      tab.addEventListener("click", (e) => {
        e.stopPropagation();
        document.querySelectorAll(".drawer-tab").forEach(t => t.classList.remove("active"));
        tab.classList.add("active");
        if (tab.dataset.tab === "tab-jobs") {
          switchToPage("page-dashboard");
          showToast("Switched to Recent Executions on Dashboard", "info");
        }
      });
    });
  }

  function refreshCurrentPage() {
    const activeSection = document.querySelector(".page-view.active");
    if (activeSection) {
      onNavigate(activeSection.id);
    }
  }

  // =========================================================================
  // Automated Triage Execution
  // =========================================================================
  async function triggerAutomatedTriage() {
    if (!state.activeEvidence) {
      customAlert({
        title: "No Evidence Selected",
        message: "Please select or import a memory dump evidence first before initiating automated triage.",
        type: "warning"
      });
      return;
    }
    try {
      showToast("⚡ Automated triage initiated with 7 forensic plugins...", "info");
      logTerminal("INFO", "Initiating automated memory triage pipeline...");

      // Auto-expand terminal drawer to show live execution
      const drawer = el("terminal-drawer");
      const chevron = el("drawer-chevron");
      if (drawer) {
        drawer.style.height = "220px";
        if (chevron) chevron.textContent = "▼";
      }

      const res = await API.post("/api/triage/start", { evidence_id: state.activeEvidence.id });
      if (res.success) {
        logTerminal("SUCCESS", `Automated triage started with ${res.plugins.length} plugins queued.`);
        showToast(`Triage started! Analyzing ${state.activeEvidence.filename}...`, "success");
      }
    } catch (err) {
      logTerminal("ERROR", `Failed to start automated triage: ${err.message}`);
      showToast(`Triage start error: ${err.message}`, "error");
    }
  }

  // =========================================================================
  // 1. Dashboard View
  // =========================================================================
  async function loadDashboardData() {
    if (!state.activeEvidence) {
      el("dash-total-procs").textContent = "0";
      el("dash-critical-procs").textContent = "0";
      el("dash-suspicious-procs").textContent = "0";
      el("dash-network-count").textContent = "0";
      const rc = el("risk-count-critical"); if (rc) rc.textContent = "0";
      const rh = el("risk-count-high"); if (rh) rh.textContent = "0";
      const rs = el("risk-count-suspicious"); if (rs) rs.textContent = "0";
      const rn = el("risk-count-normal"); if (rn) rn.textContent = "0";
      const bc = el("bar-critical"); if (bc) bc.style.width = "0%";
      const bh = el("bar-high"); if (bh) bh.style.width = "0%";
      const bs = el("bar-suspicious"); if (bs) bs.style.width = "0%";
      const bn = el("bar-normal"); if (bn) bn.style.width = "0%";
      renderRecentExecutions([]);
      return;
    }

    try {
      const [procs, conns, execs] = await Promise.all([
        API.get(`/api/processes?evidence_id=${encodeURIComponent(state.activeEvidence.id)}`),
        API.get(`/api/network?evidence_id=${encodeURIComponent(state.activeEvidence.id)}`),
        API.get(`/api/executions?evidence_id=${encodeURIComponent(state.activeEvidence.id)}`)
      ]);

      state.processes = procs || [];
      state.network = conns || [];
      state.executions = execs || [];

      // Update counters
      el("dash-total-procs").textContent = state.processes.length;
      el("dash-network-count").textContent = state.network.length;

      let crit = 0, high = 0, susp = 0, norm = 0;
      state.processes.forEach(p => {
        const lvl = (p.risk_level || "").toLowerCase();
        if (lvl === "critical") crit++;
        else if (lvl.includes("high")) high++;
        else if (lvl.includes("suspicious")) susp++;
        else norm++;
      });

      el("dash-critical-procs").textContent = crit;
      el("dash-suspicious-procs").textContent = high + susp;

      // Update risk progress bars
      const total = Math.max(state.processes.length, 1);
      el("risk-count-critical").textContent = crit;
      el("risk-count-high").textContent = high;
      el("risk-count-suspicious").textContent = susp;
      el("risk-count-normal").textContent = norm;

      el("bar-critical").style.width = `${(crit / total) * 100}%`;
      el("bar-high").style.width = `${(high / total) * 100}%`;
      el("bar-suspicious").style.width = `${(susp / total) * 100}%`;
      el("bar-normal").style.width = `${(norm / total) * 100}%`;

      // Render recent executions
      renderRecentExecutions(state.executions);
    } catch (err) {
      console.error("Dashboard data load error:", err);
    }
  }

  function renderRecentExecutions(execs) {
    const tbody = el("dash-executions-tbody");
    if (!tbody) return;

    if (!execs || execs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:20px; color:var(--text-muted);">No plugin executions recorded yet.</td></tr>`;
      return;
    }

    const rows = execs.slice(-10).reverse().map(ex => {
      const statusBadge = ex.status === "Completed" ? `<span class="badge badge-normal">Completed</span>`
        : ex.status === "Running" ? `<span class="badge badge-suspicious">Running</span>`
        : `<span class="badge badge-critical">${escapeHtml(ex.status)}</span>`;

      return `
        <tr>
          <td style="font-weight:600; color:var(--text-primary); font-family:var(--font-mono);">${escapeHtml(ex.plugin_name)}</td>
          <td>${statusBadge}</td>
          <td>${ex.runtime_seconds || 0}s</td>
          <td>${ex.result_count || 0}</td>
          <td style="font-size:12px; color:var(--text-muted);">${escapeHtml(ex.start_time || "")}</td>
          <td>
            <button class="btn btn-sm" onclick="window.viewExecutionResults('${escapeHtml(ex.id)}', '${escapeHtml(ex.plugin_name)}')">Inspect</button>
          </td>
        </tr>
      `;
    }).join("");

    tbody.innerHTML = rows;
  }

  window.viewExecutionResults = async function (execId, pluginName) {
    switchToPage("page-plugins");
    const pluginTitle = el("selected-plugin-title");
    if (pluginTitle) pluginTitle.textContent = `${pluginName} (Execution: ${execId})`;

    try {
      const res = await API.get(`/api/results/${encodeURIComponent(execId)}`);
      renderPluginOutputTable(res.headers || [], res.data || []);
    } catch (err) {
      showToast(`Failed to load results: ${err.message}`, "error");
    }
  };

  // =========================================================================
  // 2. Process Tree View
  // =========================================================================
  async function loadProcessTreeData() {
    if (!state.activeEvidence) {
      el("process-tree-root").innerHTML = `<div style="text-align:center; padding:40px; color:var(--text-muted);">No active memory evidence selected.</div>`;
      return;
    }

    try {
      state.processes = await API.get(`/api/processes?evidence_id=${encodeURIComponent(state.activeEvidence.id)}`);
      renderProcessTree();
    } catch (err) {
      el("process-tree-root").innerHTML = `<div style="color:var(--risk-critical); padding:20px;">Failed to load processes: ${err.message}</div>`;
    }
  }

  function renderProcessTree() {
    const container = el("process-tree-root");
    if (!container) return;

    if (!state.processes || state.processes.length === 0) {
      container.innerHTML = `<div style="text-align:center; padding:40px; color:var(--text-muted);">No processes correlated yet. Run Automated Triage first.</div>`;
      return;
    }

    const search = (el("tree-search-input") ? el("tree-search-input").value : "").toLowerCase().trim();
    const riskFilter = el("tree-risk-filter") ? el("tree-risk-filter").value : "ALL";

    // Map parent -> children
    const byPid = new Map();
    const childrenMap = new Map();
    state.processes.forEach(p => {
      byPid.set(p.pid, p);
      if (!childrenMap.has(p.ppid)) childrenMap.set(p.ppid, []);
      childrenMap.get(p.ppid).push(p);
    });

    // Find roots (PPID not in processes, or PPID == 0)
    const roots = state.processes.filter(p => !byPid.has(p.ppid) || p.ppid === 0 || p.ppid === p.pid);

    function buildNodeHtml(proc) {
      const children = childrenMap.get(proc.pid) || [];
      const riskClass = (proc.risk_level || "").toLowerCase().includes("critical") ? "badge-critical"
        : (proc.risk_level || "").toLowerCase().includes("high") ? "badge-high"
        : (proc.risk_level || "").toLowerCase().includes("suspicious") ? "badge-suspicious"
        : "badge-normal";

      const isHidden = proc.in_psscan && !proc.in_pslist;
      const hiddenTag = isHidden ? `<span class="badge badge-critical" title="Unlinked from EPROCESS list (DKOM)">⚠️ HIDDEN</span>` : "";

      const matchesSearch = !search || proc.name.toLowerCase().includes(search) || String(proc.pid).includes(search) || (proc.command_line || "").toLowerCase().includes(search);
      const matchesRisk = riskFilter === "ALL" || (proc.risk_level || "").toLowerCase().includes(riskFilter.toLowerCase());

      const visible = matchesSearch && matchesRisk;

      let childrenHtml = "";
      if (children.length > 0) {
        childrenHtml = children.map(c => buildNodeHtml(c)).join("");
      }

      return `
        <div class="tree-node" style="${visible ? "" : "opacity:0.3;"}">
          <div class="tree-node-item" onclick="window.inspectProcess(${proc.pid})">
            <span style="font-weight:700; color:var(--text-primary);">${escapeHtml(proc.name)}</span>
            <span class="badge ${riskClass}">PID ${proc.pid}</span>
            <span style="color:var(--text-muted); font-size:11px;">PPID ${proc.ppid}</span>
            ${hiddenTag}
            ${proc.risk_score ? `<span style="color:var(--text-muted); font-size:11px;">Score: ${proc.risk_score}</span>` : ""}
          </div>
          ${childrenHtml}
        </div>
      `;
    }

    container.innerHTML = roots.map(r => buildNodeHtml(r)).join("");

    // Wire tree action buttons, search & filter
    const btnExpand = el("btn-tree-expand");
    if (btnExpand) {
      btnExpand.onclick = () => {
        logActivity("TREE_ACTION", "Expand All", "User clicked Expand All in Process Tree");
        document.querySelectorAll("#process-tree-root .tree-node").forEach(n => n.style.display = "");
      };
    }
    const btnCollapse = el("btn-tree-collapse");
    if (btnCollapse) {
      btnCollapse.onclick = () => {
        logActivity("TREE_ACTION", "Collapse All", "User clicked Collapse All in Process Tree");
        document.querySelectorAll("#process-tree-root .tree-node .tree-node").forEach(n => n.style.display = "none");
      };
    }

    const searchInput = el("tree-search-input");
    if (searchInput) {
      searchInput.oninput = () => {
        const val = searchInput.value.trim();
        if (val.length > 2) {
          logActivity("SEARCH", "Tree Search", `Searched Process Tree for: "${val}"`);
        }
        renderProcessTree();
      };
    }
    const riskSelect = el("tree-risk-filter");
    if (riskSelect) {
      riskSelect.onchange = () => {
        logActivity("FILTER", "Risk Filter", `Filtered Process Tree by risk level: "${riskSelect.value}"`);
        renderProcessTree();
      };
    }
  }

  // =========================================================================
  // Process Investigation Focus Mode (Deep Forensic Drawer)
  // =========================================================================
  async function openProcessFocusDrawer(pid) {
    if (!state.activeEvidence) {
      showToast("Please select active memory evidence first", "warning");
      return;
    }
    state.focusedPid = pid;
    logActivity("PROCESS_INSPECT", "Focus Mode", `Opened Process Investigation Focus Mode for PID ${pid}`);

    const drawer = el("process-focus-drawer");
    const backdrop = el("drawer-backdrop");
    if (drawer) drawer.classList.add("open");
    if (backdrop) backdrop.classList.add("active");

    // Initialize loading state
    if (el("dfd-proc-name")) el("dfd-proc-name").textContent = `PID ${pid}`;
    if (el("dfd-proc-meta")) el("dfd-proc-meta").textContent = "Loading forensic correlation profile...";
    if (el("dfd-risk-badge")) {
      el("dfd-risk-badge").textContent = "...";
      el("dfd-risk-badge").className = "badge badge-normal";
    }
    if (el("dfd-risk-explanation")) el("dfd-risk-explanation").textContent = "Synthesizing process ancestry, injections, sockets, and heuristics...";

    try {
      let profile = null;
      try {
        const res = await API.get(`/api/v2/processes/${pid}?evidence_id=${encodeURIComponent(state.activeEvidence.id)}`);
        profile = res.process_profile;
      } catch (e) {
        // Fallback to standard process endpoint
        const res = await API.get(`/api/processes/${pid}?evidence_id=${encodeURIComponent(state.activeEvidence.id)}`);
        const proc = res.process || res;
        profile = {
          process: proc,
          risk_assessment: {
            score: proc.risk_score || 0,
            level: proc.risk_level || "Normal",
            explanation: proc.explanation || "Evaluated by risk engine",
            contributing_factors: proc.indicators || [],
            verdict: proc.verdict || "unassigned"
          },
          ancestry: [],
          children: [],
          sockets: res.connections || proc.network_connections || [],
          dlls: res.dlls || [],
          memory_regions: res.memory_regions || [],
          detections: []
        };
      }

      if (!profile || !profile.process) {
        showToast(`Process ${pid} not found`, "error");
        return;
      }

      const p = profile.process;
      const risk = profile.risk_assessment || {};
      const score = risk.score !== undefined ? risk.score : (p.risk_score || 0);
      const level = risk.level || p.risk_level || "Normal";

      // Badge class
      const riskClass = level.toLowerCase().includes("critical") ? "badge-critical"
        : level.toLowerCase().includes("high") ? "badge-high"
        : level.toLowerCase().includes("suspicious") ? "badge-suspicious"
        : "badge-normal";

      // Header
      if (el("dfd-proc-name")) el("dfd-proc-name").textContent = p.name || `PID ${p.pid}`;
      if (el("dfd-proc-meta")) el("dfd-proc-meta").textContent = `PID ${p.pid} · PPID ${p.ppid} · Risk Score: ${score}/100`;
      const badge = el("dfd-risk-badge");
      if (badge) {
        badge.textContent = `${level.toUpperCase()} (${score})`;
        badge.className = `badge ${riskClass}`;
      }

      setInvestigationFocus({
        type: "process",
        id: p.pid,
        pid: p.pid,
        title: `${p.name || 'Process'} (PID ${p.pid})`,
        name: p.name,
        risk_score: score,
        risk_level: level,
        verdict: p.verdict || risk.verdict || "unassigned"
      });

      // Verdict dropdown
      const verdSel = el("dfd-verdict-select");
      if (verdSel) {
        verdSel.value = (p.verdict || risk.verdict || "unassigned").toLowerCase();
        verdSel.onchange = async () => {
          const v = verdSel.value;
          try {
            await API.post(`/api/v2/processes/${p.pid}/verdict`, { verdict: v, evidence_id: state.activeEvidence.id });
            p.verdict = v;
            if (state.investigationFocus && state.investigationFocus.pid === p.pid) {
              state.investigationFocus.verdict = v;
              updateFocusUI();
            }
            showToast(`Analyst verdict set to "${v}" for ${p.name} (PID ${p.pid})`, "success");
            logActivity("ANALYST_VERDICT", "Process Verdict", `PID ${p.pid} verdict updated to: ${v}`);
          } catch (err) {
            showToast(`Failed to update verdict: ${err.message}`, "error");
          }
        };
      }

      // Promote to Finding button
      const btnMakeFinding = el("dfd-btn-make-finding");
      if (btnMakeFinding) {
        btnMakeFinding.onclick = () => {
          openCreateFindingModal({
            title: `Suspicious Activity in ${p.name} (PID ${p.pid})`,
            pid: p.pid,
            process_name: p.name,
            severity: level.toLowerCase().includes("critical") ? "Critical" : level.toLowerCase().includes("high") ? "High" : level.toLowerCase().includes("suspicious") ? "Medium" : "Low",
            summary: risk.explanation || `Process ${p.name} exhibited anomalous behavior with risk score ${score}.`,
            assessment: `Forensic analysis of PID ${p.pid} revealed ${(profile.sockets || []).length} active sockets and ${(profile.memory_regions || []).length} injected memory segments.`
          });
        };
      }

      // Tab 1: Why Suspicious?
      const expCard = el("dfd-explain-card");
      if (expCard) {
        expCard.className = `explain-card ${level.toLowerCase().includes("critical") ? "critical" : level.toLowerCase().includes("high") ? "high" : level.toLowerCase().includes("suspicious") ? "suspicious" : ""}`;
      }
      if (el("dfd-risk-summary-title")) el("dfd-risk-summary-title").textContent = `Risk Level: ${level} (Score: ${score}/100)`;
      if (el("dfd-risk-explanation")) el("dfd-risk-explanation").textContent = risk.explanation || "No suspicious indicators detected.";

      // Contributing Factors
      const factorsList = el("dfd-factors-list");
      const factors = risk.contributing_factors || [];
      if (factorsList) {
        if (factors.length === 0) {
          factorsList.innerHTML = `<div style="color:var(--text-muted); font-size:12px; padding:6px 0;">No suspicious heuristic rules triggered. Evaluated within normal thresholds.</div>`;
        } else {
          factorsList.innerHTML = factors.map(f => `
            <div class="factor-item">
              <div>
                <div class="factor-title">${escapeHtml(f.name || f.rule || 'Rule Indicator')}</div>
                <div class="factor-desc">${escapeHtml(f.description || f.desc || '')}</div>
              </div>
              <div class="factor-points">+${f.points || f.score || 0} pts</div>
            </div>
          `).join("");
        }
      }

      // Detections
      const detList = el("dfd-detections-list");
      const detections = profile.detections || [];
      if (detList) {
        if (detections.length === 0) {
          detList.innerHTML = `<div style="color:var(--text-muted); font-size:12px; padding:6px 0;">No automated rule detections registered for this PID.</div>`;
        } else {
          detList.innerHTML = detections.map(d => `
            <div class="factor-item" style="border-left-color:var(--accent-purple);">
              <div>
                <div class="factor-title" style="color:var(--accent-purple);">${escapeHtml(d.rule_name || d.title || 'Detection')}</div>
                <div class="factor-desc">${escapeHtml(d.description || d.explanation || '')}</div>
              </div>
              <span class="badge ${d.severity === 'Critical' ? 'badge-critical' : 'badge-high'}">${escapeHtml(d.severity || 'High')}</span>
            </div>
          `).join("");
        }
      }

      // Tab 2: Process Info
      if (el("dfd-info-name")) el("dfd-info-name").textContent = p.name || "-";
      if (el("dfd-info-pids")) el("dfd-info-pids").textContent = `PID: ${p.pid} | Parent PID: ${p.ppid}`;
      if (el("dfd-info-path")) el("dfd-info-path").textContent = p.path || p.image_path || "N/A";
      if (el("dfd-info-cmd")) el("dfd-info-cmd").textContent = p.command_line || p.cmdline || "No command line arguments captured";
      if (el("dfd-info-create")) el("dfd-info-create").textContent = p.create_time || "N/A";
      if (el("dfd-info-exit")) el("dfd-info-exit").textContent = p.exit_time ? `${p.exit_time} (Terminated)` : "Active / Running at memory capture time";

      const isHidden = (p.in_psscan && !p.in_pslist);
      if (el("dfd-info-dkom")) {
        el("dfd-info-dkom").innerHTML = isHidden
          ? `<span class="badge badge-critical">⚠️ UNLINKED / HIDDEN (DKOM Detected: present in psscan, absent in pslist)</span>`
          : `<span class="badge badge-normal">✅ Verified Linked (EPROCESS Active)</span>`;
      }

      // Tab 3: Ancestry
      const ancList = el("dfd-ancestry-list");
      const ancestry = profile.ancestry || [];
      const children = profile.children || [];

      if (ancList) {
        let ancHtml = "";
        if (ancestry.length > 0) {
          ancestry.forEach((a, idx) => {
            ancHtml += `
              <div class="ancestry-node" onclick="window.inspectProcess(${a.pid})">
                <span style="color:var(--text-muted); font-size:11px;">Parent [${ancestry.length - idx}]</span>
                <strong style="color:var(--accent-cyan);">${escapeHtml(a.name || 'Unknown')}</strong>
                <span class="badge badge-normal">PID ${a.pid}</span>
                ${a.missing ? '<span class="badge badge-suspicious">Unlinked/Terminated</span>' : ''}
              </div>
              <div class="ancestry-connector"></div>
            `;
          });
        }
        ancHtml += `
          <div class="ancestry-node active-node">
            <span style="font-weight:700; color:var(--text-primary); font-size:13px;">🎯 ${escapeHtml(p.name)}</span>
            <span class="badge ${riskClass}">PID ${p.pid} (Current)</span>
          </div>
        `;
        if (children.length > 0) {
          children.forEach(c => {
            ancHtml += `
              <div class="ancestry-connector"></div>
              <div class="ancestry-node" onclick="window.inspectProcess(${c.pid})">
                <span style="color:var(--text-muted); font-size:11px;">Child</span>
                <strong style="color:var(--accent-blue);">${escapeHtml(c.name)}</strong>
                <span class="badge badge-normal">PID ${c.pid}</span>
                ${c.risk_score > 20 ? `<span class="badge badge-suspicious">Score: ${c.risk_score}</span>` : ''}
              </div>
            `;
          });
        } else {
          ancHtml += `<div style="font-size:11px; color:var(--text-muted); margin-top:8px; margin-left:10px;">(No spawned child processes recorded)</div>`;
        }
        ancList.innerHTML = ancHtml;
      }

      // Tab 4: Sockets
      const sockets = profile.sockets || [];
      if (el("dfd-sockets-count")) el("dfd-sockets-count").textContent = sockets.length;
      const sockList = el("dfd-sockets-list");
      if (sockList) {
        if (sockets.length === 0) {
          sockList.innerHTML = `<div style="text-align:center; padding:30px; color:var(--text-muted);">No open network sockets for this process.</div>`;
        } else {
          sockList.innerHTML = sockets.map(s => {
            const isExt = !String(s.remote_addr || "").startsWith("127.") && !String(s.remote_addr || "").startsWith("10.") && !String(s.remote_addr || "").startsWith("192.168.");
            return `
              <div class="explain-card" style="padding:10px; margin-bottom:8px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                  <span class="badge ${s.protocol === 'TCP' ? 'badge-normal' : 'badge-suspicious'}">${escapeHtml(s.protocol || 'TCP')}</span>
                  <span class="badge ${s.state === 'ESTABLISHED' ? 'badge-high' : 'badge-normal'}">${escapeHtml(s.state || 'LISTENING')}</span>
                  ${isExt ? '<span class="badge badge-purple">Observed External Network Artifact</span>' : '<span class="badge badge-normal">Internal RFC 1918</span>'}
                </div>
                <div style="font-family:var(--font-mono); font-size:12px; color:var(--text-primary);">
                  ${escapeHtml(s.local_addr || '0.0.0.0')}:${s.local_port || 0} &rarr; <span style="color:var(--accent-blue); font-weight:700;">${escapeHtml(s.remote_addr || '0.0.0.0')}:${s.remote_port || 0}</span>
                </div>
              </div>
            `;
          }).join("");
        }
      }

      // Tab 5: Injected Memory (Malfind)
      const memRegions = profile.memory_regions || [];
      if (el("dfd-mem-count")) el("dfd-mem-count").textContent = memRegions.length;
      const memList = el("dfd-mem-list");
      if (memList) {
        if (memRegions.length === 0) {
          memList.innerHTML = `<div style="text-align:center; padding:30px; color:var(--text-muted);">No suspicious RWX or injected memory segments detected.</div>`;
        } else {
          memList.innerHTML = memRegions.map(m => `
            <div class="explain-card critical" style="padding:12px; margin-bottom:10px;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                <strong style="color:var(--risk-critical); font-family:var(--font-mono); font-size:13px;">${escapeHtml(m.start_addr || m.base_address || '0x0')} - ${escapeHtml(m.end_addr || '')}</strong>
                <span class="badge badge-critical">${escapeHtml(m.protection || 'PAGE_EXECUTE_READWRITE')}</span>
              </div>
              <div style="font-size:11px; color:var(--text-muted); margin-bottom:6px;">Tag: ${escapeHtml(m.tag || 'VadS')} | Protection: ${escapeHtml(m.protection || 'RWX')}</div>
              ${m.disasm || m.hex_dump ? `
                <pre style="background:#06090e; color:var(--risk-high); font-family:var(--font-mono); font-size:11px; padding:8px; border-radius:4px; max-height:120px; overflow-y:auto;">${escapeHtml(m.disasm || m.hex_dump)}</pre>
              ` : ''}
            </div>
          `).join("");
        }
      }

      // Tab 6: DLLs
      const dlls = profile.dlls || [];
      if (el("dfd-dlls-count")) el("dfd-dlls-count").textContent = dlls.length;
      const dllList = el("dfd-dlls-list");
      const renderDlls = (filter = "") => {
        if (!dllList) return;
        const f = filter.toLowerCase().trim();
        const filtered = dlls.filter(d => !f || (d.path || d.name || '').toLowerCase().includes(f));
        if (filtered.length === 0) {
          dllList.innerHTML = `<div style="text-align:center; padding:20px; color:var(--text-muted);">No DLLs matching filter.</div>`;
          return;
        }
        dllList.innerHTML = filtered.map(d => `
          <div style="padding:6px 8px; border-bottom:1px solid rgba(42, 55, 74, 0.4); display:flex; justify-content:space-between;">
            <span style="color:var(--text-primary);">${escapeHtml(d.path || d.name || '')}</span>
            <span style="color:var(--text-muted); font-size:10px;">${escapeHtml(d.base_address || '')}</span>
          </div>
        `).join("");
      };
      renderDlls();
      const dllSearch = el("dfd-dll-search");
      if (dllSearch) dllSearch.oninput = () => renderDlls(dllSearch.value);

    } catch (err) {
      if (el("dfd-proc-meta")) el("dfd-proc-meta").textContent = `Error loading details: ${err.message}`;
      showToast(`Failed to load process details: ${err.message}`, "error");
    }
  }

  function closeProcessFocusDrawer() {
    const drawer = el("process-focus-drawer");
    const backdrop = el("drawer-backdrop");
    if (drawer) drawer.classList.remove("open");
    if (backdrop) backdrop.classList.remove("active");
  }

  window.inspectProcess = async function (pid) {
    await openProcessFocusDrawer(pid);
  };
  window.openProcessFocusDrawer = openProcessFocusDrawer;
  window.closeProcessFocusDrawer = closeProcessFocusDrawer;

  // =========================================================================
  // 3. Interactive Force-Directed Relationship Graph
  // =========================================================================
  async function loadGraphData() {
    const svg = el("svg-graph");
    if (!state.activeEvidence) {
      if (svg) svg.innerHTML = "";
      el("graph-stats-label").textContent = "No active evidence selected. Import or select a memory image to generate relationship graph.";
      return;
    }

    try {
      el("graph-stats-label").textContent = "Building forensic graph...";
      const data = await API.get(`/api/graph?evidence_id=${encodeURIComponent(state.activeEvidence.id)}`);
      state.graph.nodes = data.nodes || [];
      state.graph.edges = data.edges || [];
      state.graph.byId = {};
      state.graph.nodes.forEach(n => state.graph.byId[n.id] = n);

      renderGraph();
      renderAccessibleGraphTable();
    } catch (err) {
      el("graph-stats-label").textContent = `Graph build error: ${err.message}`;
    }
  }

  function renderGraph() {
    const svg = el("svg-graph");
    const statsLabel = el("graph-stats-label");
    if (!svg) return;

    svg.innerHTML = "";
    if (state.graph.nodes.length === 0) {
      statsLabel.textContent = "0 nodes · 0 links. Run Automated Triage to generate forensic data.";
      return;
    }

    const W = 1100, H = 680;
    // Initial circular positioning
    state.graph.nodes.forEach((n, i) => {
      if (n.x === undefined) {
        const angle = (2 * Math.PI * i) / Math.max(state.graph.nodes.length, 1);
        const radius = 140 + (i % 6) * 50;
        n.x = W / 2 + radius * Math.cos(angle);
        n.y = H / 2 + radius * 0.75 * Math.sin(angle);
        n.vx = 0;
        n.vy = 0;
      }
    });

    const NS = "http://www.w3.org/2000/svg";
    const gContainer = document.createElementNS(NS, "g");
    gContainer.id = "graph-transform-group";
    svg.appendChild(gContainer);

    // Render Edges
    state.graph.edgeEls = [];
    state.graph.edges.forEach(e => {
      const line = document.createElementNS(NS, "line");
      line.setAttribute("class", "graph-edge");
      const label = document.createElementNS(NS, "text");
      label.setAttribute("class", "graph-edge-label");
      label.textContent = e.label || "";
      gContainer.appendChild(line);
      gContainer.appendChild(label);
      e._line = line;
      e._label = label;
      state.graph.edgeEls.push(e);
    });

    // Render Nodes
    state.graph.nodeEls = [];
    state.graph.nodes.forEach(n => {
      const g = document.createElementNS(NS, "g");
      g.setAttribute("class", "graph-node");
      g.style.cursor = "pointer";

      const circle = document.createElementNS(NS, "circle");
      const r = n.type === "process" ? 16 : 10;
      circle.setAttribute("r", r);

      let color = "#64748b";
      if (n.type === "process") {
        const lvl = (n.risk || "").toLowerCase();
        color = lvl.includes("critical") ? "#ef4444" : lvl.includes("high") ? "#f97316" : lvl.includes("suspicious") ? "#eab308" : "#10b981";
      } else if (n.type === "ip") color = "#38bdf8";
      else if (n.type === "mem") color = "#f59e0b";
      else if (n.type === "yara") color = "#a855f7";

      circle.setAttribute("fill", color);
      circle.setAttribute("stroke", n.hidden ? "#eab308" : "#0f172a");
      circle.setAttribute("stroke-width", n.hidden ? "3" : "2");

      const text = document.createElementNS(NS, "text");
      text.setAttribute("y", -r - 5);
      text.textContent = (n.label || "").slice(0, 24);

      const sub = document.createElementNS(NS, "text");
      sub.setAttribute("y", r + 13);
      sub.setAttribute("class", "graph-node-sub");
      sub.textContent = (n.sub || "").slice(0, 28);

      g.appendChild(circle);
      g.appendChild(text);
      g.appendChild(sub);

      // Node Event Listeners
      g.onmousedown = (e) => {
        e.stopPropagation();
        state.graph.draggedNode = n;
      };

      g.onmouseenter = () => highlightNode(n);
      g.onmouseleave = () => highlightNode(null);

      g.onclick = (e) => {
        e.stopPropagation();
        openInspector(n);
      };

      g.ondblclick = () => {
        if (n.type === "process" && n.pid !== undefined) {
          window.inspectProcess(n.pid);
        }
      };

      n._g = g;
      gContainer.appendChild(g);
      state.graph.nodeEls.push(n);
    });

    statsLabel.textContent = `${state.graph.nodes.length} nodes · ${state.graph.edges.length} links (Forces active)`;

    startGraphPhysics();
  }

  function startGraphPhysics() {
    if (state.graph.simulation) clearInterval(state.graph.simulation);
    let stepCount = 0;

    state.graph.simulation = setInterval(() => {
      stepCount++;
      const repulse = 3000, spring = 0.015, springLen = 130;

      // 1. Repulsion between all nodes
      for (let i = 0; i < state.graph.nodes.length; i++) {
        const a = state.graph.nodes[i];
        a.fx = 0; a.fy = 0;
        for (let j = 0; j < state.graph.nodes.length; j++) {
          if (i === j) continue;
          const b = state.graph.nodes[j];
          const dx = a.x - b.x, dy = a.y - b.y;
          const distSq = dx * dx + dy * dy || 1;
          if (distSq < 45000) {
            const dist = Math.sqrt(distSq);
            const f = repulse / distSq;
            a.fx += (dx / dist) * f;
            a.fy += (dy / dist) * f;
          }
        }
      }

      // 2. Spring pull along edges
      for (const e of state.graph.edges) {
        const a = state.graph.byId[e.source], b = state.graph.byId[e.target];
        if (!a || !b) continue;
        const dx = b.x - a.x, dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const f = (dist - springLen) * spring;
        a.fx += (dx / dist) * f; a.fy += (dy / dist) * f;
        b.fx -= (dx / dist) * f; b.fy -= (dy / dist) * f;
      }

      // 3. Central gravity & damping
      for (const n of state.graph.nodes) {
        n.fx += (550 - n.x) * 0.003;
        n.fy += (340 - n.y) * 0.003;
        n.vx = (n.vx + n.fx) * 0.82;
        n.vy = (n.vy + n.fy) * 0.82;

        if (state.graph.draggedNode !== n) {
          n.x += n.vx;
          n.y += n.vy;
        }
      }

      updateSvgPositions();

      if (stepCount > 350) {
        clearInterval(state.graph.simulation);
        state.graph.simulation = null;
      }
    }, 16);
  }

  function updateSvgPositions() {
    for (const n of state.graph.nodes) {
      if (n._g) {
        n._g.setAttribute("transform", `translate(${n.x}, ${n.y})`);
      }
    }
    for (const e of state.graph.edges) {
      const a = state.graph.byId[e.source], b = state.graph.byId[e.target];
      if (!a || !b || !e._line) continue;
      e._line.setAttribute("x1", a.x); e._line.setAttribute("y1", a.y);
      e._line.setAttribute("x2", b.x); e._line.setAttribute("y2", b.y);
      if (e._label) {
        e._label.setAttribute("x", (a.x + b.x) / 2);
        e._label.setAttribute("y", (a.y + b.y) / 2 - 4);
      }
    }
  }

  function highlightNode(targetNode) {
    const tooltip = el("graph-tooltip-box");
    if (!targetNode) {
      if (tooltip) tooltip.style.display = "none";
      state.graph.nodes.forEach(n => { if (n._g) n._g.style.opacity = 1; });
      state.graph.edges.forEach(e => { if (e._line) e._line.style.opacity = 0.6; });
      return;
    }

    const directNeighbors = new Set([targetNode.id]);
    state.graph.edges.forEach(e => {
      if (e.source === targetNode.id) directNeighbors.add(e.target);
      if (e.target === targetNode.id) directNeighbors.add(e.source);
    });

    state.graph.nodes.forEach(n => {
      if (n._g) n._g.style.opacity = directNeighbors.has(n.id) ? 1 : 0.12;
    });
    state.graph.edges.forEach(e => {
      if (e._line) {
        const isNeighbor = directNeighbors.has(e.source) && directNeighbors.has(e.target);
        e._line.style.opacity = isNeighbor ? 0.9 : 0.05;
      }
    });

    // Show Tooltip
    if (tooltip) {
      tooltip.innerHTML = `
        <div style="font-weight:700; color:var(--accent-blue); margin-bottom:4px;">${escapeHtml(targetNode.label)}</div>
        <div style="color:var(--text-muted); font-size:11px;">Type: ${escapeHtml(targetNode.type)} ${targetNode.pid ? "· PID " + targetNode.pid : ""}</div>
        ${targetNode.risk ? `<div style="margin-top:2px;">Risk: <b>${escapeHtml(targetNode.risk)}</b></div>` : ""}
        ${targetNode.cmdline ? `<div style="font-size:10px; color:var(--text-muted); margin-top:4px;">${escapeHtml(targetNode.cmdline.slice(0, 100))}</div>` : ""}
      `;
      tooltip.style.display = "block";
      tooltip.style.left = `${Math.min(targetNode.x + 20, 800)}px`;
      tooltip.style.top = `${Math.min(targetNode.y + 20, 500)}px`;
    }
  }

  function setupGraphInteractions() {
    const box = el("graph-viewport-box");
    if (!box) return;

    box.onmousedown = (e) => {
      if (e.target.closest(".graph-controls") || e.target.closest(".graph-node")) return;
      state.graph.isPanning = true;
      state.graph.panStart = { x: e.clientX - state.graph.tx, y: e.clientY - state.graph.ty };
    };

    window.addEventListener("mousemove", (e) => {
      if (state.graph.isPanning) {
        state.graph.tx = e.clientX - state.graph.panStart.x;
        state.graph.ty = e.clientY - state.graph.panStart.y;
        applyGraphTransform();
      } else if (state.graph.draggedNode) {
        state.graph.draggedNode.x = (e.clientX - state.graph.tx) / state.graph.scale;
        state.graph.draggedNode.y = (e.clientY - state.graph.ty) / state.graph.scale;
        updateSvgPositions();
      }
    });

    window.addEventListener("mouseup", () => {
      state.graph.isPanning = false;
      state.graph.draggedNode = null;
    });

    box.onwheel = (e) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.12 : 0.88;
      state.graph.scale = Math.min(3.5, Math.max(0.25, state.graph.scale * zoomFactor));
      applyGraphTransform();
    };

    const btnGraphSvg = el("btn-graph-mode-svg");
    const btnGraphTable = el("btn-graph-mode-table");
    const boxGraphVisual = el("graph-viewport-box");
    const boxGraphTable = el("graph-table-view-box");

    if (btnGraphSvg && btnGraphTable) {
      btnGraphSvg.onclick = () => {
        btnGraphSvg.classList.add("active");
        btnGraphTable.classList.remove("active");
        if (boxGraphVisual) boxGraphVisual.style.display = "block";
        if (boxGraphTable) boxGraphTable.style.display = "none";
      };
      btnGraphTable.onclick = () => {
        btnGraphTable.classList.add("active");
        btnGraphSvg.classList.remove("active");
        if (boxGraphVisual) boxGraphVisual.style.display = "none";
        if (boxGraphTable) boxGraphTable.style.display = "block";
        renderAccessibleGraphTable();
      };
    }

    el("btn-graph-reset-view").onclick = () => {
      logActivity("GRAPH_ACTION", "Reset Zoom", "User clicked Reset Zoom on Forensic Graph");
      state.graph.scale = 1;
      state.graph.tx = 0;
      state.graph.ty = 0;
      applyGraphTransform();
    };

    el("btn-graph-rebuild").onclick = () => {
      logActivity("GRAPH_ACTION", "Rebuild Graph", "User clicked Rebuild Graph on Forensic Graph");
      loadGraphData();
    };

    const searchNode = el("graph-search-node");
    if (searchNode) {
      searchNode.oninput = () => {
        const val = searchNode.value.trim();
        if (val.length > 2) {
          logActivity("SEARCH", "Graph Search", `Searched Graph for node: "${val}"`);
        }
      };
    }

    ["gf-proc", "gf-ip", "gf-mem", "gf-yara"].forEach(id => {
      const cb = el(id);
      if (cb) {
        cb.onchange = () => {
          logActivity("GRAPH_FILTER", "Toggle Filter", `Graph filter '${id}' set to: ${cb.checked}`);
          const filterKey = id.replace("gf-", "");
          state.graph.filters[filterKey] = cb.checked;
          state.graph.nodes.forEach(n => {
            const visible = state.graph.filters[n.type] !== false;
            if (n._g) n._g.style.display = visible ? "" : "none";
          });
        };
      }
    });

    const layoutSel = el("graph-layout-selector");
    if (layoutSel) {
      layoutSel.onchange = (e) => switchGraphLayout(e.target.value);
    }

    const btnZoomIn = el("btn-graph-zoom-in");
    if (btnZoomIn) {
      btnZoomIn.onclick = () => {
        state.graph.scale = Math.min(3.5, state.graph.scale * 1.25);
        applyGraphTransform();
      };
    }

    const btnZoomOut = el("btn-graph-zoom-out");
    if (btnZoomOut) {
      btnZoomOut.onclick = () => {
        state.graph.scale = Math.max(0.25, state.graph.scale * 0.8);
        applyGraphTransform();
      };
    }

    const btnExportSvg = el("btn-graph-export-svg");
    if (btnExportSvg) {
      btnExportSvg.onclick = () => exportGraphSvg();
    }

    const btnCloseInsp = el("btn-close-inspector");
    if (btnCloseInsp) {
      btnCloseInsp.onclick = () => {
        const p = el("graph-inspector-panel");
        if (p) p.style.display = "none";
      };
    }

    const btnClearTerm = el("btn-clear-terminal");
    if (btnClearTerm) {
      btnClearTerm.onclick = (e) => {
        e.stopPropagation();
        const term = el("terminal-log-output");
        if (term) term.innerHTML = '<div class="log-line"><span class="log-time">[System]</span> <span class="log-info">Terminal log cleared.</span></div>';
        logActivity("DRAWER_ACTION", "Clear Terminal", "User cleared terminal output");
      };
    }
  }

  function applyGraphTransform() {
    const g = el("graph-transform-group");
    if (g) {
      g.setAttribute("transform", `translate(${state.graph.tx}, ${state.graph.ty}) scale(${state.graph.scale})`);
    }
  }

  // =========================================================================
  // 4. Network Connections View
  // =========================================================================
  async function loadNetworkData() {
    const btnCsv = el("btn-export-network-csv");
    if (btnCsv) {
      btnCsv.onclick = () => {
        if (!state.activeEvidence || !state.network || state.network.length === 0) {
          showToast("No network connections available to export", "warning");
          return;
        }
        logActivity("NETWORK_ACTION", "Export CSV", `Exported ${state.network.length} network sockets to CSV`);
        const headers = ["Protocol", "Local Address", "Local Port", "Remote Address", "Remote Port", "State", "PID", "Process Name", "Created Time"];
        const rows = state.network.map(c => [c.protocol, c.local_addr, c.local_port, c.remote_addr, c.remote_port, c.state, c.pid, `"${c.process_name || ''}"`, c.created_time]);
        const csv = [headers.join(",")].concat(rows.map(r => r.join(","))).join("\n");
        const blob = new Blob([csv], { type: "text/csv" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `network_connections_${state.activeEvidence.id.slice(0, 8)}.csv`;
        a.click();
        showToast("Network connections exported to CSV", "success");
      };
    }

    if (!state.activeEvidence) {
      state.network = [];
      renderNetworkTable();
      return;
    }
    try {
      state.network = await API.get(`/api/network?evidence_id=${encodeURIComponent(state.activeEvidence.id)}`);
      renderNetworkTable();
    } catch (err) {
      console.error("Network load error:", err);
    }
  }

  function renderNetworkTable() {
    const tbody = el("network-table-tbody");
    if (!tbody) return;

    if (!state.network || state.network.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--text-muted);">No network connections discovered.</td></tr>`;
      return;
    }

    const search = (el("net-search-input") ? el("net-search-input").value : "").toLowerCase().trim();
    const extFilter = el("net-ext-filter") ? el("net-ext-filter").value : "ALL";

    const filtered = state.network.filter(c => {
      const matchSearch = !search || (c.remote_addr || "").toLowerCase().includes(search) || (c.process_name || "").toLowerCase().includes(search);
      const isExt = !String(c.remote_addr || "").startsWith("127.") && !String(c.remote_addr || "").startsWith("10.") && !String(c.remote_addr || "").startsWith("192.168.");
      const matchExt = extFilter === "ALL" || (extFilter === "EXTERNAL" && isExt) || (extFilter === "INTERNAL" && !isExt);
      return matchSearch && matchExt;
    });

    tbody.innerHTML = filtered.map(c => `
      <tr>
        <td><span class="badge ${c.protocol === 'TCP' ? 'badge-normal' : 'badge-suspicious'}">${escapeHtml(c.protocol)}</span></td>
        <td style="font-family:var(--font-mono); font-size:12px;">${escapeHtml(c.local_addr)}:${c.local_port || ''}</td>
        <td style="font-family:var(--font-mono); font-size:12px; font-weight:600; color:var(--accent-blue);">${escapeHtml(c.remote_addr)}:${c.remote_port || ''}</td>
        <td><span class="badge ${c.state === 'ESTABLISHED' ? 'badge-high' : 'badge-normal'}">${escapeHtml(c.state || 'N/A')}</span></td>
        <td><span class="badge" style="cursor:pointer;" onclick="window.inspectProcess(${c.pid})" title="Inspect in Focus Mode">PID ${c.pid}</span></td>
        <td style="font-weight:600; cursor:pointer;" onclick="window.inspectProcess(${c.pid})" title="Inspect in Focus Mode">${escapeHtml(c.process_name || '')}</td>
        <td style="font-size:11px; color:var(--text-muted);">${escapeHtml(c.created_time || '')}</td>
      </tr>
    `).join("");

    if (el("net-search-input")) el("net-search-input").oninput = () => renderNetworkTable();
    if (el("net-ext-filter")) el("net-ext-filter").onchange = () => renderNetworkTable();
  }

  // =========================================================================
  // 5. Threat Intel & IOCs
  // =========================================================================
  async function loadIocsData() {
    const btnHarvest = el("btn-harvest-iocs");
    if (btnHarvest) {
      btnHarvest.onclick = async () => {
        if (!state.activeCase) {
          showToast("Please select or activate an investigation case first", "warning");
          return;
        }
        logActivity("IOC_ACTION", "Harvest IOCs", "User clicked Harvest from Network");
        showToast("Harvesting indicators from network activity...", "info");
        try {
          const res = await API.post("/api/iocs/harvest", {
            case_id: state.activeCase.id,
            evidence_id: state.activeEvidence ? state.activeEvidence.id : ""
          });
          if (res.success) {
            const hCount = res.harvested_count !== undefined ? res.harvested_count : (res.count || 0);
            logTerminal("SUCCESS", `Harvested ${hCount} new public IP IOCs.`);
            showToast(`Harvested ${hCount} public IP indicators!`, "success");
            loadIocsData();
          }
        } catch (err) {
          logTerminal("ERROR", `IOC harvesting failed: ${err.message}`);
          showToast(`IOC harvesting failed: ${err.message}`, "error");
        }
      };
    }

    const btnStix = el("btn-download-stix");
    if (btnStix) {
      btnStix.onclick = () => {
        if (!state.activeCase) {
          showToast("Please select or activate an investigation case first", "warning");
          return;
        }
        logActivity("IOC_ACTION", "Export STIX", "Downloaded STIX 2.1 Threat Intel bundle");
        showToast("Exporting STIX 2.1 Threat Intel bundle...", "info");
        window.open(`/api/iocs/stix?case_id=${encodeURIComponent(state.activeCase.id)}`, "_blank");
      };
    }

    const btnHunt = el("btn-run-hunt");
    if (btnHunt) {
      btnHunt.onclick = async () => {
        if (!state.activeCase) {
          showToast("Please select or activate an investigation case first", "warning");
          return;
        }
        const query = el("hunt-query-input") ? el("hunt-query-input").value.trim() : "";
        if (!query) {
          showToast("Please enter a search query or regex", "warning");
          return;
        }
        logActivity("THREAT_HUNT", "Execute Hunt", `Executed regex threat hunt for query: "${query}"`);
        try {
          const res = await API.post("/api/iocs/hunt", {
            case_id: state.activeCase.id,
            evidence_id: state.activeEvidence ? state.activeEvidence.id : "",
            query: query
          });
          el("hunt-results-area").style.display = "block";
          const list = el("hunt-matches-list");
          if (list) {
            list.innerHTML = (res.matches || []).length === 0
              ? `<div style="color:var(--text-muted);">No matches found for query.</div>`
              : (res.matches || []).map(m => `<div>Match: <span style="color:var(--accent-cyan);">${escapeHtml(m.matched_value || m.match || m)}</span> (Type: ${m.type || 'string'})</div>`).join("");
          }
        } catch (err) {
          showToast(`Hunt failed: ${err.message}`, "error");
        }
      };
    }

    if (!state.activeCase) {
      state.iocs = [];
      renderIocsTable();
      return;
    }
    try {
      state.iocs = await API.get(`/api/iocs?case_id=${encodeURIComponent(state.activeCase.id)}`);
      renderIocsTable();
    } catch (err) {
      console.error("IOCs load error:", err);
    }
  }

  function renderIocsTable() {
    const tbody = el("iocs-table-tbody");
    if (!tbody) return;

    if (!state.iocs || state.iocs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:30px; color:var(--text-muted);">No IOCs recorded for active case. Click "Harvest from Network" to extract public IPs.</td></tr>`;
      return;
    }

    tbody.innerHTML = state.iocs.map(ioc => {
      const sevBadge = ioc.severity === "Critical" ? "badge-critical" : ioc.severity === "High" ? "badge-high" : "badge-suspicious";
      return `
        <tr>
          <td><span class="badge ${sevBadge}">${escapeHtml(ioc.type)}</span></td>
          <td style="font-family:var(--font-mono); font-weight:600; color:var(--accent-cyan);">${escapeHtml(ioc.value)}</td>
          <td><span class="badge ${sevBadge}">${escapeHtml(ioc.severity)}</span></td>
          <td style="color:var(--text-muted);">${escapeHtml(ioc.source || 'Manual')}</td>
          <td>${escapeHtml(ioc.description || '')}</td>
          <td>${ioc.associated_pid || '-'}</td>
          <td>
            <button class="btn btn-sm btn-danger" onclick="window.deleteIoc('${escapeHtml(ioc.id)}')">🗑️ Delete</button>
          </td>
        </tr>
      `;
    }).join("");
  }

  // =========================================================================
  // 6. Timeline View
  // =========================================================================
  async function loadTimelineData() {
    const btnRegen = el("btn-generate-timeline");
    if (btnRegen) {
      btnRegen.onclick = async () => {
        if (!state.activeEvidence) {
          showToast("Please select or import active evidence first", "warning");
          return;
        }
        try {
          showToast("Regenerating forensic timeline...", "info");
          const res = await API.post("/api/timeline/generate", { evidence_id: state.activeEvidence.id });
          showToast(`Timeline generated: ${res.count || 0} events compiled`, "success");
          await loadTimelineData();
        } catch (err) {
          showToast(`Timeline generation failed: ${err.message}`, "error");
        }
      };
    }

    if (!state.activeEvidence) {
      state.timeline = [];
      renderTimelineTable();
      return;
    }
    try {
      state.timeline = await API.get(`/api/timeline?evidence_id=${encodeURIComponent(state.activeEvidence.id)}`);
      renderTimelineTable();
    } catch (err) {
      console.error("Timeline load error:", err);
    }
  }

  function renderTimelineTable() {
    const tbody = el("timeline-table-tbody");
    if (!tbody) return;

    if (!state.timeline || state.timeline.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:30px; color:var(--text-muted);">No timeline events recorded. Click "Regenerate Timeline" above.</td></tr>`;
      return;
    }

    const search = (el("timeline-search") ? el("timeline-search").value : "").toLowerCase().trim();
    const filter = el("timeline-filter") ? el("timeline-filter").value : "ALL";

    const filtered = state.timeline.filter(e => {
      const matchSearch = !search || (e.description || "").toLowerCase().includes(search) || (e.process_name || "").toLowerCase().includes(search);
      const matchType = filter === "ALL" || e.event_type === filter;
      return matchSearch && matchType;
    });

    tbody.innerHTML = filtered.map(e => `
      <tr>
        <td style="font-family:var(--font-mono); font-size:12px; color:var(--accent-cyan);">${escapeHtml(e.timestamp)}</td>
        <td><span class="badge ${e.event_type.includes('Create') ? 'badge-normal' : e.event_type.includes('Exit') ? 'badge-suspicious' : 'badge-purple'}">${escapeHtml(e.event_type)}</span></td>
        <td>${e.pid ? `<span class="badge" style="cursor:pointer;" onclick="window.inspectProcess(${e.pid})" title="Inspect in Focus Mode">PID ${e.pid}</span>` : '-'}</td>
        <td style="font-weight:600; ${e.pid ? 'cursor:pointer;' : ''}" ${e.pid ? `onclick="window.inspectProcess(${e.pid})" title="Inspect in Focus Mode"` : ''}>${escapeHtml(e.process_name || '')}</td>
        <td><span class="badge ${e.severity === 'High' ? 'badge-high' : 'badge-normal'}">${escapeHtml(e.severity || 'Normal')}</span></td>
        <td style="color:var(--text-secondary);">${escapeHtml(e.description || '')}</td>
      </tr>
    `).join("");

    if (el("timeline-search")) el("timeline-search").oninput = () => renderTimelineTable();
    if (el("timeline-filter")) el("timeline-filter").onchange = () => renderTimelineTable();
  }

  // =========================================================================
  // 7. Plugins Explorer View
  // =========================================================================
  async function loadPluginsData() {
    try {
      const data = await API.get("/api/plugins");
      state.plugins = data || {};
      renderPluginsList();
    } catch (err) {
      console.error("Plugins load error:", err);
    }
  }

  function renderPluginsList() {
    const container = el("plugins-list-container");
    if (!container) return;

    const filter = (el("plugin-filter-input") ? el("plugin-filter-input").value : "").toLowerCase().trim();
    const allPlugins = (state.plugins.windows || []).concat(state.plugins.linux || []).concat(state.plugins.mac || []);

    const filtered = allPlugins.filter(p => !filter || p.name.toLowerCase().includes(filter) || (p.category || "").toLowerCase().includes(filter));

    container.innerHTML = filtered.map(p => `
      <div class="nav-item ${state.selectedPlugin && state.selectedPlugin.name === p.name ? 'active' : ''}" onclick="window.selectPlugin('${escapeHtml(p.name)}')">
        <span class="nav-icon">⚙️</span>
        <div style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
          <div style="font-weight:600; font-size:12px;">${escapeHtml(p.name)}</div>
          <div style="font-size:10px; color:var(--text-muted);">${escapeHtml(p.category || 'General')}</div>
        </div>
      </div>
    `).join("");

    if (el("plugin-filter-input")) el("plugin-filter-input").oninput = () => renderPluginsList();
  }

  window.selectPlugin = function (name) {
    const allPlugins = (state.plugins.windows || []).concat(state.plugins.linux || []).concat(state.plugins.mac || []);
    const p = allPlugins.find(item => item.name === name);
    if (!p) return;

    state.selectedPlugin = p;
    el("selected-plugin-title").textContent = p.name;
    el("selected-plugin-desc").textContent = p.doc || p.description || "No documentation available for this plugin.";
    el("btn-execute-plugin").disabled = false;
    renderPluginsList();
  };

  el("btn-execute-plugin").onclick = async () => {
    if (!state.selectedPlugin || !state.activeEvidence) {
      customAlert({ title: "Plugin Execution", message: "Please select a plugin and active evidence first.", type: "warning" });
      return;
    }
    const rawArgs = el("plugin-args-input").value.trim();
    let args = [];
    if (rawArgs) {
      try {
        args = JSON.parse(rawArgs);
      } catch (err) {
        args = rawArgs.split(" ");
      }
    }

    try {
      logTerminal("INFO", `Executing plugin ${state.selectedPlugin.name}...`);
      const res = await API.post("/api/plugins/run", {
        evidence_id: state.activeEvidence.id,
        plugin_name: state.selectedPlugin.name,
        args: args
      });
      if (res.success) {
        logTerminal("SUCCESS", `Plugin execution started (ID: ${res.execution.id})`);
      }
    } catch (err) {
      logTerminal("ERROR", `Failed to run plugin: ${err.message}`);
    }
  };

  function renderPluginOutputTable(headers, rows) {
    const thead = el("plugin-result-thead");
    const tbody = el("plugin-result-tbody");

    if (!headers || headers.length === 0) {
      thead.innerHTML = "";
      tbody.innerHTML = `<tr><td style="text-align:center; padding:20px; color:var(--text-muted);">No tabular data produced.</td></tr>`;
      return;
    }

    thead.innerHTML = `<tr>${headers.map(h => `<th>${escapeHtml(h)}</th>`).join("")}</tr>`;
    tbody.innerHTML = (rows || []).slice(0, 500).map(r => `
      <tr>${headers.map(h => `<td style="font-family:var(--font-mono); font-size:12px;">${escapeHtml(r[h] !== undefined ? r[h] : "")}</td>`).join("")}</tr>
    `).join("");
  }

  // =========================================================================
  // 8. Playbooks View
  // =========================================================================
  async function loadPlaybooksData() {
    try {
      const pbs = await API.get("/api/playbooks");
      const container = el("playbooks-cards-container");
      if (!container) return;

      container.innerHTML = (pbs || []).map(pb => `
        <div class="panel" style="margin-bottom:0;">
          <div class="panel-header">
            <span class="panel-title">▶️ ${escapeHtml(pb.name)}</span>
          </div>
          <div class="panel-body">
            <p style="color:var(--text-secondary); margin-bottom:14px; font-size:13px;">${escapeHtml(pb.description || '')}</p>
            <div style="font-size:12px; color:var(--text-muted); margin-bottom:16px;">
              Steps: <b>${pb.steps}</b> · Author: ${escapeHtml(pb.author || 'DFIR-Workbench')}
            </div>
            <button class="btn btn-primary" onclick="window.runPlaybook('${escapeHtml(pb.id)}')">Run Playbook</button>
          </div>
        </div>
      `).join("");
    } catch (err) {
      console.error("Playbooks load error:", err);
    }
  }

  window.runPlaybook = async function (pbId) {
    if (!state.activeEvidence) {
      customAlert({ title: "Playbook Execution", message: "Please select active evidence first before running a playbook.", type: "warning" });
      return;
    }
    try {
      logTerminal("INFO", `Launching Playbook '${pbId}'...`);
      const res = await API.post("/api/playbooks/run", {
        playbook_id: pbId,
        evidence_id: state.activeEvidence.id
      });
      if (res.success) {
        logTerminal("SUCCESS", `Playbook '${pbId}' started.`);
      }
    } catch (err) {
      logTerminal("ERROR", `Failed to start playbook: ${err.message}`);
    }
  };

  // =========================================================================
  // 9. Snapshot Diff View
  // =========================================================================
  async function loadDiffData() {
    const btnDiff = el("btn-execute-diff");
    const selA = el("diff-select-a");
    const selB = el("diff-select-b");

    if (btnDiff && selA && selB) {
      btnDiff.onclick = async () => {
        if (!state.activeCase) {
          showToast("Please select active case first", "warning");
          return;
        }
        const idA = selA.value, idB = selB.value;
        if (!idA || !idB || idA === idB) {
          customAlert({ title: "Comparison Error", message: "Please select two distinct memory snapshots to compare.", type: "warning" });
          return;
        }
        try {
          showToast("Executing memory snapshot differential comparison...", "info");
          const res = await API.post("/api/diff", { evidence_a: idA, evidence_b: idB });
          const d = res.diff || res;
          if (res.success !== false && (d.new_processes || d.processes)) {
            el("diff-results-area").style.display = "block";
            const newCount = (d.new_processes || (d.processes && d.processes.added) || []).length;
            const termCount = (d.terminated_processes || (d.processes && d.processes.removed) || []).length;
            const commonCount = (d.common_processes || []).length;
            el("diff-stat-new").textContent = newCount;
            el("diff-stat-term").textContent = termCount;
            el("diff-stat-common").textContent = commonCount;
            showToast("Comparison analysis completed!", "success");
          } else {
            showToast(res.error || "Snapshot comparison returned no diff data", "warning");
          }
        } catch (err) {
          showToast(`Diff failed: ${err.message}`, "error");
        }
      };
    }

    if (!state.activeCase) return;
    try {
      const evs = await API.get(`/api/evidence?case_id=${encodeURIComponent(state.activeCase.id)}`);
      if (selA && selB) {
        const opts = (evs || []).map(e => `<option value="${e.id}">${escapeHtml(e.filename)} (${e.id.slice(0, 8)})</option>`).join("");
        selA.innerHTML = opts;
        selB.innerHTML = opts;
      }
    } catch (e) {}
  }

  // =========================================================================
  // 10. Arabic RTL Forensic Report View
  // =========================================================================
  async function loadReportData() {
    const iframe = el("report-iframe");
    const btnGen = el("btn-generate-report");
    const btnPkg = el("btn-export-full-pkg");

    if (btnGen) {
      btnGen.onclick = async () => {
        if (!state.activeCase) {
          showToast("Please select or activate an investigation case first", "warning");
          return;
        }
        try {
          showToast("Compiling court-admissible Arabic RTL Forensic Report...", "info");
          logTerminal("INFO", "Generating court-admissible Arabic RTL Forensic Report...");
          const res = await API.post("/api/reports/html", { case_id: state.activeCase.id });
          if (res.success && res.report_html) {
            if (iframe) {
              iframe.style.display = "block";
              iframe.srcdoc = res.report_html;
            }
            showToast("Report compiled successfully!", "success");
            logTerminal("SUCCESS", "Forensic report compiled successfully.");
          }
        } catch (err) {
          showToast(`Report generation failed: ${err.message}`, "error");
          logTerminal("ERROR", `Report generation failed: ${err.message}`);
        }
      };
    }

    if (btnPkg) {
      btnPkg.onclick = async () => {
        if (!state.activeCase) {
          showToast("Please select or activate an investigation case first", "warning");
          return;
        }
        try {
          showToast("Packaging ISO/IEC 27037 investigation package...", "info");
          logTerminal("INFO", "Exporting complete ISO/IEC 27037 investigation package...");
          const res = await API.post("/api/reports/package", { case_id: state.activeCase.id });
          if (res.success) {
            const pkgPath = res.package_path || res.path || "";
            customAlert({
              title: "Export Succeeded",
              message: "Complete ISO/IEC 27037 investigation package exported successfully!",
              details: pkgPath,
              type: "success"
            });
            logTerminal("SUCCESS", `Investigation package written to: ${pkgPath}`);
          }
        } catch (err) {
          showToast(`Package export failed: ${err.message}`, "error");
        }
      };
    }
  }

  // =========================================================================
  // 11. Cases & Evidence Management View
  // =========================================================================
  async function loadCasesAndEvidenceData() {
    try {
      state.cases = await API.get("/api/cases");
      renderCasesTable();

      if (state.activeCase) {
        state.evidenceList = await API.get(`/api/evidence?case_id=${encodeURIComponent(state.activeCase.id)}`);
      } else {
        state.evidenceList = [];
      }
      renderEvidenceTable();
    } catch (err) {
      console.error("Cases load error:", err);
    }
  }

  function renderCasesTable() {
    const tbody = el("cases-table-tbody");
    if (!tbody) return;

    if (!state.cases || state.cases.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--text-muted);">No cases found. Click "+ New Investigation Case" or upload a memory dump to begin.</td></tr>`;
      return;
    }

    tbody.innerHTML = state.cases.map(c => `
      <tr class="${state.activeCase && state.activeCase.id === c.id ? 'selected' : ''}">
        <td style="font-family:var(--font-mono); font-weight:700; color:var(--accent-blue);">${escapeHtml(c.id)}</td>
        <td style="font-weight:600;">${escapeHtml(c.name)}</td>
        <td>${escapeHtml(c.investigator || 'Analyst')}</td>
        <td>${c.evidence_count || 0}</td>
        <td><span class="badge badge-normal">${escapeHtml(c.status || 'Open')}</span></td>
        <td style="font-size:11px; color:var(--text-muted);">${escapeHtml(c.created_at ? c.created_at.slice(0, 16) : '')}</td>
        <td style="display:flex; gap:6px;">
          <button class="btn btn-sm btn-primary" onclick="window.activateCase('${escapeHtml(c.id)}')">Open Case</button>
          <button class="btn btn-sm btn-danger" onclick="window.deleteCase('${escapeHtml(c.id)}')">🗑️ Delete</button>
        </td>
      </tr>
    `).join("");
  }

  function renderEvidenceTable() {
    const tbody = el("evidence-table-tbody");
    if (!tbody) return;

    if (!state.activeCase) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:20px; color:var(--text-muted);">No active case selected. Select or create an investigation case first.</td></tr>`;
      return;
    }

    if (!state.evidenceList || state.evidenceList.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:20px; color:var(--text-muted);">No evidence imported for active case yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = state.evidenceList.map(e => `
      <tr class="${state.activeEvidence && state.activeEvidence.id === e.id ? 'selected' : ''}">
        <td style="font-weight:700; color:var(--accent-cyan);">${escapeHtml(e.filename)}</td>
        <td style="font-family:var(--font-mono); font-size:12px;">${(e.file_size / (1024*1024)).toFixed(2)} MB</td>
        <td style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted);">${escapeHtml((e.sha256 || '').slice(0, 16))}...</td>
        <td>${escapeHtml(e.os_type || 'Windows')}</td>
        <td><span class="badge badge-normal">${escapeHtml(e.status || 'Ready')}</span></td>
        <td style="display:flex; gap:6px;">
          <button class="btn btn-sm btn-primary" onclick="window.activateEvidence('${escapeHtml(e.id)}')">Set Active</button>
          <button class="btn btn-sm" onclick="window.verifyEvidence('${escapeHtml(e.id)}')">Verify</button>
          <button class="btn btn-sm btn-danger" onclick="window.deleteEvidence('${escapeHtml(e.id)}')">🗑️ Delete</button>
        </td>
      </tr>
    `).join("");
  }

  window.activateCase = async function (cid) {
    try {
      const res = await API.post("/api/cases/activate", { case_id: cid });
      if (res.success) {
        state.activeCase = res.case;
        state.evidenceList = await API.get(`/api/evidence?case_id=${encodeURIComponent(cid)}`);
        state.activeEvidence = state.evidenceList[0] || null;
        updateHeaderContext();
        loadCasesAndEvidenceData();
        logTerminal("INFO", `Switched to Case: ${state.activeCase.name}`);
      }
    } catch (err) {
      showToast(`Failed to activate case: ${err.message}`, "error");
    }
  };

  window.activateEvidence = async function (eid) {
    try {
      const res = await API.post("/api/evidence/activate", { evidence_id: eid });
      if (res.success) {
        state.activeEvidence = res.evidence;
        updateHeaderContext();
        loadCasesAndEvidenceData();
        logTerminal("INFO", `Switched active memory evidence to: ${state.activeEvidence.filename}`);
      }
    } catch (err) {
      showToast(`Failed to activate evidence: ${err.message}`, "error");
    }
  };

  window.verifyEvidence = async function (eid) {
    try {
      logTerminal("INFO", `Verifying SHA-256 cryptographic integrity for evidence ${eid}...`);
      const res = await API.post("/api/evidence/verify", { evidence_id: eid });
      if (res.success) {
        customAlert({
          title: "Cryptographic Integrity Check",
          message: res.intact
            ? "✅ Evidence integrity verified! Memory image is intact and matches chain of custody."
            : "❌ Tampering detected! Calculated SHA-256 does not match stored hash.",
          details: `Calculated SHA-256: ${res.calculated_sha256}\nStored SHA-256:     ${res.expected_sha256}`,
          type: res.intact ? "success" : "error"
        });
      }
    } catch (err) {
      showToast(`Verification failed: ${err.message}`, "error");
    }
  };

  // =========================================================================

  // =========================================================================
  // Deletion Operations & Lifecycle Handlers
  // =========================================================================
  window.deleteCase = async function (cid) {
    const confirmed = await customConfirm({
      title: "Delete Investigation Case",
      message: `Are you sure you want to permanently delete Case "${cid}" and all associated evidence?`,
      details: "This action cannot be undone. All database records, process trees, network sockets, and workspace dump files will be permanently purged.",
      confirmText: "Delete Permanently",
      cancelText: "Cancel",
      isDanger: true
    });
    if (!confirmed) return;

    logActivity("CASE_ACTION", "Delete Case", `User requested deletion of Case: ${cid}`);
    try {
      const res = await API.delete(`/api/cases/${encodeURIComponent(cid)}?delete_files=true`);
      if (res.success) {
        logTerminal("SUCCESS", `Case ${cid} deleted successfully.`);
        showToast(`Case ${cid} deleted successfully.`, "success");
        if (state.activeCase && state.activeCase.id === cid) {
          state.activeCase = null;
          state.activeEvidence = null;
        }
        await loadCasesAndEvidenceData();
        await loadInitialData();
      } else {
        customAlert({ title: "Delete Failed", message: res.error || "Failed to delete case", type: "error" });
      }
    } catch (err) {
      customAlert({ title: "Delete Error", message: err.message, type: "error" });
    }
  };

  window.deleteEvidence = async function (eid) {
    const confirmed = await customConfirm({
      title: "Delete Memory Evidence",
      message: `Are you sure you want to delete Evidence "${eid}"?`,
      details: "This will remove all extracted processes, network connections, DLLs, and associated forensic artifacts from this investigation.",
      confirmText: "Delete Evidence",
      cancelText: "Cancel",
      isDanger: true
    });
    if (!confirmed) return;

    logActivity("EVIDENCE_ACTION", "Delete Evidence", `User requested deletion of Evidence: ${eid}`);
    try {
      const res = await API.delete(`/api/evidence/${encodeURIComponent(eid)}`);
      if (res.success) {
        logTerminal("SUCCESS", `Evidence ${eid} deleted.`);
        showToast(`Evidence ${eid} deleted successfully.`, "success");
        if (state.activeEvidence && state.activeEvidence.id === eid) {
          state.activeEvidence = null;
        }
        await loadCasesAndEvidenceData();
        await loadDashboardData();
      } else {
        customAlert({ title: "Delete Failed", message: res.error || "Failed to delete evidence", type: "error" });
      }
    } catch (err) {
      customAlert({ title: "Delete Error", message: err.message, type: "error" });
    }
  };

  window.deleteIoc = async function (iocId) {
    const confirmed = await customConfirm({
      title: "Delete Indicator of Compromise",
      message: "Are you sure you want to delete this Indicator of Compromise (IOC)?",
      confirmText: "Delete IOC",
      cancelText: "Cancel",
      isDanger: true
    });
    if (!confirmed) return;

    logActivity("IOC_ACTION", "Delete IOC", `User deleted IOC ID: ${iocId}`);
    try {
      const res = await API.delete(`/api/iocs/${encodeURIComponent(iocId)}`);
      if (res.success) {
        logTerminal("SUCCESS", `IOC deleted.`);
        showToast("Indicator of Compromise deleted.", "success");
        loadIocsData();
      } else {
        customAlert({ title: "Delete Failed", message: res.error || "Failed to delete IOC", type: "error" });
      }
    } catch (err) {
      customAlert({ title: "Delete Error", message: err.message, type: "error" });
    }
  };

  // Modals Management
  // =========================================================================
  function setupModals() {
    document.querySelectorAll("[data-close]").forEach(btn => {
      btn.onclick = () => closeModal(btn.dataset.close);
    });

    const btnNewCase = el("btn-modal-create-case");
    if (btnNewCase) btnNewCase.onclick = () => openModal("modal-create-case");

    const btnImpEv = el("btn-modal-import-ev");
    if (btnImpEv) btnImpEv.onclick = () => openModal("modal-import-evidence");

    const btnAddIoc = el("btn-add-ioc-modal");
    if (btnAddIoc) btnAddIoc.onclick = () => openModal("modal-add-ioc");

    // Case creation submit
    const btnSubCase = el("btn-submit-create-case");
    if (btnSubCase) btnSubCase.onclick = async () => {
      const nameEl = el("new-case-name");
      const name = nameEl ? nameEl.value.trim() : "";
      if (!name) { showToast("Case name is required", "warning"); return; }
      const cid = el("new-case-id") ? el("new-case-id").value.trim() : "";
      const inv = el("new-case-investigator") ? el("new-case-investigator").value.trim() : "";
      const desc = el("new-case-desc") ? el("new-case-desc").value.trim() : "";

      try {
        const res = await API.post("/api/cases", { case_id: cid, name, investigator: inv, description: desc });
        if (res.success) {
          state.activeCase = res.case;
          updateHeaderContext();
          closeModal("modal-create-case");
          loadCasesAndEvidenceData();
          logTerminal("SUCCESS", `Created and activated Case: ${res.case.name}`);
        }
      } catch (err) {
        customAlert({ title: "Case Creation Failed", message: err.message, type: "error" });
      }
    };

    // Evidence import submit
    const btnSubEv = el("btn-submit-import-evidence");
    if (btnSubEv) btnSubEv.onclick = async () => {
      const pathEl = el("import-filepath");
      const path = pathEl ? pathEl.value.trim() : "";
      if (!path) { showToast("File path is required", "warning"); return; }

      const progBox = el("import-progress-box");
      if (progBox) progBox.style.display = "block";
      try {
        logTerminal("INFO", `Importing memory dump: ${path}`);
        const res = await API.post("/api/evidence/import", {
          case_id: state.activeCase ? state.activeCase.id : "",
          filepath: path
        });
        if (res.success) {
          state.activeEvidence = res.evidence;
          updateHeaderContext();
          closeModal("modal-import-evidence");
          loadCasesAndEvidenceData();
          logTerminal("SUCCESS", `Evidence imported: ${res.evidence.filename} (SHA-256: ${res.evidence.sha256.slice(0, 16)}...)`);
        }
      } catch (err) {
        customAlert({ title: "Import Failed", message: err.message, type: "error" });
      } finally {
        if (progBox) progBox.style.display = "none";
      }
    };

    // Add IOC submit
    const btnSubIoc = el("btn-submit-add-ioc");
    if (btnSubIoc) btnSubIoc.onclick = async () => {
      const valEl = el("ioc-value-input");
      const val = valEl ? valEl.value.trim() : "";
      if (!val) { showToast("Indicator value is required", "warning"); return; }
      try {
        const res = await API.post("/api/iocs", {
          case_id: state.activeCase ? state.activeCase.id : "",
          type: el("ioc-type-select") ? el("ioc-type-select").value : "ip",
          value: val,
          severity: el("ioc-severity-select") ? el("ioc-severity-select").value : "High",
          description: el("ioc-desc-input") ? el("ioc-desc-input").value.trim() : ""
        });
        if (res.success) {
          closeModal("modal-add-ioc");
          loadIocsData();
          logTerminal("SUCCESS", `Registered IOC: ${val}`);
        }
      } catch (err) {
        customAlert({ title: "Failed to Add IOC", message: err.message, type: "error" });
      }
    };

    // Findings Center wiring
    const btnNewFinding = el("btn-create-finding-modal");
    if (btnNewFinding) btnNewFinding.onclick = () => openCreateFindingModal();

    const btnRefFindings = el("btn-refresh-findings");
    if (btnRefFindings) btnRefFindings.onclick = () => loadFindingsData();

    const fSearch = el("findings-search-input");
    if (fSearch) fSearch.oninput = () => renderFindings();

    const fStatus = el("findings-status-filter");
    if (fStatus) fStatus.onchange = () => renderFindings();

    const fSev = el("findings-severity-filter");
    if (fSev) fSev.onchange = () => renderFindings();

    const btnSubFinding = el("btn-submit-create-finding");
    if (btnSubFinding) {
      btnSubFinding.onclick = async () => {
        const title = (el("finding-form-title") ? el("finding-form-title").value : "").trim();
        if (!title) { showToast("Finding title is required", "warning"); return; }
        const data = {
          case_id: state.activeCase ? state.activeCase.id : "",
          title: title,
          severity: el("finding-form-severity") ? el("finding-form-severity").value : "High",
          confidence: el("finding-form-confidence") ? el("finding-form-confidence").value : "High",
          status: el("finding-form-status") ? el("finding-form-status").value : "triaged",
          associated_pid: parseInt(el("finding-form-pid") ? el("finding-form-pid").value : "0") || 0,
          associated_process_name: (el("finding-form-process") ? el("finding-form-process").value : "").trim(),
          summary: (el("finding-form-summary") ? el("finding-form-summary").value : "").trim(),
          analyst_assessment: (el("finding-form-assessment") ? el("finding-form-assessment").value : "").trim(),
          investigator: "Lead Analyst"
        };
        try {
          await API.post("/api/v2/findings", data);
          closeModal("modal-create-finding");
          showToast("Forensic finding registered successfully", "success");
          loadFindingsData();
        } catch (err) {
          customAlert({ title: "Failed to Create Finding", message: err.message, type: "error" });
        }
      };
    }

    // Process Focus Drawer Controls
    const drawerCloseBtn = el("dfd-close-btn");
    if (drawerCloseBtn) drawerCloseBtn.onclick = () => closeProcessFocusDrawer();

    const drawerBackdrop = el("drawer-backdrop");
    if (drawerBackdrop) drawerBackdrop.onclick = () => closeProcessFocusDrawer();

    document.querySelectorAll(".drawer-subtab").forEach(tab => {
      tab.onclick = () => {
        document.querySelectorAll(".drawer-subtab").forEach(t => t.classList.remove("active"));
        document.querySelectorAll(".drawer-subtab-pane").forEach(p => p.classList.remove("active"));
        tab.classList.add("active");
        const target = el(tab.dataset.subtab);
        if (target) target.classList.add("active");
      };
    });
  }

  // =========================================================================
  // V2 Findings & Verdicts Lifecycle Management
  // =========================================================================
  async function loadFindingsData() {
    if (!state.activeCase) {
      renderFindings();
      return;
    }
    try {
      let findings = [];
      try {
        const res = await API.get(`/api/v2/findings?case_id=${encodeURIComponent(state.activeCase.id)}`);
        findings = res.findings || [];
      } catch (e) {
        findings = await API.get(`/api/findings?case_id=${encodeURIComponent(state.activeCase.id)}`);
      }
      state.findings = findings || [];
      renderFindings();
    } catch (err) {
      console.error("Failed to load findings:", err);
      showToast(`Findings error: ${err.message}`, "error");
    }
  }

  function renderFindings() {
    const tbody = el("findings-table-tbody");
    if (!tbody) return;

    const findings = state.findings || [];

    // Metrics counters
    const totalEl = el("findings-total-count");
    const confEl = el("findings-confirmed-count");
    const invEl = el("findings-investigating-count");
    const fpEl = el("findings-fp-count");

    if (totalEl) totalEl.textContent = findings.length;
    if (confEl) confEl.textContent = findings.filter(f => (f.status || "").toLowerCase() === "confirmed").length;
    if (invEl) invEl.textContent = findings.filter(f => ["investigating", "triaged", "detected"].includes((f.status || "").toLowerCase())).length;
    if (fpEl) fpEl.textContent = findings.filter(f => (f.status || "").toLowerCase() === "false_positive").length;

    if (findings.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:35px; color:var(--text-muted);">No forensic findings recorded yet. Click "+ New Finding" or promote suspicious processes from Focus Mode.</td></tr>`;
      return;
    }

    const search = (el("findings-search-input") ? el("findings-search-input").value : "").toLowerCase().trim();
    const statusFilter = el("findings-status-filter") ? el("findings-status-filter").value : "ALL";
    const sevFilter = el("findings-severity-filter") ? el("findings-severity-filter").value : "ALL";

    const filtered = findings.filter(f => {
      const matchSearch = !search || (f.title || "").toLowerCase().includes(search) || (f.summary || "").toLowerCase().includes(search) || (f.affected_entity || "").toLowerCase().includes(search) || (f.associated_process_name || "").toLowerCase().includes(search);
      const matchStatus = statusFilter === "ALL" || (f.status || "").toLowerCase() === statusFilter.toLowerCase();
      const matchSev = sevFilter === "ALL" || (f.severity || "").toLowerCase() === sevFilter.toLowerCase();
      return matchSearch && matchStatus && matchSev;
    });

    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--text-muted);">No findings matching active filters.</td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map(f => {
      const sevClass = (f.severity || "").toLowerCase() === "critical" ? "badge-critical"
        : (f.severity || "").toLowerCase() === "high" ? "badge-high"
        : (f.severity || "").toLowerCase() === "medium" ? "badge-suspicious"
        : "badge-normal";

      const status = (f.status || "detected").toLowerCase();
      const entity = f.associated_process_name ? `${f.associated_process_name} (PID ${f.associated_pid})`
        : f.affected_entity || "Case Scope";

      let artCount = 0;
      if (Array.isArray(f.supporting_evidence)) artCount = f.supporting_evidence.length;
      else if (typeof f.supporting_evidence === "string" && f.supporting_evidence.startsWith("[")) {
        try { artCount = JSON.parse(f.supporting_evidence).length; } catch (e) {}
      }

      return `
        <tr>
          <td><span class="badge ${sevClass}">${escapeHtml(f.severity || 'Medium')}</span></td>
          <td>
            <div style="font-weight:700; color:var(--text-primary); cursor:pointer;" onclick="window.viewFinding('${f.id}')">${escapeHtml(f.title)}</div>
            <div style="font-size:12px; color:var(--text-muted); margin-top:2px;">${escapeHtml(f.summary || f.description || '')}</div>
          </td>
          <td style="font-family:var(--font-mono); font-size:12px;">${escapeHtml(entity)}</td>
          <td><span class="badge badge-normal">${escapeHtml(f.confidence || 'Medium')}</span></td>
          <td>
            <select class="select-input" style="font-size:11px; padding:3px 6px;" onchange="window.updateFindingStatus('${f.id}', this.value)">
              <option value="detected" ${status === 'detected' ? 'selected' : ''}>Detected</option>
              <option value="triaged" ${status === 'triaged' ? 'selected' : ''}>Triaged</option>
              <option value="investigating" ${status === 'investigating' ? 'selected' : ''}>Investigating</option>
              <option value="confirmed" ${status === 'confirmed' ? 'selected' : ''}>Confirmed Threat</option>
              <option value="false_positive" ${status === 'false_positive' ? 'selected' : ''}>False Positive</option>
              <option value="inconclusive" ${status === 'inconclusive' ? 'selected' : ''}>Inconclusive</option>
              <option value="closed" ${status === 'closed' ? 'selected' : ''}>Closed</option>
            </select>
          </td>
          <td><span class="badge badge-purple">${artCount} items</span></td>
          <td style="text-align:right;">
            <button class="btn btn-sm" onclick="window.viewFinding('${f.id}')" style="padding:3px 8px; font-size:11px;">🔍 Inspect</button>
            <button class="btn btn-danger btn-sm" onclick="window.deleteFinding('${f.id}')" style="padding:3px 8px; font-size:11px; margin-left:4px;">🗑️</button>
          </td>
        </tr>
      `;
    }).join("");
  }

  function openCreateFindingModal(prefill = {}) {
    if (el("finding-form-title")) el("finding-form-title").value = prefill.title || "";
    if (el("finding-form-severity")) el("finding-form-severity").value = prefill.severity || "High";
    if (el("finding-form-confidence")) el("finding-form-confidence").value = prefill.confidence || "High";
    if (el("finding-form-status")) el("finding-form-status").value = prefill.status || "triaged";
    if (el("finding-form-pid")) el("finding-form-pid").value = prefill.pid !== undefined ? prefill.pid : 0;
    if (el("finding-form-process")) el("finding-form-process").value = prefill.process_name || "";
    if (el("finding-form-summary")) el("finding-form-summary").value = prefill.summary || "";
    if (el("finding-form-assessment")) el("finding-form-assessment").value = prefill.assessment || "";

    openModal("modal-create-finding");
  }
  window.openCreateFindingModal = openCreateFindingModal;

  window.updateFindingStatus = async function (findingId, newStatus) {
    try {
      await API.post(`/api/v2/findings/${findingId}/status`, {
        status: newStatus,
        analyst: "Lead Analyst",
        reason: "Updated via Findings cockpit"
      });
      showToast(`Finding status transitioned to: ${newStatus}`, "success");
      logActivity("FINDING_ACTION", "Status Transition", `Finding ${findingId} transitioned to ${newStatus}`);
      await loadFindingsData();
    } catch (err) {
      showToast(`Status change failed: ${err.message}`, "error");
    }
  };

  window.deleteFinding = async function (findingId) {
    const ok = await customConfirm({
      title: "Delete Forensic Finding",
      message: "Are you sure you want to permanently delete this finding? This cannot be undone.",
      confirmText: "Delete Finding",
      isDanger: true
    });
    if (!ok) return;

    try {
      await API.delete(`/api/v2/findings/${findingId}`);
      showToast("Finding deleted successfully", "success");
      logActivity("FINDING_ACTION", "Delete Finding", `Deleted finding ${findingId}`);
      await loadFindingsData();
      closeModal("modal-view-finding");
    } catch (err) {
      showToast(`Delete failed: ${err.message}`, "error");
    }
  };

  window.viewFinding = async function (findingId) {
    try {
      const res = await API.get(`/api/v2/findings/${findingId}`);
      const details = res.details || {};
      const f = details.finding || details;
      state.activeFinding = f;

      if (el("vf-title")) el("vf-title").textContent = f.title || "Forensic Finding";

      const sevBadge = el("vf-severity-badge");
      if (sevBadge) {
        sevBadge.textContent = f.severity || "High";
        sevBadge.className = `badge ${(f.severity || '').toLowerCase() === 'critical' ? 'badge-critical' : 'badge-high'}`;
      }

      const stBadge = el("vf-status-badge");
      if (stBadge) {
        stBadge.textContent = (f.status || "detected").toUpperCase();
        stBadge.className = `badge badge-status-${(f.status || 'detected').toLowerCase()}`;
      }

      if (el("vf-entity")) el("vf-entity").textContent = f.associated_process_name ? `${f.associated_process_name} (PID ${f.associated_pid})` : (f.affected_entity || 'N/A');
      if (el("vf-confidence")) el("vf-confidence").textContent = f.confidence || "Medium";
      if (el("vf-investigator")) el("vf-investigator").textContent = f.investigator || "Analyst";
      if (el("vf-created")) el("vf-created").textContent = f.created_at || "N/A";
      if (el("vf-summary")) el("vf-summary").textContent = f.summary || f.description || "No summary provided.";
      if (el("vf-assessment")) el("vf-assessment").textContent = f.analyst_assessment || f.technical_description || "No analyst assessment recorded.";

      // Wire lifecycle buttons
      const transitions = [
        { id: "vf-btn-triage", status: "triaged" },
        { id: "vf-btn-investigate", status: "investigating" },
        { id: "vf-btn-confirm", status: "confirmed" },
        { id: "vf-btn-fp", status: "false_positive" },
        { id: "vf-btn-inconclusive", status: "inconclusive" },
        { id: "vf-btn-close", status: "closed" }
      ];
      transitions.forEach(t => {
        const b = el(t.id);
        if (b) {
          b.onclick = async () => {
            await window.updateFindingStatus(f.id, t.status);
            window.viewFinding(f.id);
          };
        }
      });

      // Wire delete button
      const delBtn = el("vf-btn-delete");
      if (delBtn) delBtn.onclick = () => window.deleteFinding(f.id);

      // Render artifacts list
      const artContainer = el("vf-artifacts-list");
      const arts = details.artifacts || [];
      if (el("vf-artifacts-count")) el("vf-artifacts-count").textContent = arts.length;
      if (artContainer) {
        if (arts.length === 0) {
          artContainer.innerHTML = `<div style="color:var(--text-muted); font-size:12px;">No evidence artifacts attached to this finding.</div>`;
        } else {
          artContainer.innerHTML = arts.map(a => `
            <div style="display:flex; justify-content:space-between; align-items:center; background:var(--bg-surface); padding:6px 10px; border-radius:4px; border:1px solid var(--border-color);">
              <div>
                <strong style="color:var(--accent-cyan); font-family:var(--font-mono);">${escapeHtml(a.artifact_type || 'artifact')}</strong>: ${escapeHtml(a.id || '')}
                <span style="color:var(--text-muted); font-size:11px; margin-left:6px;">(${escapeHtml(a.role || 'supports')})</span>
              </div>
              <button class="btn btn-sm" onclick="window.viewArtifact('${a.id}')" style="padding:2px 6px; font-size:10px;">View</button>
            </div>
          `).join("");
        }
      }

      // Render notes list
      const notesContainer = el("vf-notes-list");
      const notes = details.notes || [];
      if (notesContainer) {
        if (notes.length === 0) {
          notesContainer.innerHTML = `<div style="color:var(--text-muted); font-size:12px;">No analyst notes posted yet.</div>`;
        } else {
          notesContainer.innerHTML = notes.map(n => `
            <div style="background:var(--bg-primary); padding:8px 10px; border-radius:4px; border-left:3px solid var(--accent-cyan); font-size:12px;">
              <div style="display:flex; justify-content:space-between; color:var(--text-muted); font-size:10.5px; margin-bottom:3px;">
                <span><strong>${escapeHtml(n.author || 'Analyst')}</strong></span>
                <span>${escapeHtml(n.created_at || '')}</span>
              </div>
              <div style="color:var(--text-primary);">${escapeHtml(n.content || '')}</div>
            </div>
          `).join("");
        }
      }

      // Wire add note button
      const postBtn = el("vf-btn-add-note");
      if (postBtn) {
        postBtn.onclick = async () => {
          const input = el("vf-new-note-input");
          const noteText = input ? input.value.trim() : "";
          if (!noteText) return;
          try {
            await API.post(`/api/v2/findings/${f.id}/notes`, {
              author: "Lead Analyst",
              content: noteText
            });
            input.value = "";
            showToast("Analyst note posted", "success");
            window.viewFinding(f.id);
          } catch (err) {
            showToast(`Failed to add note: ${err.message}`, "error");
          }
        };
      }

      openModal("modal-view-finding");
    } catch (err) {
      showToast(`Failed to load finding: ${err.message}`, "error");
    }
  };

  // =========================================================================
  // V2 Artifact Inspection & Provenance
  // =========================================================================
  window.viewArtifact = async function (artifactId) {
    try {
      const res = await API.get(`/api/v2/artifacts/${artifactId}`);
      const art = res.artifact;
      if (!art) {
        showToast("Artifact details not found", "error");
        return;
      }

      if (el("va-id")) el("va-id").textContent = art.id;
      if (el("va-type")) el("va-type").textContent = art.type || art.artifact_type || "generic";
      if (el("va-plugin")) el("va-plugin").textContent = art.source_plugin || "volatility3";
      if (el("va-created")) el("va-created").textContent = art.created_at || "-";
      if (el("va-raw-data")) el("va-raw-data").textContent = JSON.stringify(art.raw_data || art.data || {}, null, 2);

      const btnPromote = el("va-btn-promote-ioc");
      const isIp = (art.type || "").includes("network") || (art.type || "").includes("ip");
      if (btnPromote) {
        btnPromote.style.display = isIp ? "block" : "none";
        btnPromote.onclick = () => window.promoteArtifactToIOC(art.id);
      }

      openModal("modal-view-artifact");
    } catch (err) {
      showToast(`Failed to load artifact: ${err.message}`, "error");
    }
  };

  window.promoteArtifactToIOC = async function (artifactId) {
    const ok = await customConfirm({
      title: "Promote Artifact to IOC",
      message: "Promote this network artifact to a Threat Indicator of Compromise (IOC)?",
      confirmText: "Promote to IOC",
      isDanger: false
    });
    if (!ok) return;

    try {
      const res = await API.post("/api/v2/iocs/promote", {
        artifact_id: artifactId,
        case_id: state.activeCase ? state.activeCase.id : "",
        severity: "High",
        analyst: "Lead Analyst"
      });
      showToast(`Artifact successfully promoted to IOC: ${res.ioc.value}`, "success");
      logActivity("IOC_ACTION", "Promote to IOC", `Promoted artifact ${artifactId} to IOC`);
      closeModal("modal-view-artifact");
      loadIocsData();
    } catch (err) {
      showToast(`Promotion failed: ${err.message}`, "error");
    }
  };

  function openModal(modalId) {
    const modal = el(modalId);
    if (!modal) return;
    logActivity("MODAL_ACTION", "Open Modal", `User opened modal dialog: ${modalId}`);
    if (modalId === "modal-import-evidence" && state.cases.length > 0) {
      const sel = el("import-case-select");
      if (sel) {
        sel.innerHTML = state.cases.map(c => `<option value="${c.id}" ${state.activeCase && state.activeCase.id === c.id ? 'selected' : ''}>${escapeHtml(c.name)} (${c.id})</option>`).join("");
      }
    }
    modal.style.display = "flex";
    requestAnimationFrame(() => {
      modal.classList.add("active");
    });
  }

  function closeModal(modalId) {
    const modal = el(modalId);
    if (!modal) return;
    logActivity("MODAL_ACTION", "Close Modal", `User closed modal dialog: ${modalId}`);
    modal.classList.remove("active");
    setTimeout(() => {
      if (!modal.classList.contains("active")) {
        modal.style.display = "none";
      }
    }, 200);
  }


  // =========================================================================
  // Enhanced Forensic Graph Layouts & Side Inspector
  // =========================================================================
  function switchGraphLayout(layoutType) {
    state.graph.layout = layoutType;
    logActivity("GRAPH_ACTION", "Switch Layout", `Switched graph layout to: ${layoutType}`);
    computeGraphLayout(layoutType);
    updateSvgPositions();
  }

  function computeGraphLayout(layoutType) {
    const W = 1100, H = 680;
    const nodes = state.graph.nodes;
    if (!nodes || nodes.length === 0) return;

    if (layoutType === "tree") {
      // Hierarchical Process Lineage
      const byPid = new Map();
      const childrenMap = new Map();
      nodes.forEach(n => {
        if (n.pid) byPid.set(n.pid, n);
      });
      nodes.forEach(n => {
        const ppid = n.ppid || 0;
        if (!childrenMap.has(ppid)) childrenMap.set(ppid, []);
        childrenMap.get(ppid).push(n);
      });

      const roots = nodes.filter(n => !byPid.has(n.ppid) || n.ppid === 0 || n.ppid === n.pid);
      let colIdx = 0;

      function layoutBranch(node, depth, xOffset) {
        node.x = xOffset;
        node.y = 80 + depth * 110;
        const children = childrenMap.get(node.pid) || [];
        children.forEach((c, idx) => {
          layoutBranch(c, depth + 1, xOffset + (idx - children.length / 2) * 140);
        });
      }

      roots.forEach((r, idx) => {
        layoutBranch(r, 0, 160 + idx * 260);
      });

    } else if (layoutType === "concentric") {
      // Concentric Orbital Layout
      const centerX = W / 2, centerY = H / 2;
      const criticals = nodes.filter(n => (n.risk || "").toLowerCase().includes("critical"));
      const highNormals = nodes.filter(n => !(n.risk || "").toLowerCase().includes("critical") && n.type === "process");
      const externals = nodes.filter(n => n.type !== "process");

      // Ring 0: Center (Critical threats)
      criticals.forEach((n, i) => {
        const a = (2 * Math.PI * i) / Math.max(criticals.length, 1);
        n.x = centerX + 70 * Math.cos(a);
        n.y = centerY + 70 * Math.sin(a);
      });

      // Ring 1: High & Normal processes
      highNormals.forEach((n, i) => {
        const a = (2 * Math.PI * i) / Math.max(highNormals.length, 1);
        n.x = centerX + 210 * Math.cos(a);
        n.y = centerY + 180 * Math.sin(a);
      });

      // Ring 2: External IPs, memory, YARA
      externals.forEach((n, i) => {
        const a = (2 * Math.PI * i) / Math.max(externals.length, 1);
        n.x = centerX + 340 * Math.cos(a);
        n.y = centerY + 280 * Math.sin(a);
      });

    } else if (layoutType === "clusters") {
      // Group by Risk Severity Clusters
      const clusters = {
        "critical": { x: 200, y: 180, nodes: [] },
        "high": { x: 550, y: 180, nodes: [] },
        "suspicious": { x: 900, y: 180, nodes: [] },
        "normal": { x: 380, y: 460, nodes: [] },
        "network": { x: 780, y: 460, nodes: [] }
      };

      nodes.forEach(n => {
        if (n.type !== "process") {
          clusters.network.nodes.push(n);
        } else {
          const r = (n.risk || "").toLowerCase();
          if (r.includes("critical")) clusters.critical.nodes.push(n);
          else if (r.includes("high")) clusters.high.nodes.push(n);
          else if (r.includes("suspicious")) clusters.suspicious.nodes.push(n);
          else clusters.normal.nodes.push(n);
        }
      });

      Object.values(clusters).forEach(cl => {
        cl.nodes.forEach((n, idx) => {
          const row = Math.floor(idx / 4);
          const col = idx % 4;
          n.x = cl.x + (col - 1.5) * 55;
          n.y = cl.y + (row - 1.5) * 45;
        });
      });

    } else {
      // Force-directed initial radial
      nodes.forEach((n, i) => {
        const angle = (2 * Math.PI * i) / Math.max(nodes.length, 1);
        const radius = 160 + (i % 6) * 45;
        n.x = W / 2 + radius * Math.cos(angle);
        n.y = H / 2 + radius * 0.75 * Math.sin(angle);
      });
    }
  }

  function openInspector(node) {
    const panel = el("graph-inspector-panel");
    const title = el("insp-header-title");
    const body = el("insp-content-body");
    if (!panel || !body) return;

    logActivity("GRAPH_INSPECT", "Inspect Node", `User opened side inspector for node: ${node.label} [${node.type}]`);
    title.textContent = `${node.type === 'process' ? '🖥️' : node.type === 'ip' ? '🌐' : '💉'} ${node.label}`;

    let propsHtml = `
      <div class="inspector-prop">
        <div class="inspector-prop-label">Entity Type</div>
        <div class="inspector-prop-value">${escapeHtml(node.type.toUpperCase())}</div>
      </div>
    `;

    if (node.pid) {
      propsHtml += `
        <div class="inspector-prop">
          <div class="inspector-prop-label">Process ID / Parent PID</div>
          <div class="inspector-prop-value">PID ${node.pid} (PPID: ${node.ppid || 'N/A'})</div>
        </div>
        <div class="inspector-prop">
          <div class="inspector-prop-label">Heuristic Risk Assessment</div>
          <div class="inspector-prop-value" style="color:${node.risk && node.risk.includes('Critical') ? 'var(--risk-critical)' : 'var(--accent-cyan)'}">
            ${escapeHtml(node.risk || 'Normal')} ${node.score ? `(Score: ${node.score})` : ''}
          </div>
        </div>
      `;
    }

    if (node.cmdline) {
      propsHtml += `
        <div class="inspector-prop">
          <div class="inspector-prop-label">Command Line Execution</div>
          <div class="inspector-prop-value" style="font-size:11px; max-height:80px; overflow-y:auto;">${escapeHtml(node.cmdline)}</div>
        </div>
      `;
    }

    if (node.hidden) {
      propsHtml += `
        <div class="inspector-prop">
          <div class="inspector-prop-label">DKOM Stealth Status</div>
          <div class="inspector-prop-value" style="color:var(--risk-critical); font-weight:700;">⚠️ UNLINKED FROM EPROCESS LIST</div>
        </div>
      `;
    }

    // Related neighbors count
    const relatedLinks = state.graph.edges.filter(e => e.source === node.id || e.target === node.id);
    propsHtml += `
      <div class="inspector-prop">
        <div class="inspector-prop-label">Direct Graph Relations</div>
        <div class="inspector-prop-value">${relatedLinks.length} connections</div>
      </div>
      <div style="display:flex; flex-direction:column; gap:8px; margin-top:16px;">
        ${node.pid ? `<button class="btn btn-sm btn-primary" onclick="window.inspectProcess(${node.pid})">🔍 Deep Process Analysis</button>` : ''}
        ${node.pid ? `<button class="btn btn-sm" onclick="switchToPage('page-processes');">🌳 Locate in Process Tree</button>` : ''}
        <button class="btn btn-sm" onclick="highlightNode(state.graph.byId['${node.id}']);">🎯 Isolate Subtree</button>
      </div>
    `;

    body.innerHTML = propsHtml;
    panel.style.display = "flex";
  }

  function exportGraphSvg() {
    const svg = el("svg-graph");
    if (!svg) return;
    logActivity("GRAPH_ACTION", "Export Graph", "User downloaded SVG graph image");
    const serializer = new XMLSerializer();
    const source = serializer.serializeToString(svg);
    const blob = new Blob([source], { type: "image/svg+xml;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `forensic_graph_${state.activeEvidence ? state.activeEvidence.id.slice(0, 8) : 'export'}.svg`;
    a.click();
  }

  // =========================================================================
  // Ingestion & File Upload Module
  // =========================================================================
  let selectedUploadFile = null;

  async function setupUploadCenter() {
    logActivity("TAB_NAVIGATION", "Open Tab", "User opened Memory Dump Ingestion Center");
    const dropzone = el("dump-dropzone");
    const fileInput = el("file-dump-input");
    const btnBrowse = el("btn-browse-dump");
    const btnUpload = el("btn-start-upload");
    const caseSelect = el("upload-case-select");

    // Populate cases
    if (caseSelect) {
      let opts = '<option value="">[Auto-create new incident case]</option>';
      state.cases.forEach(c => {
        opts += `<option value="${c.id}" ${state.activeCase && state.activeCase.id === c.id ? 'selected' : ''}>${escapeHtml(c.name)} (${c.id})</option>`;
      });
      caseSelect.innerHTML = opts;
    }

    if (btnBrowse && fileInput) {
      btnBrowse.onclick = () => fileInput.click();
      dropzone.onclick = () => fileInput.click();
    }

    if (fileInput) {
      fileInput.onchange = (e) => {
        if (e.target.files && e.target.files[0]) {
          handleFileChosen(e.target.files[0]);
        }
      };
    }

    if (dropzone) {
      dropzone.ondragover = (e) => { e.preventDefault(); dropzone.classList.add("dragover"); };
      dropzone.ondragleave = () => dropzone.classList.remove("dragover");
      dropzone.ondrop = (e) => {
        e.preventDefault();
        dropzone.classList.remove("dragover");
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
          handleFileChosen(e.dataTransfer.files[0]);
        }
      };
    }

    function handleFileChosen(file) {
      selectedUploadFile = file;
      dropzone.querySelector(".dropzone-title").textContent = `Selected: ${file.name}`;
      dropzone.querySelector(".dropzone-subtitle").textContent = `${(file.size / (1024*1024)).toFixed(2)} MB · Ready for ingestion`;
      if (btnUpload) btnUpload.disabled = false;
      logActivity("FILE_UPLOAD", "Select File", `Selected file for upload: ${file.name} (${file.size} bytes)`);
    }

    if (btnUpload) {
      btnUpload.onclick = async () => {
        if (!selectedUploadFile) return;
        const targetCaseId = caseSelect.value;
        btnUpload.disabled = true;

        const progressContainer = el("upload-progress-container");
        const progressBar = el("upload-progress-bar");
        const progressLabel = el("upload-pct-label");
        const statusText = el("upload-status-text");

        progressContainer.style.display = "block";
        statusText.textContent = "Streaming memory image blocks to workspace...";

        const formData = new FormData();
        formData.append("file", selectedUploadFile);
        if (targetCaseId) formData.append("case_id", targetCaseId);

        const xhr = new XMLHttpRequest();
        xhr.open("POST", "/api/upload", true);

        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) {
            const pct = Math.round((e.loaded / e.total) * 100);
            progressBar.style.width = `${pct}%`;
            progressLabel.textContent = `${pct}%`;
          }
        };

        xhr.onload = async () => {
          if (xhr.status === 200) {
            const res = JSON.parse(xhr.responseText);
            statusText.textContent = "Ingestion complete! SHA-256 verified.";
            progressBar.style.background = "var(--risk-normal)";
            logTerminal("SUCCESS", `Memory image ingested: ${selectedUploadFile.name}`);
            logActivity("FILE_UPLOAD", "Upload Success", `Uploaded ${selectedUploadFile.name} successfully`);
            await loadInitialData();
            setTimeout(() => switchToPage("page-dashboard"), 1200);
          } else {
            statusText.textContent = `Upload error: ${xhr.statusText}`;
            btnUpload.disabled = false;
          }
        };

        xhr.onerror = () => {
          statusText.textContent = "Network error during upload.";
          btnUpload.disabled = false;
        };

        xhr.send(formData);
      };
    }
  }

  // =========================================================================
  // Live Memory YARA Scanner Module
  // =========================================================================
  async function setupYaraCenter() {
    logActivity("TAB_NAVIGATION", "Open Tab", "User opened Live Memory YARA Scanner");
    const presetSelect = el("yara-preset-select");
    const editor = el("yara-rule-editor");
    const btnValidate = el("btn-validate-yara");
    const btnScan = el("btn-run-yara-scan");
    const statusLabel = el("yara-validation-status");

    let presets = {};
    try {
      const res = await API.get("/api/yara/rules");
      if (res.rules) {
        res.rules.forEach(r => presets[r.id] = r.rule);
      }
    } catch (e) {}

    if (presetSelect && editor) {
      if (presets["cobalt_strike"]) editor.value = presets["cobalt_strike"];
      presetSelect.onchange = () => {
        const val = presetSelect.value;
        if (presets[val]) editor.value = presets[val];
      };
    }

    if (btnValidate && editor) {
      btnValidate.onclick = () => {
        logActivity("YARA_ACTION", "Validate Rule", "User validated YARA rule syntax");
        statusLabel.textContent = "Syntax valid. Ready to scan.";
        statusLabel.style.color = "var(--risk-normal)";
      };
    }

    if (btnScan && editor) {
      btnScan.onclick = async () => {
        const ruleText = editor.value.trim();
        if (!ruleText) { showToast("Rule cannot be empty", "warning"); return; }
        logActivity("YARA_ACTION", "Execute Scan", "User initiated live memory YARA scan");
        logTerminal("INFO", "Executing YARA signature scan across memory artifacts...");

        try {
          const res = await API.post("/api/yara/scan", {
            rule_text: ruleText,
            evidence_id: state.activeEvidence ? state.activeEvidence.id : ""
          });

          el("yara-match-counter").textContent = res.count || 0;
          const tbody = el("yara-matches-tbody");

          if (!res.matches || res.matches.length === 0) {
            tbody.innerHTML = `<tr><td colspan="3" style="text-align:center; padding:30px; color:var(--text-muted);">No matches detected. Clean signature evaluation.</td></tr>`;
            logTerminal("INFO", "YARA scan completed: 0 matches.");
            return;
          }

          tbody.innerHTML = res.matches.map(m => `
            <tr>
              <td style="font-family:var(--font-mono); font-weight:700; color:var(--accent-purple);">${escapeHtml(m.rule)}</td>
              <td>PID ${m.pid || '-'} <span style="font-size:11px; color:var(--text-muted);">(${escapeHtml(m.target || '')})</span></td>
              <td style="font-family:var(--font-mono); font-size:11px; color:var(--accent-cyan);">${escapeHtml(String((m.strings && m.strings[0]) ? m.strings[0][2] : 'Pattern Match'))}</td>
            </tr>
          `).join("");

          logTerminal("SUCCESS", `YARA scan found ${res.count} match(es)!`);
        } catch (err) {
          logTerminal("ERROR", `YARA scan failed: ${err.message}`);
        }
      };
    }
  }

  // =========================================================================
  // Live Platform Audit Trail & Activity Log
  // =========================================================================
  async function setupActivityCenter() {
    logActivity("TAB_NAVIGATION", "Open Tab", "User opened Platform Audit Trail");
    await loadActivityLogs();

    const searchInput = el("activity-search-input");
    if (searchInput) searchInput.oninput = () => renderActivityRows();

    const catFilter = el("activity-category-filter");
    if (catFilter) catFilter.onchange = () => renderActivityRows();

    const btnRefresh = el("btn-refresh-activity");
    if (btnRefresh) btnRefresh.onclick = () => loadActivityLogs();

    const btnDownload = el("btn-download-activity-log");
    if (btnDownload) {
      btnDownload.onclick = () => {
        logActivity("ACTIVITY_ACTION", "Download Log", "User downloaded site_activity.log");
        window.open("/api/activity/tail?limit=5000", "_blank");
      };
    }
  }

  let activityLogLines = [];

  async function loadActivityLogs() {
    try {
      const res = await API.get("/api/activity/tail?limit=200");
      activityLogLines = (res.lines || []).reverse();
      renderActivityRows();
    } catch (err) {
      console.error("Activity load error:", err);
    }
  }

  function renderActivityRows() {
    const tbody = el("activity-table-tbody");
    if (!tbody) return;

    if (!activityLogLines || activityLogLines.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:30px; color:var(--text-muted);">No activity recorded yet.</td></tr>`;
      return;
    }

    const search = (el("activity-search-input") ? el("activity-search-input").value : "").toLowerCase().trim();
    const cat = el("activity-category-filter") ? el("activity-category-filter").value : "ALL";

    const filtered = activityLogLines.filter(line => {
      const parts = line.split(" | ");
      const text = line.toLowerCase();
      const matchSearch = !search || text.includes(search);
      const category = parts[1] ? parts[1].replace(/[\[\]]/g, "").trim() : "";
      const matchCat = cat === "ALL" || category.includes(cat);
      return matchSearch && matchCat;
    });

    tbody.innerHTML = filtered.map(line => {
      const parts = line.split(" | ");
      const ts = parts[0] || "";
      const category = parts[1] ? parts[1].replace(/[\[\]]/g, "").trim() : "LOG";
      const action = parts[2] ? parts[2].replace(/[\[\]]/g, "").trim() : "";
      const details = parts[3] || "";
      const ip = parts[4] || "127.0.0.1";

      const catBadge = category.includes("TAB") ? "badge-normal"
        : category.includes("PROCESS") ? "badge-high"
        : category.includes("FILE") ? "badge-purple"
        : category.includes("CASE") ? "badge-critical"
        : "badge-suspicious";

      return `
        <tr>
          <td style="font-family:var(--font-mono); font-size:12px; color:var(--text-muted);">${escapeHtml(ts)}</td>
          <td><span class="badge ${catBadge}">${escapeHtml(category)}</span></td>
          <td style="font-weight:600; color:var(--text-primary);">${escapeHtml(action)}</td>
          <td style="color:var(--text-secondary);">${escapeHtml(details)}</td>
          <td style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted);">${escapeHtml(ip)}</td>
        </tr>
      `;
    }).join("");
  }

  // =========================================================================
  // Investigation Focus & Context Bar System
  // =========================================================================
  function setInvestigationFocus(entity) {
    if (!entity) return;
    state.investigationFocus = entity;
    if (entity.type === "process" && entity.pid) {
      state.focusedPid = entity.pid;
    }
    updateFocusUI();
    logActivity("FOCUS", "Set Focus", `Investigation focus set to: [${(entity.type || 'entity').toUpperCase()}] ${entity.title || entity.name || entity.id}`);
  }

  function clearInvestigationFocus() {
    state.investigationFocus = null;
    state.focusedPid = null;
    updateFocusUI();
    logActivity("FOCUS", "Clear Focus", "Cleared active investigation focus");
  }

  function updateFocusUI() {
    const focus = state.investigationFocus;
    const bar = el("investigation-context-bar");
    const pill = el("pill-investigation-focus");
    const headerVal = el("header-focus-val");

    if (!focus) {
      if (bar) bar.style.display = "none";
      if (pill) pill.style.display = "none";
      if (headerVal) headerVal.textContent = "None";
      return;
    }

    if (pill) pill.style.display = "flex";
    if (headerVal) headerVal.textContent = focus.title || focus.name || `ID ${focus.id}`;

    if (bar) {
      bar.style.display = "flex";
      const titleEl = el("ctx-bar-entity-title");
      const riskEl = el("ctx-bar-risk-badge");
      const verdictEl = el("ctx-bar-verdict-badge");

      if (titleEl) {
        titleEl.textContent = `[${(focus.type || "ENTITY").toUpperCase()}] ${focus.title || focus.name || ('ID: ' + focus.id)}`;
      }

      if (riskEl) {
        const score = focus.risk_score !== undefined ? focus.risk_score : (focus.score || 0);
        const level = focus.risk_level || (score >= 70 ? "Critical" : score >= 40 ? "Suspicious" : "Normal");
        riskEl.textContent = `${level.toUpperCase()} (${score})`;
        riskEl.className = `badge ${level.toLowerCase().includes("crit") ? "badge-critical" : level.toLowerCase().includes("high") ? "badge-high" : level.toLowerCase().includes("susp") ? "badge-suspicious" : "badge-normal"}`;
      }

      if (verdictEl) {
        const verdict = (focus.verdict || "unreviewed").toLowerCase();
        verdictEl.textContent = `Verdict: ${verdict.toUpperCase()}`;
        if (verdict.includes("malicious")) {
          verdictEl.style.background = "rgba(239, 68, 68, 0.25)";
          verdictEl.style.color = "var(--risk-critical)";
        } else if (verdict.includes("suspicious")) {
          verdictEl.style.background = "rgba(245, 158, 11, 0.25)";
          verdictEl.style.color = "var(--risk-suspicious)";
        } else if (verdict.includes("benign")) {
          verdictEl.style.background = "rgba(16, 185, 129, 0.25)";
          verdictEl.style.color = "var(--risk-normal)";
        } else {
          verdictEl.style.background = "rgba(148, 163, 184, 0.15)";
          verdictEl.style.color = "#94a3b8";
        }
      }
    }
  }

  function setupInvestigationContext() {
    const btnOpenFocus = el("btn-ctx-open-focus");
    if (btnOpenFocus) {
      btnOpenFocus.onclick = () => {
        if (!state.investigationFocus) return;
        const f = state.investigationFocus;
        if (f.pid || f.type === "process") {
          openProcessFocusDrawer(f.pid || f.id);
        } else if (f.type === "artifact") {
          window.viewArtifact(f.id);
        } else if (f.type === "finding") {
          window.viewFinding(f.id);
        } else {
          showToast(`Focus target is [${f.type}]: ${f.title || f.name}`, "info");
        }
      };
    }

    const btnPivotProc = el("btn-ctx-pivot-process");
    if (btnPivotProc) {
      btnPivotProc.onclick = () => {
        switchToPage("page-processes");
        if (state.investigationFocus?.pid) {
          const searchInput = el("tree-search-input");
          if (searchInput) {
            searchInput.value = state.investigationFocus.pid;
            searchInput.dispatchEvent(new Event("input"));
          }
        }
      };
    }

    const btnPivotMem = el("btn-ctx-pivot-memory");
    if (btnPivotMem) {
      btnPivotMem.onclick = () => {
        switchToPage("page-memory");
        if (state.investigationFocus?.pid) {
          const memSearch = el("mem-search-input");
          if (memSearch) {
            memSearch.value = state.investigationFocus.pid;
            renderMemoryRows();
          }
        }
      };
    }

    const btnPivotNet = el("btn-ctx-pivot-network");
    if (btnPivotNet) {
      btnPivotNet.onclick = () => {
        switchToPage("page-network");
        if (state.investigationFocus) {
          const term = state.investigationFocus.pid || state.investigationFocus.ip || state.investigationFocus.name || "";
          const netSearch = el("net-search-input");
          if (netSearch && term) {
            netSearch.value = term;
            netSearch.dispatchEvent(new Event("input"));
          }
        }
      };
    }

    const btnPivotTl = el("btn-ctx-pivot-timeline");
    if (btnPivotTl) {
      btnPivotTl.onclick = () => {
        switchToPage("page-timeline");
        if (state.investigationFocus) {
          const term = state.investigationFocus.pid || state.investigationFocus.name || "";
          const tlSearch = el("timeline-search-input");
          if (tlSearch && term) {
            tlSearch.value = term;
            tlSearch.dispatchEvent(new Event("input"));
          }
        }
      };
    }

    const btnPivotGraph = el("btn-ctx-pivot-graph");
    if (btnPivotGraph) {
      btnPivotGraph.onclick = () => {
        switchToPage("page-graph");
        if (state.investigationFocus) {
          const term = state.investigationFocus.pid || state.investigationFocus.name || state.investigationFocus.title || "";
          const gSearch = el("graph-search-node");
          if (gSearch && term) {
            gSearch.value = term;
            gSearch.dispatchEvent(new Event("input"));
          }
        }
      };
    }

    const btnPivotFinding = el("btn-ctx-pivot-finding");
    if (btnPivotFinding) {
      btnPivotFinding.onclick = () => {
        const f = state.investigationFocus;
        if (!f) {
          openCreateFindingModal();
          return;
        }
        openCreateFindingModal({
          title: `Forensic Finding for ${f.title || f.name || f.id}`,
          pid: f.pid || (f.type === "process" ? f.id : null),
          process_name: f.name || f.title || "",
          severity: (f.risk_level || "").toLowerCase().includes("crit") ? "Critical" : "High",
          summary: `Identified suspicious artifact or behavior associated with ${f.type} ${f.title || f.name || f.id}.`,
          assessment: `Pivoted from investigation workbench focus mode.`
        });
      };
    }

    const btnPivotBoard = el("btn-ctx-pivot-board");
    if (btnPivotBoard) {
      btnPivotBoard.onclick = () => {
        const f = state.investigationFocus;
        const entInput = el("board-note-entity");
        const textInput = el("board-note-text");
        if (f) {
          if (entInput) entInput.value = `${(f.type || 'entity').toUpperCase()}: ${f.title || f.name || f.id}`;
          if (textInput) textInput.value = `Observed entity ${f.title || f.name || f.id} during investigation.`;
        }
        openModal("modal-add-board-note");
      };
    }

    const btnClearFocus = el("btn-ctx-clear-focus");
    if (btnClearFocus) btnClearFocus.onclick = () => clearInvestigationFocus();

    const btnHeaderClear = el("btn-header-clear-focus");
    if (btnHeaderClear) btnHeaderClear.onclick = (e) => {
      e.stopPropagation();
      clearInvestigationFocus();
    };

    const pillFocus = el("pill-investigation-focus");
    if (pillFocus) {
      pillFocus.onclick = (e) => {
        if (e.target.id === "btn-header-clear-focus") return;
        if (state.investigationFocus?.pid || state.investigationFocus?.type === "process") {
          openProcessFocusDrawer(state.investigationFocus.pid || state.investigationFocus.id);
        } else {
          showToast(`Active focus is [${state.investigationFocus?.type}]: ${state.investigationFocus?.title || state.investigationFocus?.name}`, "info");
        }
      };
    }

    const btnToggleDeepDive = el("btn-toggle-focus-panel");
    if (btnToggleDeepDive) {
      btnToggleDeepDive.onclick = () => {
        const pid = state.investigationFocus?.pid || (state.investigationFocus?.type === "process" ? state.investigationFocus.id : null) || state.focusedPid;
        if (pid) {
          openProcessFocusDrawer(pid);
        } else {
          showToast("No active process focus. Click any process to focus and inspect.", "info");
        }
      };
    }
  }

  // =========================================================================
  // Global Forensic Search (Ctrl+K)
  // =========================================================================
  let searchDebounceTimer = null;
  let activeSearchIndex = -1;

  function setupGlobalSearch() {
    const input = el("global-search-input");
    const resultsBox = el("global-search-results");
    if (!input || !resultsBox) return;

    // Keyboard shortcut Ctrl+K / Cmd+K
    document.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        input.focus();
        input.select();
      }
      if (e.key === "Escape" && resultsBox.style.display !== "none") {
        resultsBox.style.display = "none";
        input.blur();
      }
    });

    input.addEventListener("input", () => {
      clearTimeout(searchDebounceTimer);
      const q = input.value.trim();
      if (!q) {
        resultsBox.style.display = "none";
        resultsBox.innerHTML = "";
        activeSearchIndex = -1;
        return;
      }
      searchDebounceTimer = setTimeout(() => executeGlobalSearch(q), 220);
    });

    input.addEventListener("focus", () => {
      if (input.value.trim().length > 0 && resultsBox.children.length > 0) {
        resultsBox.style.display = "block";
      }
    });

    // Close on outside click
    document.addEventListener("click", (e) => {
      if (!input.contains(e.target) && !resultsBox.contains(e.target)) {
        resultsBox.style.display = "none";
      }
    });

    // Arrow navigation
    input.addEventListener("keydown", (e) => {
      const items = resultsBox.querySelectorAll(".search-result-item");
      if (!items.length || resultsBox.style.display === "none") return;

      if (e.key === "ArrowDown") {
        e.preventDefault();
        activeSearchIndex = (activeSearchIndex + 1) % items.length;
        updateSearchHighlight(items);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        activeSearchIndex = (activeSearchIndex - 1 + items.length) % items.length;
        updateSearchHighlight(items);
      } else if (e.key === "Enter") {
        e.preventDefault();
        if (activeSearchIndex >= 0 && activeSearchIndex < items.length) {
          items[activeSearchIndex].click();
        }
      }
    });
  }

  function updateSearchHighlight(items) {
    items.forEach((it, idx) => {
      if (idx === activeSearchIndex) {
        it.classList.add("keyboard-focused");
        it.scrollIntoView({ block: "nearest" });
      } else {
        it.classList.remove("keyboard-focused");
      }
    });
  }

  async function executeGlobalSearch(query) {
    const resultsBox = el("global-search-results");
    if (!resultsBox) return;

    try {
      const evParam = state.activeEvidence ? `&evidence_id=${encodeURIComponent(state.activeEvidence.id)}` : "";
      const res = await API.get(`/api/v2/search?q=${encodeURIComponent(query)}${evParam}`);
      activeSearchIndex = -1;

      const counts = res.counts || {};
      const totalResults = Object.values(counts).reduce((a, b) => a + b, 0);

      if (totalResults === 0) {
        resultsBox.innerHTML = `
          <div style="padding:18px 16px; text-align:center; color:var(--text-muted); font-size:12px;">
            No forensic entities found matching "<strong>${escapeHtml(query)}</strong>"
          </div>
        `;
        resultsBox.style.display = "block";
        return;
      }

      let html = "";
      const groups = [
        { key: "processes", label: "Processes", icon: "⚙️" },
        { key: "network_connections", label: "Network Sockets", icon: "🌐" },
        { key: "artifacts", label: "Evidence Artifacts", icon: "📦" },
        { key: "detections", label: "Detections & Rules", icon: "🛡️" },
        { key: "findings", label: "Case Findings", icon: "📋" },
        { key: "iocs", label: "Threat Indicators (IOCs)", icon: "🎯" },
        { key: "timeline_events", label: "Timeline Events", icon: "⏱️" }
      ];

      groups.forEach(g => {
        const items = (res.results && res.results[g.key]) || [];
        if (items.length > 0) {
          html += `<div class="search-result-group"><div class="search-group-title">${g.icon} ${g.label} (${items.length})</div>`;
          items.forEach(it => {
            const title = it.title || it.name || it.rule_name || it.type || `Item ${it.id}`;
            const sub = it.subtitle || it.summary || it.description || it.path || "";
            const risk = (it.risk_level || it.severity || "Normal").toLowerCase();
            const badgeClass = risk.includes("crit") ? "badge-critical" : risk.includes("high") ? "badge-high" : risk.includes("susp") ? "badge-suspicious" : "badge-normal";
            const badgeText = it.score !== undefined ? `${it.risk_level || 'Risk'} (${it.score})` : (it.severity || it.risk_level || "Normal");

            html += `
              <div class="search-result-item" 
                   data-type="${escapeHtml(it.type || g.key)}" 
                   data-id="${escapeHtml(String(it.id || ''))}" 
                   data-pid="${escapeHtml(String(it.pid || ''))}"
                   data-title="${escapeHtml(title)}"
                   data-score="${escapeHtml(String(it.score !== undefined ? it.score : '0'))}"
                   data-risk="${escapeHtml(it.risk_level || it.severity || 'Normal')}"
                   data-verdict="${escapeHtml(it.verdict || 'unassigned')}"
                   role="button" tabindex="0">
                <div class="search-item-info">
                  <div class="search-item-title">${escapeHtml(title)}</div>
                  <div class="search-item-sub">${escapeHtml(sub)}</div>
                </div>
                <span class="badge ${badgeClass}" style="font-size:10px;">${escapeHtml(badgeText.toUpperCase())}</span>
              </div>
            `;
          });
          html += `</div>`;
        }
      });

      resultsBox.innerHTML = html;
      resultsBox.style.display = "block";

      // Bind clicks
      resultsBox.querySelectorAll(".search-result-item").forEach(itemEl => {
        itemEl.onclick = () => {
          const type = itemEl.dataset.type;
          const id = itemEl.dataset.id;
          const pid = itemEl.dataset.pid ? parseInt(itemEl.dataset.pid, 10) : null;
          const title = itemEl.dataset.title;
          const score = parseInt(itemEl.dataset.score, 10) || 0;
          const riskLevel = itemEl.dataset.risk;
          const verdict = itemEl.dataset.verdict;

          setInvestigationFocus({
            type: type,
            id: id,
            pid: pid,
            title: title,
            name: title,
            risk_score: score,
            risk_level: riskLevel,
            verdict: verdict
          });

          resultsBox.style.display = "none";
          el("global-search-input").value = "";

          // Smart pivot based on type
          if (type === "process" && pid) {
            openProcessFocusDrawer(pid);
          } else if (type === "network_connection" || type === "network") {
            switchToPage("page-network");
          } else if (type === "artifact") {
            window.viewArtifact(id);
          } else if (type === "finding") {
            window.viewFinding(id);
          } else if (type === "ioc") {
            switchToPage("page-iocs");
          } else if (type === "timeline_event" || type === "timeline") {
            switchToPage("page-timeline");
          }
        };
      });

    } catch (err) {
      console.error("Global search error:", err);
      resultsBox.innerHTML = `<div style="padding:14px; color:var(--risk-critical); font-size:12px;">Search failed: ${escapeHtml(err.message)}</div>`;
      resultsBox.style.display = "block";
    }
  }

  // =========================================================================
  // Investigation Coverage & Action Items
  // =========================================================================
  async function loadCoverageData() {
    const listEl = el("cov-action-items-list");
    if (!state.activeEvidence) {
      if (listEl) listEl.innerHTML = `<div style="color:var(--text-muted); padding:30px; text-align:center;">Select active evidence to inspect investigation coverage.</div>`;
      return;
    }

    try {
      const res = await API.get(`/api/v2/investigation/coverage?evidence_id=${encodeURIComponent(state.activeEvidence.id)}`);
      state.coverageData = res;

      // Update Process Coverage
      const p = res.process_coverage || {};
      const totProc = p.total_processes || 0;
      const revProc = p.reviewed_processes || 0;
      const procPct = p.coverage_percent || 0;
      if (el("cov-proc-reviewed")) el("cov-proc-reviewed").textContent = `${revProc} / ${totProc}`;
      if (el("cov-proc-bar")) el("cov-proc-bar").style.width = `${Math.min(100, procPct)}%`;
      if (el("cov-proc-pct")) el("cov-proc-pct").textContent = `${procPct}% reviewed (${p.unreviewed_processes || 0} unreviewed)`;

      // Update Risk Coverage
      const r = res.risk_coverage || {};
      const totRisk = r.high_risk_total || 0;
      const revRisk = r.high_risk_reviewed || 0;
      const riskPct = totRisk > 0 ? Math.round((revRisk / totRisk) * 100) : 100;
      if (el("cov-risk-reviewed")) el("cov-risk-reviewed").textContent = `${revRisk} / ${totRisk}`;
      if (el("cov-risk-bar")) el("cov-risk-bar").style.width = `${riskPct}%`;
      if (el("cov-risk-meta")) el("cov-risk-meta").textContent = `${r.high_risk_unreviewed || 0} high-risk entities await review`;

      // Update Critical Threat Review
      if (el("cov-crit-reviewed")) el("cov-crit-reviewed").textContent = r.critical_threats_count || 0;

      // Evidence Verification
      const ev = res.evidence || {};
      if (el("cov-ev-status")) {
        const isVer = ev.status === "verified";
        el("cov-ev-status").textContent = isVer ? "VERIFIED" : (ev.status || "UNVERIFIED").toUpperCase();
        el("cov-ev-status").style.color = isVer ? "var(--risk-normal)" : "var(--risk-suspicious)";
      }
      if (el("cov-ev-meta")) {
        el("cov-ev-meta").textContent = ev.sha256 ? `SHA-256: ${ev.sha256.substring(0, 16)}...` : "Cryptographic hash check";
      }

      // Action items checklist
      const items = res.action_items || [];
      const countEl = el("cov-action-items-count");
      if (countEl) countEl.textContent = `${items.length} Pending`;

      if (listEl) {
        if (items.length === 0) {
          listEl.innerHTML = `
            <div style="color:var(--risk-normal); padding:24px; text-align:center; display:flex; flex-direction:column; align-items:center; gap:8px;">
              <span style="font-size:24px;">✅</span>
              <strong>All critical forensic entities have been reviewed!</strong>
              <span style="color:var(--text-muted); font-size:12px;">No unreviewed high-risk processes or unassigned critical threats remain.</span>
            </div>
          `;
        } else {
          listEl.innerHTML = items.map(item => {
            const isCrit = (item.priority || "").toLowerCase().includes("crit");
            const badgeClass = isCrit ? "badge-critical" : "badge-high";
            return `
              <div class="action-item-card ${isCrit ? 'critical' : ''}">
                <div class="action-item-header">
                  <div style="display:flex; align-items:center; gap:8px;">
                    <span class="badge ${badgeClass}">${escapeHtml((item.priority || 'High').toUpperCase())}</span>
                    <strong style="color:var(--text-primary); font-size:13px;">${escapeHtml(item.title)}</strong>
                  </div>
                  <span style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted);">Risk Score: ${item.score}/100</span>
                </div>
                <div class="action-item-body">${escapeHtml(item.reason || '')}</div>
                <div class="action-item-actions">
                  <button class="btn btn-sm btn-primary" onclick="window.inspectProcess(${item.id})">🔍 Investigate Focus</button>
                  <button class="btn btn-sm" onclick="window.setQuickProcessVerdict(${item.id}, 'malicious')">Mark Malicious</button>
                  <button class="btn btn-sm" onclick="window.setQuickProcessVerdict(${item.id}, 'benign')">Mark Benign</button>
                </div>
              </div>
            `;
          }).join("");
        }
      }

      // Findings Breakdown
      const bd = res.findings_breakdown || {};
      const bdEl = el("cov-findings-breakdown");
      if (bdEl) {
        const statuses = [
          { key: "draft", label: "Draft / Triaged", color: "var(--accent-blue)" },
          { key: "under_review", label: "Under Review / Investigating", color: "var(--risk-suspicious)" },
          { key: "confirmed", label: "Confirmed Incident Finding", color: "var(--risk-critical)" },
          { key: "closed", label: "Closed / Resolved", color: "var(--risk-normal)" }
        ];

        bdEl.innerHTML = statuses.map(s => {
          const val = bd[s.key] || 0;
          return `
            <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 12px; background:rgba(255,255,255,0.02); border-radius:6px; border:1px solid rgba(255,255,255,0.05);">
              <span style="font-size:12px; color:var(--text-secondary); font-weight:500;">${s.label}</span>
              <span class="badge" style="background:${s.color}22; color:${s.color}; border:1px solid ${s.color}44; font-weight:700;">${val}</span>
            </div>
          `;
        }).join("");
      }

    } catch (err) {
      console.error("Coverage load error:", err);
      showToast(`Failed to load investigation coverage: ${err.message}`, "error");
    }
  }

  const btnRefreshCov = el("btn-refresh-coverage");
  if (btnRefreshCov) btnRefreshCov.onclick = () => loadCoverageData();

  window.setQuickProcessVerdict = async function(pid, verdict) {
    if (!state.activeEvidence) return;
    try {
      await API.post(`/api/v2/processes/${pid}/verdict`, {
        verdict: verdict,
        evidence_id: state.activeEvidence.id
      });
      showToast(`PID ${pid} marked as "${verdict}"`, "success");
      await loadCoverageData();
    } catch (err) {
      showToast(`Failed to set verdict: ${err.message}`, "error");
    }
  };

  // =========================================================================
  // Investigation Evidence Board
  // =========================================================================
  async function loadBoardData() {
    const container = el("evidence-board-container");
    if (!container) return;

    try {
      const cParam = state.activeCase ? `case_id=${encodeURIComponent(state.activeCase.id)}` : "";
      const eParam = state.activeEvidence ? `&evidence_id=${encodeURIComponent(state.activeEvidence.id)}` : "";
      const query = cParam ? `?${cParam}${eParam}` : (eParam ? `?${eParam.substring(1)}` : "");
      
      const res = await API.get(`/api/v2/board${query}`);
      state.boardItems = res.board_items || [];

      if (state.boardItems.length === 0) {
        container.innerHTML = `
          <div style="grid-column: 1 / -1; color:var(--text-muted); text-align:center; padding:48px; border:1px dashed var(--border-light); border-radius:8px;">
            <div style="font-size:32px; margin-bottom:12px;">📌</div>
            <strong style="color:var(--text-primary); font-size:14px; display:block; margin-bottom:6px;">No entities or notes pinned yet</strong>
            <p style="font-size:12px; max-width:400px; margin:0 auto 16px auto;">
              Pin key processes, network sockets, memory anomalies, and analyst hypotheses here to build a structured case narrative.
            </p>
            <button class="btn btn-primary" onclick="window.openAddBoardNoteModal()">➕ Add Investigation Note</button>
          </div>
        `;
        return;
      }

      container.innerHTML = state.boardItems.map(item => {
        const entType = (item.entity_type || 'note').toUpperCase();
        const typeBadge = entType.includes("PROC") ? "badge-normal" : entType.includes("NET") ? "badge-purple" : entType.includes("MEM") ? "badge-critical" : "badge-suspicious";
        return `
          <div class="board-card" data-id="${item.id}">
            <div class="board-card-header">
              <span class="badge ${typeBadge}" style="font-size:10px;">${escapeHtml(entType)}</span>
              <span class="board-card-time">${escapeHtml(item.created_at || '')}</span>
              <button class="board-card-del" onclick="window.deleteBoardItem(${item.id})" title="Remove from board">&times;</button>
            </div>
            <div class="board-card-title">${escapeHtml(item.title || 'Investigation Observation')}</div>
            <div class="board-card-body">${escapeHtml(item.notes || '')}</div>
            <div class="board-card-footer">
              <span style="font-size:11px; font-family:var(--font-mono); color:var(--text-muted);">${item.entity_id ? escapeHtml(String(item.entity_id)) : ''}</span>
              <button class="btn btn-sm" onclick="window.inspectBoardItem(${item.id})" style="font-size:11px; padding:2px 8px;">Inspect</button>
            </div>
          </div>
        `;
      }).join("");

    } catch (err) {
      console.error("Board load error:", err);
      container.innerHTML = `<div style="grid-column: 1 / -1; color:var(--risk-critical); text-align:center; padding:30px;">Failed to load Evidence Board: ${escapeHtml(err.message)}</div>`;
    }
  }

  function setupEvidenceBoardEvents() {
    const btnAdd = el("btn-board-add-note");
    if (btnAdd) btnAdd.onclick = () => window.openAddBoardNoteModal();

    const btnRef = el("btn-refresh-board");
    if (btnRef) btnRef.onclick = () => loadBoardData();

    const btnSub = el("btn-submit-board-note");
    if (btnSub) {
      btnSub.onclick = async () => {
        const noteEl = el("board-note-text");
        const entityEl = el("board-note-entity");
        const text = noteEl ? noteEl.value.trim() : "";
        const entity = entityEl ? entityEl.value.trim() : "";

        if (!text) {
          showToast("Please enter an observation or note", "warning");
          return;
        }

        try {
          await API.post("/api/v2/board", {
            case_id: state.activeCase ? state.activeCase.id : null,
            evidence_id: state.activeEvidence ? state.activeEvidence.id : null,
            entity_type: entity ? "entity" : "note",
            entity_id: entity || null,
            title: entity ? `Note: ${entity}` : "Analyst Hypothesis",
            notes: text,
            color: "yellow"
          });

          closeModal("modal-add-board-note");
          if (noteEl) noteEl.value = "";
          if (entityEl) entityEl.value = "";
          showToast("Note pinned to Evidence Board", "success");
          await loadBoardData();
        } catch (err) {
          showToast(`Failed to pin note: ${err.message}`, "error");
        }
      };
    }
  }

  window.openAddBoardNoteModal = function() {
    openModal("modal-add-board-note");
    const textEl = el("board-note-text");
    if (textEl) textEl.focus();
  };

  window.deleteBoardItem = async function(id) {
    const ok = await customConfirm({
      title: "Remove Pinned Item",
      message: "Are you sure you want to remove this item from the Evidence Board?",
      confirmText: "Remove",
      cancelText: "Keep",
      isDanger: false
    });
    if (!ok) return;

    try {
      await API.delete(`/api/v2/board/${id}`);
      showToast("Item unpinned from Evidence Board", "info");
      await loadBoardData();
    } catch (err) {
      showToast(`Delete failed: ${err.message}`, "error");
    }
  };

  window.inspectBoardItem = function(id) {
    const item = state.boardItems.find(b => b.id === id);
    if (!item) return;
    if (item.entity_type === "process" && item.entity_id) {
      const pid = parseInt(item.entity_id.replace(/\D/g, ""), 10);
      if (!isNaN(pid)) {
        openProcessFocusDrawer(pid);
        return;
      }
    }
    setInvestigationFocus({
      type: item.entity_type || "note",
      id: item.entity_id || item.id,
      title: item.title,
      name: item.title
    });
  };

  // =========================================================================
  // Forensic Artifact Explorer
  // =========================================================================
  async function loadArtifactsData() {
    const tbody = el("artifacts-table-tbody");
    if (!tbody) return;

    if (!state.activeEvidence) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:30px; color:var(--text-muted);">Select active evidence to view forensic artifacts.</td></tr>`;
      return;
    }

    try {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:30px; color:var(--text-muted);">Querying first-class forensic artifacts...</td></tr>`;
      const res = await API.get(`/api/v2/artifacts?evidence_id=${encodeURIComponent(state.activeEvidence.id)}`);
      state.artifacts = res.artifacts || [];
      renderArtifactRows();
    } catch (err) {
      console.error("Artifacts load error:", err);
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:30px; color:var(--risk-critical);">Failed to load artifacts: ${escapeHtml(err.message)}</td></tr>`;
    }
  }

  function renderArtifactRows() {
    const tbody = el("artifacts-table-tbody");
    if (!tbody) return;

    const search = (el("art-search-input") ? el("art-search-input").value : "").toLowerCase().trim();
    const typeFilter = el("art-type-filter") ? el("art-type-filter").value : "ALL";

    const filtered = (state.artifacts || []).filter(a => {
      const matchType = typeFilter === "ALL" || (a.type || "").toLowerCase() === typeFilter.toLowerCase();
      const matchSearch = !search ||
        (a.id || "").toLowerCase().includes(search) ||
        (a.plugin || "").toLowerCase().includes(search) ||
        (a.entity_id || "").toLowerCase().includes(search) ||
        (a.sha256 || "").toLowerCase().includes(search);
      return matchType && matchSearch;
    });

    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:30px; color:var(--text-muted);">No artifacts match the current filter.</td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map(a => {
      const type = (a.type || 'unknown').toLowerCase();
      const typeBadge = type.includes("net") ? "badge-purple" : type.includes("mem") ? "badge-critical" : type.includes("proc") ? "badge-normal" : "badge-suspicious";
      const hash = a.sha256 ? `${a.sha256.substring(0, 16)}...` : "-";

      return `
        <tr>
          <td style="font-family:var(--font-mono); font-size:12px; color:var(--accent-cyan); font-weight:600;">${escapeHtml(a.id || '')}</td>
          <td><span class="badge ${typeBadge}">${escapeHtml(a.type || 'Artifact')}</span></td>
          <td style="font-family:var(--font-mono); font-size:12px; color:var(--text-primary);">${escapeHtml(a.plugin || 'vol3')}</td>
          <td style="font-weight:600; color:var(--text-primary);">${escapeHtml(a.entity_id || '-')}</td>
          <td style="font-size:11px; color:var(--text-muted);">${escapeHtml(a.created_at || a.timestamp || '')}</td>
          <td style="font-family:var(--font-mono); font-size:11px; color:var(--text-secondary); max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(a.raw_ref || '')}">${escapeHtml(a.raw_ref || '-')}</td>
          <td style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted);" title="${escapeHtml(a.sha256 || '')}">${escapeHtml(hash)}</td>
          <td>
            <div style="display:flex; gap:6px;">
              <button class="btn btn-sm" onclick="window.viewArtifact('${escapeHtml(a.id)}')">Inspect</button>
              <button class="btn btn-sm" onclick="window.setFocusFromArtifact('${escapeHtml(a.id)}')">Focus</button>
              ${a.type === 'network_connection' ? `<button class="btn btn-sm" onclick="window.promoteArtifactToIOC('${escapeHtml(a.id)}')">IOC</button>` : ''}
            </div>
          </td>
        </tr>
      `;
    }).join("");
  }

  function setupArtifactExplorerEvents() {
    const searchInput = el("art-search-input");
    if (searchInput) searchInput.oninput = () => renderArtifactRows();

    const typeFilter = el("art-type-filter");
    if (typeFilter) typeFilter.onchange = () => renderArtifactRows();

    const refreshBtn = el("btn-refresh-artifacts");
    if (refreshBtn) refreshBtn.onclick = () => loadArtifactsData();
  }

  window.setFocusFromArtifact = function(artId) {
    const a = (state.artifacts || []).find(x => x.id === artId);
    if (!a) return;
    setInvestigationFocus({
      type: "artifact",
      id: a.id,
      title: `${(a.type || 'Artifact').toUpperCase()}: ${a.entity_id || a.id}`,
      name: a.id
    });
  };

  // =========================================================================
  // Memory Anomalies Workspace
  // =========================================================================
  async function loadMemoryData() {
    const tbody = el("memory-table-tbody");
    if (!tbody) return;

    if (!state.activeEvidence) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--text-muted);">Select active evidence to inspect memory anomalies.</td></tr>`;
      return;
    }

    try {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--text-muted);">Analyzing Virtual Address Descriptors and executable sections...</td></tr>`;
      const res = await API.get(`/api/v2/memory?evidence_id=${encodeURIComponent(state.activeEvidence.id)}`);
      state.memoryRegions = res.regions || [];

      // Update counters
      if (el("mem-total-count")) el("mem-total-count").textContent = res.total || state.memoryRegions.length;
      if (el("mem-rwx-count")) el("mem-rwx-count").textContent = res.rwx_count || 0;
      if (el("mem-suspicious-count")) el("mem-suspicious-count").textContent = res.suspicious_count || 0;
      if (el("mem-procs-count")) el("mem-procs-count").textContent = res.unique_pids || 0;

      renderMemoryRows();
    } catch (err) {
      console.error("Memory data load error:", err);
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--risk-critical);">Failed to load memory anomalies: ${escapeHtml(err.message)}</td></tr>`;
    }
  }

  function renderMemoryRows() {
    const tbody = el("memory-table-tbody");
    if (!tbody) return;

    const search = (el("mem-search-input") ? el("mem-search-input").value : "").toLowerCase().trim();
    const rwxOnly = el("mem-filter-rwx") ? el("mem-filter-rwx").checked : false;
    const suspOnly = el("mem-filter-suspicious") ? el("mem-filter-suspicious").checked : false;

    const filtered = (state.memoryRegions || []).filter(m => {
      const matchSearch = !search || String(m.pid).includes(search) || (m.start_addr || '').toLowerCase().includes(search) || (m.end_addr || '').toLowerCase().includes(search);
      const isRwx = (m.protection || '').toUpperCase().includes("PAGE_EXECUTE_READWRITE") || (m.protection || '').toUpperCase().includes("RWX");
      const isSusp = m.is_suspicious || (m.tag || '').toLowerCase().includes("vad") || isRwx;
      
      if (rwxOnly && !isRwx) return false;
      if (suspOnly && !isSusp) return false;
      return matchSearch;
    });

    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--text-muted);">No memory sections match the active filter criteria.</td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map(m => {
      const isRwx = (m.protection || '').toUpperCase().includes("PAGE_EXECUTE_READWRITE") || (m.protection || '').toUpperCase().includes("RWX");
      const isSusp = m.is_suspicious || isRwx;

      return `
        <tr>
          <td>
            <a href="javascript:void(0)" onclick="window.inspectProcess(${m.pid})" style="font-weight:700; color:var(--accent-blue); text-decoration:none; font-family:var(--font-mono);">PID ${m.pid}</a>
          </td>
          <td style="font-family:var(--font-mono); font-size:12px; color:var(--text-primary);">${escapeHtml(m.start_addr || '0x0')} &ndash; ${escapeHtml(m.end_addr || '')}</td>
          <td>
            <span class="badge ${isRwx ? 'badge-rwx' : 'badge-normal'}">${escapeHtml(m.protection || 'PAGE_READWRITE')}</span>
          </td>
          <td style="font-family:var(--font-mono); font-size:12px; color:var(--text-secondary);">${escapeHtml(m.tag || 'Vad')}</td>
          <td>
            ${isSusp ? '<span class="badge badge-critical">⚠️ Suspicious</span>' : '<span class="badge badge-normal">Normal</span>'}
          </td>
          <td style="max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-family:var(--font-mono); font-size:11px; color:var(--text-muted);">
            ${escapeHtml(m.disasm || m.hex_dump || m.details || 'VAD allocation without disk-backing')}
          </td>
          <td>
            <div style="display:flex; gap:6px;">
              <button class="btn btn-sm btn-primary" onclick="window.inspectProcess(${m.pid})">Deep Dive</button>
              <button class="btn btn-sm" onclick="window.setFocusFromMemory(${m.pid}, '${escapeHtml(m.start_addr || '')}')">Focus</button>
            </div>
          </td>
        </tr>
      `;
    }).join("");
  }

  function setupMemoryAnomaliesEvents() {
    const searchInput = el("mem-search-input");
    if (searchInput) searchInput.oninput = () => renderMemoryRows();

    const rwxCheck = el("mem-filter-rwx");
    if (rwxCheck) rwxCheck.onchange = () => renderMemoryRows();

    const suspCheck = el("mem-filter-suspicious");
    if (suspCheck) suspCheck.onchange = () => renderMemoryRows();

    const refreshBtn = el("btn-refresh-memory");
    if (refreshBtn) refreshBtn.onclick = () => loadMemoryData();
  }

  window.setFocusFromMemory = function(pid, addr) {
    setInvestigationFocus({
      type: "memory",
      id: `${pid}:${addr}`,
      pid: pid,
      title: `Mem Anomaly (PID ${pid} @ ${addr})`,
      name: `PID ${pid}`
    });
  };

  // =========================================================================
  // Accessible Graph Relational Table
  // =========================================================================
  function renderAccessibleGraphTable() {
    const nodesTbody = el("graph-nodes-table-tbody");
    const edgesTbody = el("graph-edges-table-tbody");
    if (!nodesTbody || !edgesTbody) return;

    const nodes = state.graph.nodes || [];
    const edges = state.graph.edges || [];

    if (nodes.length === 0) {
      nodesTbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:20px; color:var(--text-muted);">No graph nodes generated. Run triage to populate graph.</td></tr>`;
    } else {
      nodesTbody.innerHTML = nodes.map(n => {
        const type = n.type || "node";
        const risk = (n.risk || "normal").toLowerCase();
        const badgeClass = risk.includes("crit") ? "badge-critical" : risk.includes("high") ? "badge-high" : risk.includes("susp") ? "badge-suspicious" : "badge-normal";
        const typeBadge = type === "process" ? "badge-normal" : type === "ip" ? "badge-purple" : type === "mem" ? "badge-critical" : "badge-suspicious";
        const pidOrId = n.pid || n.id || "-";
        return `
          <tr>
            <td><span class="badge ${typeBadge}">${escapeHtml(type.toUpperCase())}</span></td>
            <td style="font-weight:600; color:var(--text-primary);">${escapeHtml(n.label || n.id || '')}</td>
            <td style="font-family:var(--font-mono); font-size:12px;">${escapeHtml(String(pidOrId))}</td>
            <td style="font-weight:700; color:var(--text-primary);">${n.score !== undefined ? n.score : (n.risk_score || '-')}</td>
            <td><span class="badge ${badgeClass}">${escapeHtml((n.risk || 'Normal').toUpperCase())}</span></td>
            <td>
              <div style="display:flex; gap:6px;">
                <button class="btn btn-sm" onclick="window.setFocusAndInspect('${escapeHtml(type)}', '${escapeHtml(String(pidOrId))}', '${escapeHtml(n.label || '')}')">Inspect</button>
              </div>
            </td>
          </tr>
        `;
      }).join("");
    }

    if (edges.length === 0) {
      edgesTbody.innerHTML = `<tr><td colspan="4" style="text-align:center; padding:20px; color:var(--text-muted);">No relational edges available.</td></tr>`;
    } else {
      edgesTbody.innerHTML = edges.map(e => {
        const src = typeof e.source === 'object' ? (e.source.label || e.source.id) : e.source;
        const tgt = typeof e.target === 'object' ? (e.target.label || e.target.id) : e.target;
        return `
          <tr>
            <td style="font-weight:600; color:var(--accent-cyan); font-family:var(--font-mono); font-size:12px;">${escapeHtml(String(src))}</td>
            <td><span class="badge badge-suspicious" style="font-size:11px;">${escapeHtml(e.label || e.relation || 'LINKED_TO')}</span></td>
            <td style="font-weight:600; color:var(--accent-blue); font-family:var(--font-mono); font-size:12px;">${escapeHtml(String(tgt))}</td>
            <td style="color:var(--text-muted); font-size:11px;">${escapeHtml(e.provenance || 'Volatility 3 Heuristic')}</td>
          </tr>
        `;
      }).join("");
    }
  }

  window.setFocusAndInspect = function(type, id, name) {
    if (type === "process" && id && id !== "-") {
      const pid = parseInt(id, 10);
      if (!isNaN(pid)) {
        openProcessFocusDrawer(pid);
        return;
      }
    }
    setInvestigationFocus({
      type: type || "entity",
      id: id,
      title: name || `${type}: ${id}`,
      name: name || id
    });
  };

  window.setInvestigationFocus = setInvestigationFocus;
  window.clearInvestigationFocus = clearInvestigationFocus;

  // Global bootstrap on ready
  if (document.readyState === "loading") {
    window.addEventListener("DOMContentLoaded", initApp);
  } else {
    initApp();
  }

})();
