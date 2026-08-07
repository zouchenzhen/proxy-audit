const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const state = {
  system: null,
  imported: null,
  currentTask: null,
  tasks: [],
  activeImportTab: "paste",
  pollTimer: null,
};

const keyLabels = {
  ipinfo_api_key: "IPinfo API Token",
  ip2location_api_key: "IP2Location API Key",
  ipqs_api_key: "IPQualityScore API Key",
  scamalytics_user: "Scamalytics Username",
  scamalytics_api_key: "Scamalytics API Key",
  abuseipdb_api_key: "AbuseIPDB API Key",
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[ch]));
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  let data;
  try { data = await response.json(); } catch { data = { error: await response.text() }; }
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

function toast(message, type = "info") {
  const node = document.createElement("div");
  node.className = `toast ${type}`;
  node.textContent = message;
  $("#toastStack").append(node);
  setTimeout(() => node.remove(), 4200);
}

function formatTime(timestamp) {
  if (!timestamp) return "--:--:--";
  return new Date(timestamp * 1000).toLocaleTimeString("zh-CN", { hour12: false });
}

function formatDuration(start, end) {
  if (!start) return "";
  const seconds = Math.max(0, Math.round((end || Date.now() / 1000) - start));
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

function initTabs() {
  $$("#importTabs button").forEach(button => button.addEventListener("click", () => {
    state.activeImportTab = button.dataset.tab;
    $$("#importTabs button").forEach(item => item.classList.toggle("active", item === button));
    $$(".tab-panel").forEach(panel => panel.classList.toggle("active", panel.dataset.panel === state.activeImportTab));
  }));
}

function initDropZone() {
  const zone = $("#dropZone");
  const input = $("#nodeFile");
  const update = () => $("#fileLabel").textContent = input.files[0]?.name || "选择或拖入文件";
  input.addEventListener("change", update);
  ["dragenter", "dragover"].forEach(name => zone.addEventListener(name, event => { event.preventDefault(); zone.classList.add("dragging"); }));
  ["dragleave", "drop"].forEach(name => zone.addEventListener(name, event => { event.preventDefault(); zone.classList.remove("dragging"); }));
  zone.addEventListener("drop", event => {
    if (event.dataTransfer.files.length) {
      input.files = event.dataTransfer.files;
      update();
    }
  });
}

async function loadSystem() {
  try {
    state.system = await api("/api/system");
    $(".health-pill").classList.add("ok");
    $("#healthText").textContent = "本地引擎已连接";
    $("#timeout").value = state.system.settings.default_timeout;
    $("#concurrency").value = state.system.settings.default_concurrency;
    renderKernels();
    renderProviders();
    renderServices();
    renderSettings();
  } catch (error) {
    $(".health-pill").classList.add("error");
    $("#healthText").textContent = "本地引擎连接失败";
    toast(error.message, "error");
  }
}

function renderKernels() {
  const kernels = state.system?.kernels || [];
  const firstAvailable = kernels.find(item => item.available)?.id;
  $("#kernelGrid").innerHTML = kernels.map(kernel => `
    <label class="kernel-card ${kernel.available ? "" : "unavailable"} ${kernel.id === firstAvailable ? "selected" : ""}">
      <input type="radio" name="kernel" value="${escapeHtml(kernel.id)}" ${kernel.id === firstAvailable ? "checked" : ""} ${kernel.available ? "" : "disabled"}>
      <strong>${escapeHtml(kernel.name)}</strong>
      <small title="${escapeHtml(kernel.path)}">${escapeHtml(kernel.version || kernel.path)}</small>
      <b>${kernel.available ? `${kernel.protocols.length} 种协议` : "未找到内核"}</b>
    </label>`).join("");
  $$("input[name=kernel]").forEach(input => input.addEventListener("change", () => {
    $$(".kernel-card").forEach(card => card.classList.toggle("selected", $("input", card)?.checked));
  }));
}

function renderProviders() {
  const configured = state.system?.settings?.configured || {};
  $("#providerList").innerHTML = (state.system?.providers || []).map(provider => `
    <label class="check-tile" title="${provider.key_field ? "可在设置中填写 Key" : "无需 Key"}">
      <input type="checkbox" value="${escapeHtml(provider.id)}" data-default="${provider.default}" ${provider.default ? "checked" : ""}>
      <span>${escapeHtml(provider.name)}</span>
      <em class="${provider.key_field && configured[provider.key_field] ? "configured" : ""}"></em>
    </label>`).join("");
}

function renderServices() {
  $("#serviceList").innerHTML = (state.system?.services || []).map(service => `
    <label><input type="checkbox" value="${escapeHtml(service.id)}"><span>${escapeHtml(service.name)}</span></label>`).join("");
}

function renderSettings() {
  const settings = state.system?.settings || {};
  const configured = settings.configured || {};
  const fields = ["ipinfo_api_key", "ip2location_api_key", "ipqs_api_key", "scamalytics_user", "scamalytics_api_key", "abuseipdb_api_key"];
  $("#keySettings").innerHTML = fields.map(field => {
    const isSecret = field !== "scamalytics_user";
    const isConfigured = field === "scamalytics_user" ? settings.scamalytics_user_configured : configured[field];
    return `<div class="key-field">
      <label><span>${escapeHtml(keyLabels[field])}</span>${isConfigured ? "<b>已配置</b>" : ""}</label>
      <input type="${isSecret ? "password" : "text"}" data-setting="${field}" autocomplete="off" placeholder="${isConfigured ? "留空保留现有值" : "未配置"}">
      ${isConfigured ? `<input class="clear-key" type="checkbox" data-clear="${field}" title="勾选后清除">` : ""}
    </div>`;
  }).join("");
  $("#settingSingbox").value = settings.singbox_path || "";
  $("#settingXray").value = settings.xray_path || "";
  $("#vaultNote").textContent = `存储方式：${settings.storage}。${settings.legacy_config_detected ? "检测到旧版 config.local.json；新保存值会优先使用加密配置。" : "页面不会回传或显示已保存的 Key。"}`;
}

async function saveSettings() {
  const updates = {};
  $$('[data-setting]').forEach(input => { if (input.value.trim()) updates[input.dataset.setting] = input.value.trim(); });
  if ($("#settingSingbox").value.trim()) updates.singbox_path = $("#settingSingbox").value.trim();
  if ($("#settingXray").value.trim()) updates.xray_path = $("#settingXray").value.trim();
  updates.default_timeout = Number($("#timeout").value || 15);
  updates.default_concurrency = Number($("#concurrency").value || 2);
  const clear_fields = $$('[data-clear]:checked').map(input => input.dataset.clear);
  try {
    const settings = await api("/api/settings", { method: "PUT", headers: {"Content-Type":"application/json"}, body: JSON.stringify({updates, clear_fields}) });
    state.system.settings = settings;
    closeModal("settingsModal");
    await loadSystem();
    toast("设置已在本机加密保存", "success");
  } catch (error) { toast(error.message, "error"); }
}

async function importNodes() {
  const button = $("#importButton");
  const form = new FormData();
  form.append("source_type", state.activeImportTab);
  if (state.activeImportTab === "paste") form.append("content", $("#nodeText").value);
  if (state.activeImportTab === "url") form.append("url", $("#subscriptionUrl").value);
  if (state.activeImportTab === "file") {
    const file = $("#nodeFile").files[0];
    if (!file) return toast("请选择节点文件", "error");
    form.append("file", file);
  }
  button.disabled = true;
  button.querySelector("span").textContent = "正在解析…";
  try {
    state.imported = await api("/api/import", { method: "POST", body: form });
    const chips = Object.entries(state.imported.protocols).map(([key,value]) => `<span class="mini-chip">${escapeHtml(key)} · ${value}</span>`).join("");
    $("#importSummary").innerHTML = `<strong>已识别 ${state.imported.total} 个唯一节点</strong><small>${escapeHtml(state.imported.source_label)}</small><div class="mini-chips">${chips}</div>`;
    $("#importSummary").classList.remove("hidden");
    $("#metricImported").textContent = state.imported.total;
    $("#metricProtocols").textContent = Object.keys(state.imported.protocols).join(" / ");
    $("#startButton").disabled = false;
    $("#startHint").textContent = `${state.imported.total} 个节点待检测`;
    populateProtocolFilter(Object.keys(state.imported.protocols));
    toast("节点解析完成，凭据未在页面中显示", "success");
  } catch (error) { toast(error.message, "error"); }
  finally { button.disabled = false; button.querySelector("span").textContent = "解析并预览"; }
}

function selectedValues(selector) { return $$(selector).filter(input => input.checked).map(input => input.value); }

async function startTask() {
  if (!state.imported) return toast("请先导入节点", "error");
  const kernel = $('input[name=kernel]:checked')?.value;
  if (!kernel) return toast("没有可用的检测内核", "error");
  const payload = {
    import_id: state.imported.id,
    kernel,
    timeout: Number($("#timeout").value || 15),
    concurrency: Number($("#concurrency").value || 2),
    providers: selectedValues("#providerList input"),
    service_targets: selectedValues("#serviceList input"),
    quality_samples: $("#qualityProbe").checked ? 2 : 0,
    search: $("#preFilter").value.trim(),
    limit: Number($("#nodeLimit").value || 0),
  };
  if (!payload.providers.length) return toast("请至少选择一个 IP 情报源", "error");
  try {
    state.currentTask = await api("/api/tasks", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
    $("#startButton").disabled = true;
    $("#cancelButton").classList.remove("hidden");
    renderTask();
    schedulePoll(250);
    toast(`任务 ${state.currentTask.id} 已开始`, "success");
  } catch (error) { toast(error.message, "error"); }
}

function schedulePoll(delay = 900) {
  clearTimeout(state.pollTimer);
  state.pollTimer = setTimeout(pollTask, delay);
}

async function pollTask() {
  if (!state.currentTask) return;
  try {
    state.currentTask = await api(`/api/tasks/${state.currentTask.id}`);
    renderTask();
    const active = ["queued","running","cancelling"].includes(state.currentTask.status);
    if (active) schedulePoll();
    else {
      $("#startButton").disabled = !state.imported;
      $("#cancelButton").classList.add("hidden");
      await loadHistory();
    }
  } catch (error) { toast(error.message, "error"); schedulePoll(2000); }
}

function renderTask() {
  const task = state.currentTask;
  if (!task) return;
  const active = ["queued","running","cancelling"].includes(task.status);
  $("#taskOrb").className = `status-orb ${active ? "running" : task.status === "completed" ? "completed" : "failed"}`;
  $("#taskTitle").textContent = `${task.kernel} · ${task.status === "completed" ? "检测完成" : task.status === "cancelled" ? "任务已取消" : "正在批量检测"}`;
  $("#taskSubtitle").textContent = `${task.completed}/${task.total} · 成功 ${task.success} · 失败 ${task.failed} · 跳过 ${task.skipped} · ${formatDuration(task.started_at, task.finished_at)}`;
  $("#progressBar").style.width = `${task.progress || 0}%`;
  $("#progressText").textContent = `${Math.round(task.progress || 0)}%`;
  const finished = ["completed","cancelled"].includes(task.status);
  [$("#exportCsv"),$("#exportJson"),$("#exportMd")].forEach(button => button.disabled = !finished);
  $("#metricSuccess").textContent = task.success;
  $("#metricSuccessRate").textContent = task.total ? `${Math.round(task.success / task.total * 100)}% 成功率` : "—";
  const rows = task.rows || [];
  $("#metricLowRisk").textContent = rows.filter(row => row.success && row.risk_level_final === "low").length;
  $("#metricCivilian").textContent = rows.filter(row => row.success && ["residential_or_business","mobile"].includes(row.ip_type_final)).length;
  renderEvents(task.events || []);
  renderRows();
}

function rowStatus(row) { return row.success ? "success" : row.supported === false ? "skipped" : "failed"; }
function riskLabel(value) { return ({low:"低",medium:"中",high:"高"})[value] || "未知"; }
function typeLabel(value) { return ({residential_or_business:"住宅/商业",mobile:"移动网络",datacenter:"数据中心",proxy_or_transit:"代理/中转"})[value] || "待判定"; }

function filteredRows() {
  let rows = [...(state.currentTask?.rows || [])];
  const query = $("#resultSearch").value.trim().toLowerCase();
  const status = $("#statusFilter").value;
  const protocol = $("#protocolFilter").value;
  const risk = $("#riskFilter").value;
  const type = $("#typeFilter").value;
  return rows.filter(row => {
    const haystack = [row.remark,row.server,row.exit_ip,row.country,row.city,row.asn,row.asname,row.isp,row.org].join(" ").toLowerCase();
    return (!query || haystack.includes(query)) && (!status || rowStatus(row) === status) && (!protocol || row.protocol === protocol) && (!risk || row.risk_level_final === risk) && (!type || row.ip_type_final === type);
  });
}

function renderRows() {
  const rows = filteredRows();
  $("#visibleCount").textContent = `${rows.length} 条`;
  $("#emptyState").classList.toggle("hidden", rows.length > 0);
  $("#resultBody").innerHTML = rows.map((row, index) => {
    const status = rowStatus(row);
    const statusText = status === "success" ? "成功" : status === "skipped" ? "跳过" : "失败";
    const latency = row.latency_median_ms;
    const latencyClass = latency == null ? "" : latency < 250 ? "latency-good" : latency < 600 ? "latency-mid" : "latency-bad";
    return `<tr>
      <td><span class="cell-main" title="${escapeHtml(row.remark)}">${escapeHtml(row.remark || "未命名")}</span><span class="cell-sub">${escapeHtml(row.protocol)} · ${escapeHtml(row.kernel || "")}</span></td>
      <td><span class="status-badge status-${status}">${statusText}</span></td>
      <td><span class="cell-main">${escapeHtml(row.exit_ip || "—")}</span><span class="cell-sub">${escapeHtml(row.server || "")} : ${escapeHtml(row.port || "")}</span></td>
      <td><span class="cell-main">${escapeHtml([row.country,row.city].filter(Boolean).join(" · ") || "—")}</span><span class="cell-sub" title="${escapeHtml(row.asn || row.asname)}">${escapeHtml(row.asn || row.asname || "无 ASN")}</span></td>
      <td><span class="type-badge">${typeLabel(row.ip_type_final)}</span><span class="cell-sub">${escapeHtml(row.native_ip_judgement || "")}</span></td>
      <td>${row.risk_level_final ? `<span class="risk-badge risk-${escapeHtml(row.risk_level_final)}">${riskLabel(row.risk_level_final)} · ${escapeHtml(row.risk_score_final)}</span>` : "—"}</td>
      <td><span class="cell-main ${latencyClass}">${latency == null ? "—" : `${latency} ms`}</span><span class="cell-sub">抖动 ${row.jitter_ms == null ? "—" : `${row.jitter_ms} ms`}</span></td>
      <td><button class="row-action" data-detail="${index}" title="查看详情">···</button></td>
    </tr>`;
  }).join("");
  $$('[data-detail]').forEach(button => button.addEventListener("click", () => showDetail(rows[Number(button.dataset.detail)])));
}

function showDetail(row) {
  $("#detailTitle").textContent = row.remark || "节点详情";
  const stats = [
    ["出口 IP", row.exit_ip], ["入口服务器", `${row.server || "—"}:${row.port || "—"}`], ["协议 / 内核", `${row.protocol || "—"} / ${row.kernel || "—"}`],
    ["地区", [row.country,row.regionName,row.city].filter(Boolean).join(" · ")], ["ASN", row.asn || row.asname], ["ISP / ORG", row.isp || row.org],
    ["最终类型", typeLabel(row.ip_type_final)], ["风险", `${riskLabel(row.risk_level_final)} / ${row.risk_score_final ?? "—"}`], ["原生判断", row.native_ip_judgement],
    ["内核启动", row.core_startup_ms == null ? "—" : `${row.core_startup_ms} ms`], ["HTTP 出口", row.ipify_latency_ms == null ? "—" : `${row.ipify_latency_ms} ms`], ["延迟 / 抖动", `${row.latency_median_ms ?? "—"} / ${row.jitter_ms ?? "—"} ms`],
  ];
  $("#detailBody").innerHTML = `<div class="detail-grid">${stats.map(([label,value]) => `<div class="detail-stat"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value || "—")}</strong></div>`).join("")}</div>
    <div class="detail-section"><h3>判断摘要</h3><pre>${escapeHtml(row.reasoning_brief || row.error || row.skip_reason || "无")}</pre></div>
    <div class="detail-section"><h3>安全导出字段</h3><pre>${escapeHtml(JSON.stringify(row,null,2))}</pre></div>`;
  openModal("detailModal");
}

function renderEvents(events) {
  $("#eventList").innerHTML = events.length ? [...events].reverse().slice(0,40).map(event => `<div class="event ${escapeHtml(event.level)}"><time>${formatTime(event.time)}</time><span>${escapeHtml(event.message)}</span></div>`).join("") : '<div class="event muted"><time>--:--:--</time><span>等待任务事件</span></div>';
}

async function cancelTask() {
  if (!state.currentTask) return;
  try {
    state.currentTask = await api(`/api/tasks/${state.currentTask.id}/cancel`, {method:"POST"});
    renderTask();
    toast("已请求取消任务", "info");
  } catch (error) { toast(error.message, "error"); }
}

async function loadHistory() {
  try {
    const data = await api("/api/tasks");
    state.tasks = data.tasks || [];
    $("#historyList").innerHTML = state.tasks.length ? state.tasks.slice(0,6).map(task => `<div class="history-item" data-task-id="${escapeHtml(task.id)}"><div><strong>${escapeHtml(task.kernel)} · ${escapeHtml(task.source_label)}</strong><small>${task.completed}/${task.total} · ${formatTime(task.created_at)}</small></div><b>${escapeHtml(task.status)}</b></div>`).join("") : '<p class="muted-copy">当前服务启动后尚无任务</p>';
    $$('[data-task-id]').forEach(item => item.addEventListener("click", async () => {
      state.currentTask = await api(`/api/tasks/${item.dataset.taskId}`);
      renderTask();
    }));
  } catch {}
}

function populateProtocolFilter(protocols) {
  $("#protocolFilter").innerHTML = '<option value="">全部协议</option>' + protocols.map(protocol => `<option value="${escapeHtml(protocol)}">${escapeHtml(protocol)}</option>`).join("");
}

function exportCurrent(format) {
  if (!state.currentTask) return;
  window.location.href = `/api/tasks/${state.currentTask.id}/export?format=${format}`;
}

function openModal(id) { $("#" + id).classList.remove("hidden"); }
function closeModal(id) { $("#" + id).classList.add("hidden"); }

function bindEvents() {
  initTabs();
  initDropZone();
  $("#importButton").addEventListener("click", importNodes);
  $("#startButton").addEventListener("click", startTask);
  $("#cancelButton").addEventListener("click", cancelTask);
  $("#refreshButton").addEventListener("click", () => state.currentTask ? pollTask() : loadHistory());
  $("#settingsButton").addEventListener("click", () => openModal("settingsModal"));
  $("#saveSettings").addEventListener("click", saveSettings);
  $$('[data-close]').forEach(button => button.addEventListener("click", () => closeModal(button.dataset.close)));
  $$(".modal-backdrop").forEach(backdrop => backdrop.addEventListener("click", event => { if (event.target === backdrop) closeModal(backdrop.id); }));
  $("#selectDefaultProviders").addEventListener("click", () => $$("#providerList input").forEach(input => input.checked = input.dataset.default === "true"));
  ["resultSearch","statusFilter","protocolFilter","riskFilter","typeFilter"].forEach(id => $("#" + id).addEventListener("input", renderRows));
  $("#exportCsv").addEventListener("click", () => exportCurrent("csv"));
  $("#exportJson").addEventListener("click", () => exportCurrent("json"));
  $("#exportMd").addEventListener("click", () => exportCurrent("md"));
  document.addEventListener("keydown", event => {
    if (event.key === "Escape") $$(".modal-backdrop:not(.hidden)").forEach(modal => closeModal(modal.id));
    if (event.key === "Enter" && event.ctrlKey && state.activeImportTab === "paste") importNodes();
  });
}

async function boot() {
  bindEvents();
  await loadSystem();
  await loadHistory();
}

boot();
