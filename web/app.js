const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const state = {
  system: null,
  imported: null,
  currentTask: null,
  tasks: [],
  activeImportTab: "paste",
  pollTimer: null,
  selectedNodeIds: new Set(),
  page: 1,
  pageSize: 100,
  pendingKeyRemovals: {},
  renameTaskId: null,
};

const UI_THEME_KEY = "proxyAudit.theme";
const UI_FONT_KEY = "proxyAudit.fontSize";
const SESSION_IMPORT_KEY = "proxyAudit.currentImport";
const SESSION_TASK_KEY = "proxyAudit.currentTask";
const CLOUD_SESSION_KEY = "proxyAudit.cloudSession";
const IS_LOCAL_UI = ["127.0.0.1", "localhost", "::1"].includes(location.hostname);
const IS_CLOUD_UI = !IS_LOCAL_UI || new URLSearchParams(location.search).get("cloud") === "1";

function migrateLegacyStorage() {
  [
    [localStorage, "proxyScope.theme", UI_THEME_KEY],
    [localStorage, "proxyScope.fontSize", UI_FONT_KEY],
    [sessionStorage, "proxyScope.currentImport", SESSION_IMPORT_KEY],
    [sessionStorage, "proxyScope.currentTask", SESSION_TASK_KEY],
  ].forEach(([storage, legacyKey, currentKey]) => {
    if (storage.getItem(currentKey) === null && storage.getItem(legacyKey) !== null) {
      storage.setItem(currentKey, storage.getItem(legacyKey));
    }
    storage.removeItem(legacyKey);
  });
}

const keyLabels = {
  ipapi_is_api_key: "ipapi.is API Key（可选）",
  ipinfo_api_key: "IPinfo API Token",
  ip2location_api_key: "IP2Location API Key",
  ipqs_api_key: "IPQualityScore API Key",
  scamalytics_user: "Scamalytics Username",
  scamalytics_api_key: "Scamalytics API Key",
  abuseipdb_api_key: "AbuseIPDB API Key",
};

const keyHelp = {
  ipapi_is_api_key: "对应 ipapi.is 账户首页右侧 API Credentials；不填仍可匿名查询。",
  scamalytics_user: "申请后由 Scamalytics 邮件提供 Username；本机已配置时留空即可。",
  scamalytics_api_key: "申请后由 Scamalytics 邮件提供 API Key；本机已配置时留空即可。",
  abuseipdb_api_key: "AbuseIPDB 登录后进入 API → API Settings 创建。",
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[ch]));
}

async function api(path, options = {}) {
  const requestOptions = {...options};
  requestOptions.headers = {...(options.headers || {})};
  const cloudToken = sessionStorage.getItem(CLOUD_SESSION_KEY);
  if (IS_CLOUD_UI && cloudToken) requestOptions.headers["X-Proxy-Audit-Session"] = cloudToken;
  const response = await fetch(path, requestOptions);
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

function applyPreferences(theme = localStorage.getItem(UI_THEME_KEY) || "dark", fontSize = localStorage.getItem(UI_FONT_KEY) || "large") {
  const resolvedTheme = theme === "system" ? (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark") : theme;
  document.documentElement.dataset.theme = resolvedTheme;
  document.documentElement.dataset.fontSize = fontSize;
  localStorage.setItem(UI_THEME_KEY, theme);
  localStorage.setItem(UI_FONT_KEY, fontSize);
  if ($("#themeSelect")) $("#themeSelect").value = theme;
  if ($("#fontSizeSelect")) $("#fontSizeSelect").value = fontSize;
  if ($("#themeButton")) {
    $("#themeButton span").textContent = resolvedTheme === "light" ? "☀" : "☾";
    $("#themeButton").title = resolvedTheme === "light" ? "当前浅色；点击切换深色" : "当前深色；点击切换浅色";
  }
}

function toggleTheme() {
  const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  applyPreferences(next, localStorage.getItem(UI_FONT_KEY) || "large");
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
    $("#healthText").textContent = IS_CLOUD_UI ? "云端临时会话已连接" : "本地引擎已连接";
    $("#timeout").value = state.system.settings.default_timeout;
    $("#concurrency").value = state.system.settings.default_concurrency;
    renderKernels();
    renderProviders();
    renderServices();
    renderSettings();
    if (IS_CLOUD_UI) {
      $("#concurrency").max = state.system.limits.max_concurrency;
      $("#timeout").max = 12;
      $("#nodeLimit").max = state.system.limits.max_nodes_per_task;
      $("#uploadLimitHint").textContent = "TXT / ZIP / guiNDB.db · 最大 4 MB；每次最多 20 节点";
      $("#keyLimitHelp").textContent = `IP-API 无需注册或 Key；IP-API 与 ipapi.is 是两个不同服务。其余服务商可加入多个授权 Key（每行一个，本次会话最多 ${state.system.limits.max_keys_per_provider} 个），鉴权失败或额度受限时自动切换。`;
    }
    return true;
  } catch (error) {
    $(".health-pill").classList.add("error");
    $("#healthText").textContent = IS_CLOUD_UI ? "云端临时会话连接失败" : "本地引擎连接失败";
    toast(error.message, "error");
    return false;
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
  $("#providerList").innerHTML = (state.system?.providers || []).map(provider => {
    const hasKey = Boolean(provider.key_field && configured[provider.key_field]);
    const status = !provider.key_field ? "无需 Key" : hasKey ? "Key 已配置" : provider.id === "ipapi_is" ? "未配置 Key，匿名可用" : "可在设置中填写 Key";
    return `
    <label class="check-tile" title="${escapeHtml(status)}">
      <input type="checkbox" value="${escapeHtml(provider.id)}" data-default="${provider.default}" ${provider.default ? "checked" : ""}>
      <span>${escapeHtml(provider.name)}</span>
      <em class="${hasKey ? "configured" : ""}" aria-label="${escapeHtml(status)}"></em>
    </label>`;
  }).join("");
}

function renderServices() {
  $("#serviceList").innerHTML = (state.system?.services || []).map(service => `
    <label><input type="checkbox" value="${escapeHtml(service.id)}"><span>${escapeHtml(service.name)}</span></label>`).join("");
}

function keyVisibilityIcon(visible) {
  return visible
    ? `<svg class="key-eye-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M3 3l18 18M10.6 6.2A10.8 10.8 0 0 1 12 6c6.5 0 10 6 10 6a18.4 18.4 0 0 1-3.1 3.7M6.2 6.3C3.5 8.1 2 12 2 12s3.5 6 10 6a10.8 10.8 0 0 0 3.1-.5M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>`
    : `<svg class="key-eye-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg>`;
}

function renderSettings() {
  const settings = state.system?.settings || {};
  const configured = settings.configured || {};
  const previews = settings.key_previews || {};
  const fields = ["ipapi_is_api_key", "ipinfo_api_key", "ip2location_api_key", "ipqs_api_key", "scamalytics_user", "scamalytics_api_key", "abuseipdb_api_key"];
  state.pendingKeyRemovals = {};
  $("#keySettings").innerHTML = fields.map(field => {
    const isSecret = field !== "scamalytics_user";
    const isConfigured = field === "scamalytics_user" ? settings.scamalytics_user_configured : configured[field];
    const saved = isSecret ? (previews[field] || []) : [];
    const savedKeys = saved.length ? `<div class="saved-key-list" data-key-list="${field}">${saved.map((item, index) => `
      <span class="saved-key" data-key-id="${escapeHtml(item.id)}">
        <code data-masked="${escapeHtml(item.masked)}" data-prefix="${escapeHtml(item.prefix)}">Key ${index + 1} · ${escapeHtml(item.masked)}</code>
        <button type="button" class="key-remove" data-remove-key="${escapeHtml(field)}" data-remove-id="${escapeHtml(item.id)}" title="保存后移除此 Key">×</button>
      </span>`).join("")}</div>` : "";
    return `<div class="key-field">
      <label><span>${escapeHtml(keyLabels[field])}</span>${isConfigured ? `<b>${isSecret ? `${saved.length} 个 Key` : "已配置"}</b>` : ""}</label>
      ${savedKeys}
      <div class="key-input-row">
        ${isSecret
          ? `<textarea class="secret-entry" data-setting="${field}" autocomplete="off" spellcheck="false" placeholder="${isConfigured ? "每行添加一个新 Key；留空保留" : "每行填写一个 Key"}"></textarea><button type="button" class="key-eye" data-key-eye="${field}" title="仅显示已保存 Key 的短前缀" aria-label="显示 Key 短前缀" aria-pressed="false">${keyVisibilityIcon(false)}</button>`
          : `<input type="text" data-setting="${field}" autocomplete="off" placeholder="${isConfigured ? "留空保留现有值" : "未配置"}">`}
        ${isConfigured ? `<label class="clear-option" title="勾选后保存将清除此项"><input type="checkbox" data-clear="${field}"><span>清空</span></label>` : ""}
      </div>
      ${keyHelp[field] ? `<p class="key-help">${escapeHtml(keyHelp[field])}</p>` : ""}
    </div>`;
  }).join("");
  $$('[data-key-eye]').forEach(button => button.addEventListener("click", () => {
    const field = button.dataset.keyEye;
    const visible = button.classList.toggle("visible");
    $$(`[data-key-list="${field}"] code`).forEach(code => {
      code.textContent = visible ? code.dataset.prefix : code.dataset.masked;
    });
    button.innerHTML = keyVisibilityIcon(visible);
    button.title = visible ? "隐藏 Key 短前缀" : "仅显示已保存 Key 的短前缀";
    button.setAttribute("aria-label", visible ? "隐藏 Key 短前缀" : "显示 Key 短前缀");
    button.setAttribute("aria-pressed", String(visible));
  }));
  $$('[data-remove-key]').forEach(button => button.addEventListener("click", () => {
    const field = button.dataset.removeKey;
    state.pendingKeyRemovals[field] ||= new Set();
    state.pendingKeyRemovals[field].add(button.dataset.removeId);
    button.closest(".saved-key").classList.add("pending-remove");
  }));
  $("#settingSingbox").value = settings.singbox_path || "";
  $("#settingXray").value = settings.xray_path || "";
  $("#settingHistoryLimit").value = settings.history_limit || 10;
  applyPreferences(localStorage.getItem(UI_THEME_KEY) || "dark", localStorage.getItem(UI_FONT_KEY) || "large");
  $("#vaultNote").textContent = IS_CLOUD_UI
    ? `存储方式：${settings.storage}。完整 Key 会上传到临时检测后端，但不会回传页面或写入结果；最长 1 小时后删除。小眼睛只显示短前缀。`
    : `存储方式：${settings.storage}。服务端绝不回传完整 Key；小眼睛只显示用于辨认的短前缀。${settings.legacy_config_detected ? "检测到旧版 config.local.json；新保存值会优先使用加密配置。" : ""}`;
}

async function saveSettings() {
  const updates = {};
  $$('[data-setting]').forEach(input => {
    if (!input.value.trim()) return;
    updates[input.dataset.setting] = input.classList.contains("secret-entry")
      ? input.value.split(/[\r\n,;]+/).map(value => value.trim()).filter(Boolean)
      : input.value.trim();
  });
  if (IS_LOCAL_UI && $("#settingSingbox").value.trim()) updates.singbox_path = $("#settingSingbox").value.trim();
  if (IS_LOCAL_UI && $("#settingXray").value.trim()) updates.xray_path = $("#settingXray").value.trim();
  updates.default_timeout = Number($("#timeout").value || 15);
  updates.default_concurrency = Number($("#concurrency").value || 2);
  if (IS_LOCAL_UI) updates.history_limit = Math.max(1, Math.min(Number($("#settingHistoryLimit").value || 10), 100));
  applyPreferences($("#themeSelect").value, $("#fontSizeSelect").value);
  const clear_fields = $$('[data-clear]:checked').map(input => input.dataset.clear);
  const remove_key_ids = Object.fromEntries(Object.entries(state.pendingKeyRemovals).map(([field, values]) => [field, [...values]]));
  try {
    const settings = await api("/api/settings", { method: "PUT", headers: {"Content-Type":"application/json"}, body: JSON.stringify({updates, clear_fields, remove_key_ids}) });
    state.system.settings = settings;
    closeModal("settingsModal");
    await loadSystem();
    await loadHistory();
    toast(IS_CLOUD_UI ? "Key 已加入本次云端临时会话" : "设置已在本机加密保存", "success");
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
    state.currentTask = null;
    state.selectedNodeIds.clear();
    state.page = 1;
    $("#authorizationConfirm").checked = false;
    sessionStorage.setItem(SESSION_IMPORT_KEY, state.imported.id);
    sessionStorage.removeItem(SESSION_TASK_KEY);
    ["resultSearch","statusFilter","riskFilter","typeFilter"].forEach(id => $("#" + id).value = "");
    renderImport();
    toast("节点解析完成，凭据未在页面中显示", "success");
  } catch (error) { toast(error.message, "error"); }
  finally { button.disabled = false; button.querySelector("span").textContent = "解析并预览"; }
}

function previewRows() {
  return (state.imported?.preview || []).map(node => ({...node, kernel: "待选择", supported: null, success: null, pending: true}));
}

function renderImport() {
  if (!state.imported) return;
  const chips = Object.entries(state.imported.protocols || {}).map(([key,value]) => `<span class="mini-chip">${escapeHtml(key)} · ${value}</span>`).join("");
  const note = state.imported.preview_truncated ? `显示前 ${state.imported.preview_count} 条` : "节点列表已在右侧显示，可筛选并勾选部分节点";
  $("#importSummary").innerHTML = `<strong>已识别 ${state.imported.total} 个唯一节点</strong><small>${escapeHtml(state.imported.source_label)}</small><div class="mini-chips">${chips}</div><div class="preview-note">${escapeHtml(note)} · 凭据已隐藏</div>`;
  $("#importSummary").classList.remove("hidden");
  $("#metricImported").textContent = state.imported.total;
  $("#metricImportedLabel").textContent = "已导入";
  $("#metricProtocols").textContent = Object.keys(state.imported.protocols || {}).join(" / ");
  updateSelectionSummary();
  populateProtocolFilter(Object.keys(state.imported.protocols || {}));
  if (!state.currentTask) {
    $("#metricSuccess").textContent = "—";
    $("#metricSuccessRate").textContent = "尚未运行";
    $("#metricLowRisk").textContent = "—";
    $("#metricCivilian").textContent = "—";
    $("#taskOrb").className = "status-orb idle";
    $("#taskTitle").textContent = "等待检测任务";
    $("#taskSubtitle").textContent = "已显示脱敏节点预览，选择策略后开始";
    $("#progressBar").style.width = "0%";
    $("#progressText").textContent = "0%";
    [$("#exportCsv"),$("#exportJson"),$("#exportMd")].forEach(button => button.disabled = true);
    renderEvents([]);
  }
  renderRows();
}

function selectedValues(selector) { return $$(selector).filter(input => input.checked).map(input => input.value); }

function syncStartAvailability() {
  const active = ["queued","running","cancelling"].includes(state.currentTask?.status);
  const authorized = Boolean($("#authorizationConfirm")?.checked);
  $("#startButton").disabled = !state.imported || !authorized || active;
  if (!state.imported) $("#startHint").textContent = "请先导入节点";
  else if (!authorized) $("#startHint").textContent = "请先确认节点授权";
  else {
    const count = state.selectedNodeIds.size;
    $("#startHint").textContent = count ? `仅检测已选 ${count} 个节点` : `${state.imported.total} 个节点待检测`;
  }
}

function updateSelectionSummary(filteredCount = null) {
  const count = state.selectedNodeIds.size;
  if ($("#selectionCount")) $("#selectionCount").textContent = count ? `已选择 ${count} 个节点` : "尚未手动选择（默认检测全部）";
  if ($("#selectionFiltered")) $("#selectionFiltered").textContent = filteredCount == null ? "" : `当前筛选 ${filteredCount} 个`;
  syncStartAvailability();
}

async function startTask() {
  if (!state.imported) return toast("请先导入节点", "error");
  if (!$("#authorizationConfirm").checked) return toast("请先确认节点由本人所有或已取得测试授权", "error");
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
    node_ids: [...state.selectedNodeIds],
    authorization_confirmed: true,
  };
  if (!payload.providers.length) return toast("请至少选择一个 IP 情报源", "error");
  try {
    state.currentTask = await api("/api/tasks", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
    sessionStorage.setItem(SESSION_TASK_KEY, state.currentTask.id);
    $("#authorizationConfirm").checked = false;
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
      syncStartAvailability();
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
  const taskName = task.name || task.kernel;
  $("#taskTitle").textContent = `${taskName} · ${task.status === "completed" ? "检测完成" : task.status === "cancelled" ? "任务已取消" : "正在批量检测"}`;
  $("#taskSubtitle").textContent = `${task.completed}/${task.total} · 成功 ${task.success} · 失败 ${task.failed} · 跳过 ${task.skipped} · ${formatDuration(task.started_at, task.finished_at)}`;
  $("#progressBar").style.width = `${task.progress || 0}%`;
  $("#progressText").textContent = `${Math.round(task.progress || 0)}%`;
  const finished = ["completed","cancelled"].includes(task.status);
  [$("#exportCsv"),$("#exportJson"),$("#exportMd")].forEach(button => button.disabled = !finished);
  $("#metricSuccess").textContent = task.success;
  $("#metricSuccessRate").textContent = task.total ? `${Math.round(task.success / task.total * 100)}% 成功率` : "—";
  const rows = task.rows || [];
  $("#metricImportedLabel").textContent = "本任务节点";
  $("#metricImported").textContent = task.total;
  $("#metricProtocols").textContent = Object.keys(task.protocols || {}).join(" / ") || "历史检测节点";
  populateProtocolFilter(Object.keys(task.protocols || {}));
  $("#metricLowRisk").textContent = rows.filter(row => row.success && row.risk_level_final === "low").length;
  $("#metricCivilian").textContent = rows.filter(row => row.success && ["residential_or_business","mobile"].includes(row.ip_type_final)).length;
  renderEvents(task.events || []);
  renderRows();
}

function rowStatus(row) { return row.pending ? "pending" : row.success ? "success" : row.supported === false ? "skipped" : "failed"; }
function riskLabel(value) { return ({low:"低",medium:"中",high:"高"})[value] || "未知"; }
function typeLabel(value) { return ({residential_or_business:"住宅/商业",mobile:"移动网络",datacenter:"数据中心",proxy_or_transit:"代理/中转"})[value] || "待判定"; }

function filteredRows() {
  let rows = state.currentTask ? [...(state.currentTask.rows || [])] : previewRows();
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
  const allRows = filteredRows();
  const pageCount = Math.max(1, Math.ceil(allRows.length / state.pageSize));
  state.page = Math.min(Math.max(1, state.page), pageCount);
  const start = (state.page - 1) * state.pageSize;
  const rows = allRows.slice(start, start + state.pageSize);
  $("#visibleCount").textContent = allRows.length ? `${start + 1}–${start + rows.length} / ${allRows.length} 条` : "0 条";
  $("#emptyState").classList.toggle("hidden", allRows.length > 0);
  $("#emptyTitle").textContent = state.imported || state.currentTask ? "没有符合筛选条件的节点" : "等待导入节点";
  $("#emptyCopy").textContent = state.imported || state.currentTask ? "请清除搜索词或筛选条件后重试。" : "解析后会立即显示脱敏节点列表；节点凭据不会出现在页面中。";
  const selecting = !state.currentTask && !!state.imported;
  $("#selectionBar").classList.toggle("hidden", !selecting);
  $("#pagePrev").disabled = state.page <= 1;
  $("#pageNext").disabled = state.page >= pageCount;
  $("#pageInfo").textContent = `${state.page} / ${pageCount}`;
  updateSelectionSummary(allRows.length);
  $("#selectColumn").classList.toggle("hidden", !selecting);
  $("#resultBody").innerHTML = rows.map((row, index) => {
    const status = rowStatus(row);
    const statusText = status === "pending" ? "待检测" : status === "success" ? "成功" : status === "skipped" ? "跳过" : "失败";
    const latency = row.latency_median_ms;
    const latencyClass = latency == null ? "" : latency < 250 ? "latency-good" : latency < 600 ? "latency-mid" : "latency-bad";
    return `<tr>
      <td class="select-cell ${selecting ? "" : "hidden"}">${selecting ? `<input type="checkbox" data-node-select="${escapeHtml(row.node_id)}" ${state.selectedNodeIds.has(row.node_id) ? "checked" : ""} aria-label="选择 ${escapeHtml(row.remark || "节点")}">` : ""}</td>
      <td><span class="cell-main" title="${escapeHtml(row.remark)}">${escapeHtml(row.remark || "未命名")}</span><span class="cell-sub">${escapeHtml(row.protocol)} · ${escapeHtml(row.kernel || "")}</span></td>
      <td><span class="status-badge status-${status}">${statusText}</span></td>
      <td><span class="cell-main">${escapeHtml(row.exit_ip || "—")}</span><span class="cell-sub">${escapeHtml(row.server || "")}${row.port ? ` : ${escapeHtml(row.port)}` : ""}</span></td>
      <td><span class="cell-main">${escapeHtml([row.country,row.city].filter(Boolean).join(" · ") || "—")}</span><span class="cell-sub" title="${escapeHtml(row.asn || row.asname)}">${escapeHtml(row.asn || row.asname || "无 ASN")}</span></td>
      <td><span class="type-badge">${typeLabel(row.ip_type_final)}</span><span class="cell-sub">${escapeHtml(row.native_ip_judgement || "")}</span></td>
      <td>${row.risk_level_final ? `<span class="risk-badge risk-${escapeHtml(row.risk_level_final)}">${riskLabel(row.risk_level_final)} · ${escapeHtml(row.risk_score_final)}</span>` : "—"}</td>
      <td><span class="cell-main ${latencyClass}">${latency == null ? "—" : `${latency} ms`}</span><span class="cell-sub">抖动 ${row.jitter_ms == null ? "—" : `${row.jitter_ms} ms`}</span></td>
      <td><button class="row-action" data-detail="${index}" title="查看详情">···</button></td>
    </tr>`;
  }).join("");
  $$('[data-node-select]').forEach(input => input.addEventListener("change", () => {
    if (input.checked) state.selectedNodeIds.add(input.dataset.nodeSelect);
    else state.selectedNodeIds.delete(input.dataset.nodeSelect);
    updateSelectionSummary(allRows.length);
    syncSelectPage(rows);
  }));
  syncSelectPage(rows);
  $$('[data-detail]').forEach(button => button.addEventListener("click", () => showDetail(rows[Number(button.dataset.detail)])));
}

function syncSelectPage(rows) {
  const input = $("#selectPage");
  const ids = rows.map(row => row.node_id).filter(Boolean);
  const selected = ids.filter(id => state.selectedNodeIds.has(id)).length;
  input.checked = ids.length > 0 && selected === ids.length;
  input.indeterminate = selected > 0 && selected < ids.length;
}

function selectFilteredNodes() {
  filteredRows().forEach(row => { if (row.node_id) state.selectedNodeIds.add(row.node_id); });
  renderRows();
}

function clearSelectedNodes() {
  state.selectedNodeIds.clear();
  renderRows();
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
    $("#historyCount").textContent = `显示 ${state.tasks.length}/${state.system?.settings?.history_limit || 10} 条`;
    $("#historyList").innerHTML = state.tasks.length ? state.tasks.map(task => `<div class="history-item ${state.currentTask?.id === task.id ? "active" : ""}" data-task-id="${escapeHtml(task.id)}"><div><strong>${escapeHtml(task.name || `${task.kernel} · ${task.source_label}`)}</strong><small>${task.completed}/${task.total} · ${formatTime(task.created_at)}</small></div><div class="history-actions"><b>${escapeHtml(task.status)}</b><button type="button" data-rename-task="${escapeHtml(task.id)}" title="重命名任务" aria-label="重命名任务">✎</button></div></div>`).join("") : `<p class="muted-copy">${IS_CLOUD_UI ? "本次临时会话尚无任务" : "本机尚无任务记录"}</p>`;
    $$('[data-task-id]').forEach(item => item.addEventListener("click", async () => {
      state.currentTask = await api(`/api/tasks/${item.dataset.taskId}`);
      state.page = 1;
      sessionStorage.setItem(SESSION_TASK_KEY, state.currentTask.id);
      renderTask();
      await loadHistory();
    }));
    $$('[data-rename-task]').forEach(button => button.addEventListener("click", event => {
      event.stopPropagation();
      const task = state.tasks.find(item => item.id === button.dataset.renameTask);
      state.renameTaskId = task?.id || null;
      $("#renameTaskInput").value = task?.name || `${task?.kernel || "任务"} · ${task?.source_label || ""}`;
      openModal("renameModal");
      $("#renameTaskInput").focus();
      $("#renameTaskInput").select();
    }));
  } catch {}
}

async function saveTaskName() {
  if (!state.renameTaskId) return;
  const name = $("#renameTaskInput").value.trim();
  if (!name) return toast("任务名称不能为空", "error");
  try {
    const updated = await api(`/api/tasks/${state.renameTaskId}`, {method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({name})});
    if (state.currentTask?.id === updated.id) {
      state.currentTask = updated;
      renderTask();
    }
    closeModal("renameModal");
    await loadHistory();
    toast("历史任务名称已保存", "success");
  } catch (error) { toast(error.message, "error"); }
}

async function restoreSession() {
  const importId = sessionStorage.getItem(SESSION_IMPORT_KEY);
  let importRestored = false;
  if (importId) {
    try {
      state.imported = await api(`/api/imports/${importId}`);
      renderImport();
      importRestored = true;
    } catch { sessionStorage.removeItem(SESSION_IMPORT_KEY); }
  }
  const rememberedTask = sessionStorage.getItem(SESSION_TASK_KEY);
  const taskId = rememberedTask || (!importRestored ? state.tasks[0]?.id : null);
  if (taskId) {
    try {
      state.currentTask = await api(`/api/tasks/${taskId}`);
      sessionStorage.setItem(SESSION_TASK_KEY, taskId);
      renderTask();
      if (["queued","running","cancelling"].includes(state.currentTask.status)) schedulePoll(500);
    } catch {
      sessionStorage.removeItem(SESSION_TASK_KEY);
      if (state.tasks[0]?.id && state.tasks[0].id !== taskId) {
        state.currentTask = await api(`/api/tasks/${state.tasks[0].id}`);
        sessionStorage.setItem(SESSION_TASK_KEY, state.currentTask.id);
        renderTask();
      }
    }
  }
}

function populateProtocolFilter(protocols) {
  const current = $("#protocolFilter").value;
  $("#protocolFilter").innerHTML = '<option value="">全部协议</option>' + protocols.map(protocol => `<option value="${escapeHtml(protocol)}">${escapeHtml(protocol)}</option>`).join("");
  if (protocols.includes(current)) $("#protocolFilter").value = current;
}

async function exportCurrent(format) {
  if (!state.currentTask) return;
  const path = `/api/tasks/${state.currentTask.id}/export?format=${format}`;
  try {
    const headers = {};
    const cloudToken = sessionStorage.getItem(CLOUD_SESSION_KEY);
    if (IS_CLOUD_UI && cloudToken) headers["X-Proxy-Audit-Session"] = cloudToken;
    const response = await fetch(path, {headers});
    if (!response.ok) throw new Error(`导出失败：HTTP ${response.status}`);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `proxy-audit-${state.currentTask.id}.${format === "md" ? "md" : format}`;
    link.click();
    URL.revokeObjectURL(url);
  } catch (error) { toast(error.message, "error"); }
}

async function createCloudSession() {
  const response = await fetch("/api/session", {method:"POST",headers:{"Content-Type":"application/json"},body:"{}"});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  sessionStorage.setItem(CLOUD_SESSION_KEY, data.token);
  return data.session;
}

async function resumeCloudSession() {
  if (!sessionStorage.getItem(CLOUD_SESSION_KEY)) return false;
  try {
    await api("/api/session");
    return true;
  } catch {
    sessionStorage.removeItem(CLOUD_SESSION_KEY);
    sessionStorage.removeItem(SESSION_IMPORT_KEY);
    sessionStorage.removeItem(SESSION_TASK_KEY);
    return false;
  }
}

async function deleteCloudSession() {
  if (!IS_CLOUD_UI) return;
  const button = $("#deleteCloudSession");
  button.disabled = true;
  try { await api("/api/session", {method:"DELETE"}); } catch {}
  sessionStorage.removeItem(CLOUD_SESSION_KEY);
  sessionStorage.removeItem(SESSION_IMPORT_KEY);
  sessionStorage.removeItem(SESSION_TASK_KEY);
  state.system = null;
  state.imported = null;
  state.currentTask = null;
  state.tasks = [];
  state.selectedNodeIds.clear();
  $("#healthText").textContent = "云端数据已删除";
  openModal("onlineModeModal");
  $("#startCloudSession").textContent = "创建新的 1 小时临时会话";
  button.disabled = false;
  toast("会话已失效；活动请求结束后完成内存清理", "success");
}

async function initializeConnectedApp() {
  const connected = await loadSystem();
  if (!connected) return false;
  await loadHistory();
  await restoreSession();
  return true;
}

function setupOnlineMode() {
  document.body.classList.add("online-ui");
  $("#settingsEyebrow").textContent = "EPHEMERAL SETTINGS";
  $("#settingsTitle").textContent = "临时会话设置";
  $("#settingsSubtitle").textContent = "Key 会上传到 HF 临时后端，仅保存在本次进程内存会话。";
  $("#saveSettings").textContent = "保存到临时会话";
  $("#healthText").textContent = "云端版 · 等待临时会话";
  openModal("onlineModeModal");
  $("#startCloudSession").addEventListener("click", async () => {
    const button = $("#startCloudSession");
    button.disabled = true;
    button.textContent = "正在创建临时会话…";
    try {
      await createCloudSession();
      const connected = await initializeConnectedApp();
      if (!connected) throw new Error("云端服务暂时不可用");
      closeModal("onlineModeModal");
      button.textContent = "开始使用云端版";
    } catch (error) {
      button.textContent = "重试创建临时会话";
      toast(error.message, "error");
    } finally { button.disabled = false; }
  });
  $("#deleteCloudSession").addEventListener("click", deleteCloudSession);
}

function openModal(id) {
  $("#" + id).classList.remove("hidden");
  document.body.classList.add("modal-open");
}
function closeModal(id) {
  $("#" + id).classList.add("hidden");
  if (!$(".modal-backdrop:not(.hidden)")) document.body.classList.remove("modal-open");
}

function bindEvents() {
  initTabs();
  initDropZone();
  $("#importButton").addEventListener("click", importNodes);
  $("#startButton").addEventListener("click", startTask);
  $("#authorizationConfirm").addEventListener("change", syncStartAvailability);
  $("#cancelButton").addEventListener("click", cancelTask);
  $("#refreshButton").addEventListener("click", () => state.currentTask ? pollTask() : loadHistory());
  $("#settingsButton").addEventListener("click", () => openModal("settingsModal"));
  $("#themeButton").addEventListener("click", toggleTheme);
  $("#themeSelect").addEventListener("change", () => applyPreferences($("#themeSelect").value, $("#fontSizeSelect").value));
  $("#fontSizeSelect").addEventListener("change", () => applyPreferences($("#themeSelect").value, $("#fontSizeSelect").value));
  $("#saveSettings").addEventListener("click", saveSettings);
  $("#saveTaskName").addEventListener("click", saveTaskName);
  $$('[data-close]').forEach(button => button.addEventListener("click", () => closeModal(button.dataset.close)));
  $$(".modal-backdrop").forEach(backdrop => backdrop.addEventListener("click", event => { if (event.target === backdrop) closeModal(backdrop.id); }));
  $("#selectDefaultProviders").addEventListener("click", () => $$("#providerList input").forEach(input => input.checked = input.dataset.default === "true"));
  ["resultSearch","statusFilter","protocolFilter","riskFilter","typeFilter"].forEach(id => $("#" + id).addEventListener("input", () => { state.page = 1; renderRows(); }));
  $("#selectFiltered").addEventListener("click", selectFilteredNodes);
  $("#clearSelection").addEventListener("click", clearSelectedNodes);
  $("#selectPage").addEventListener("change", event => {
    const allRows = filteredRows();
    const start = (state.page - 1) * state.pageSize;
    allRows.slice(start, start + state.pageSize).forEach(row => {
      if (!row.node_id) return;
      if (event.target.checked) state.selectedNodeIds.add(row.node_id);
      else state.selectedNodeIds.delete(row.node_id);
    });
    renderRows();
  });
  $("#pagePrev").addEventListener("click", () => { state.page = Math.max(1, state.page - 1); renderRows(); });
  $("#pageNext").addEventListener("click", () => { state.page += 1; renderRows(); });
  $("#exportCsv").addEventListener("click", () => exportCurrent("csv"));
  $("#exportJson").addEventListener("click", () => exportCurrent("json"));
  $("#exportMd").addEventListener("click", () => exportCurrent("md"));
  document.addEventListener("keydown", event => {
    if (event.key === "Escape") $$(".modal-backdrop:not(.hidden)").forEach(modal => closeModal(modal.id));
    if (event.key === "Enter" && event.ctrlKey && state.activeImportTab === "paste") importNodes();
  });
}

async function boot() {
  migrateLegacyStorage();
  applyPreferences();
  bindEvents();
  if (IS_CLOUD_UI) {
    setupOnlineMode();
    if (await resumeCloudSession()) {
      if (await initializeConnectedApp()) closeModal("onlineModeModal");
    }
    return;
  }
  await initializeConnectedApp();
}

boot();
