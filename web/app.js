/* 界面骨架：网格、表单、运行/停止、通用渲染 */
const $ = id => document.getElementById(id);
const state = { tool: null, es: null, ctrl: null, running: false, lines: 0, dlTick: 0, sp: {},
  ai: { configured: false, base_url: '', model: '' }, aiRunning: false, aiCtrl: null };

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

let toastTimer = null;
function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 1800);
}

async function openInApp(url, title) {
  if (!url) return false;
  try {
    if (window.pywebview && window.pywebview.api && window.pywebview.api.open_url) {
      const r = await window.pywebview.api.open_url(url, title || '');
      if (r && r.ok === false) throw new Error(r.error || '打开失败');
      return true;
    }
  } catch (e) {}
  try {
    const resp = await fetch('/api/open_url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, title: title || '' })
    });
    const d = await resp.json();
    if (!d.ok) throw new Error(d.error || '打开失败');
    return true;
  } catch (e) {
    toast((e && e.message) ? e.message : '无法在软件内打开网页');
    return false;
  }
}

function isExternalHttp(url) {
  try {
    const u = new URL(url, location.href);
    if (!/^https?:$/i.test(u.protocol)) return false;
    return u.origin !== location.origin;
  } catch (e) {
    return false;
  }
}

document.addEventListener('click', e => {
  const a = e.target.closest && e.target.closest('a[href]');
  if (!a) return;
  const href = a.href;
  if (!isExternalHttp(href)) return;
  e.preventDefault();
  openInApp(href, a.getAttribute('title') || a.textContent || '');
}, true);

(function () {
  const orig = window.open;
  window.open = function (url, name, specs) {
    if (url && isExternalHttp(url)) {
      openInApp(url, name && name !== '_blank' ? String(name) : '');
      return null;
    }
    return orig.apply(window, arguments);
  };
})();

function fmtBytes(n) {
  if (n == null) return '—';
  n = Number(n);
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1073741824) return (n / 1048576).toFixed(2) + ' MB';
  return (n / 1073741824).toFixed(2) + ' GB';
}

function setStatus(text, cls) {
  const s = $('status');
  s.textContent = text;
  s.className = 'status' + (cls ? ' ' + cls : '');
}

function appendLog(text, cls) {
  const c = $('console');
  c.hidden = false;
  const line = el('div', cls || '', text);
  c.appendChild(line);
  if (++state.lines > 1500) {
    c.removeChild(c.firstChild);
    state.lines--;
  }
  c.scrollTop = c.scrollHeight;
}

function appendStage(text) {
  const c = $('console');
  c.hidden = false;
  c.appendChild(el('div', 'stage', text));
  state.lines++;
  c.scrollTop = c.scrollHeight;
}

function setMetrics(list) {
  const box = $('metrics');
  box.hidden = false;
  box.innerHTML = '';
  list.forEach(m => {
    const card = el('div', 'metric');
    card.appendChild(el('div', 'k', m.k));
    const v = el('div', 'v');
    const text = m.v == null ? '—' : String(m.v);
    v.appendChild(document.createTextNode(text));
    if (m.u) v.appendChild(el('small', '', m.u));
    else if (text.length > 15) v.classList.add('long');
    card.appendChild(v);
    box.appendChild(card);
  });
}

function showTable(headers, rows) {
  const wrap = $('tableWrap');
  wrap.hidden = false;
  wrap.innerHTML = '';
  const table = el('table');
  const thead = el('thead');
  const tr = el('tr');
  headers.forEach(h => tr.appendChild(el('th', '', h)));
  thead.appendChild(tr);
  table.appendChild(thead);
  const tbody = el('tbody');
  rows.forEach(cells => {
    const r = el('tr');
    cells.forEach((val, i) => {
      const td = el('td');
      td.textContent = val == null || val === '' ? '—' : String(val);
      if (i > 0 && typeof val === 'number') td.className = 'num';
      r.appendChild(td);
    });
    tbody.appendChild(r);
  });
  table.appendChild(tbody);
  wrap.appendChild(table);
  wrap.hidden = false;
}

function clearOutputs() {
  if (state.aiCtrl) { state.aiCtrl.abort(); state.aiCtrl = null; }
  state.lines = 0;
  state.dlTick = 0;
  state.sp = {};
  state.mtr = {};
  state.win = [];
  const c = $('console');
  c.innerHTML = '';
  c.hidden = true;
  $('metrics').innerHTML = '';
  $('metrics').hidden = true;
  $('tableWrap').innerHTML = '';
  $('tableWrap').hidden = true;
  $('imgBox').innerHTML = '';
  $('imgBox').hidden = true;
  $('raw').hidden = true;
  $('raw').textContent = '';
  $('exportBtn').disabled = true;
  $('aiBtn').disabled = true;
  const aiBox = $('aiBox');
  aiBox.hidden = true;
  $('aiText').textContent = '';
  $('aiState').textContent = '';
}

function setBusy(busy) {
  $('runBtn').disabled = busy;
  $('stopBtn').disabled = !busy;
  $('clearBtn').disabled = busy;
  $('exportBtn').disabled = busy || !hasResult();
  $('aiBtn').disabled = busy || state.aiRunning || !hasResult();
  if (!$('pkgBtn').hidden) $('pkgBtn').disabled = busy;
  if (!$('cmpBtn').hidden) $('cmpBtn').disabled = busy;
}

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function hasResult() {
  return document.querySelectorAll('#metrics .metric').length > 0
    || document.querySelector('#tableWrap table')
    || !$('console').hidden
    || ($('raw') && !$('raw').hidden)
    || document.querySelector('#imgBox img');
}

function buildResultHtml() {
  const tool = state.tool;
  const now = new Date();
  const p = n => String(n).padStart(2, '0');
  const stamp = `${now.getFullYear()}${p(now.getMonth() + 1)}${p(now.getDate())}_` +
    `${p(now.getHours())}${p(now.getMinutes())}${p(now.getSeconds())}`;
  const timeText = `${now.getFullYear()}-${p(now.getMonth() + 1)}-${p(now.getDate())} ` +
    `${p(now.getHours())}:${p(now.getMinutes())}:${p(now.getSeconds())}`;
  const params = (tool.fields || [])
    .map(f => [f.label, String(fieldValue(f) || '').trim()])
    .filter(x => x[1] !== '');
  const metrics = Array.from(document.querySelectorAll('#metrics .metric')).map(m => [
    m.querySelector('.k').textContent,
    m.querySelector('.v').innerText.trim()
  ]);
  const tableNode = document.querySelector('#tableWrap table');
  const logs = Array.from(document.querySelectorAll('#console div')).map(d => d.textContent);
  const raw = $('raw').hidden ? '' : $('raw').textContent;
  const img = document.querySelector('#imgBox img');

  const paramHtml = params.length
    ? '<h2>参数</h2><table><tbody>' +
      params.map(([k, v]) => `<tr><th style="width:170px">${esc(k)}</th><td>${esc(v)}</td></tr>`).join('') +
      '</tbody></table>'
    : '';
  const metricHtml = metrics.length
    ? '<h2>指标</h2><div class="cards">' +
      metrics.map(([k, v]) => `<div class="card"><b>${esc(k)}</b>${esc(v)}</div>`).join('') +
      '</div>'
    : '';
  const tableHtml = tableNode
    ? '<h2>结果表格</h2><table>' + tableNode.innerHTML + '</table>'
    : '';
  const imgHtml = img
    ? '<h2>图片</h2><img src="' + img.src + '" alt="QR" style="max-width:280px;border:1px solid #e6ebf2;border-radius:8px">'
    : '';
  const logHtml = logs.length
    ? '<h2>运行日志</h2><pre>' + esc(logs.join('\n')) + '</pre>'
    : '';
  const rawHtml = raw.trim()
    ? '<h2>原始输出</h2><pre>' + esc(raw) + '</pre>'
    : '';
  const aiText = $('aiText').textContent.trim();
  const aiHtml = (!$('aiBox').hidden && aiText)
    ? '<h2>AI 分析</h2><pre>' + esc(aiText) + '</pre>'
    : '';
  const emptyHtml = (!paramHtml && !metricHtml && !tableHtml && !imgHtml && !logHtml && !rawHtml && !aiHtml)
    ? '<p style="color:#7b8794">本次没有产生结果。</p>'
    : '';
  const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>${esc(tool.name)} · 测试结果</title>
<style>
body{font-family:"Microsoft YaHei","PingFang SC",sans-serif;margin:24px;color:#26323f;line-height:1.6}
h1{font-size:20px;margin:0 0 4px}
.meta{color:#7b8794;font-size:12px;margin-bottom:16px}
h2{font-size:15px;margin:22px 0 8px;border-left:4px solid #3a4a9e;padding-left:8px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid #dfe6ef;padding:6px 9px;text-align:left;white-space:pre-wrap;vertical-align:top}
th{background:#f2f5fa}
pre{background:#f7f9fc;border:1px solid #e6ebf2;border-radius:8px;padding:10px;font-size:12px;
white-space:pre-wrap;word-break:break-all;font-family:Consolas,monospace}
.cards{display:flex;flex-wrap:wrap;gap:8px}
.card{border:1px solid #e6ebf2;border-radius:8px;padding:6px 10px;font-size:13px;min-width:110px}
.card b{display:block;font-size:11px;color:#7b8794;font-weight:400}
footer{margin-top:28px;color:#95a0ad;font-size:11px;border-top:1px solid #e6ebf2;padding-top:10px}
@media print{body{margin:0}}
</style></head><body>
<h1>网络工具 · ${esc(tool.name)} 测试结果</h1>
<div class="meta">导出时间：${timeText} ｜ 工具：${esc(tool.name)} ｜ 平台：Windows</div>
${paramHtml}${metricHtml}${tableHtml}${imgHtml}${aiHtml}${logHtml}${rawHtml}${emptyHtml}
<footer>网络工具 Windows 版 · 作者：Lorenzo</footer>
</body></html>`;
  const safeName = String(tool.name).replace(/[\\/:*?"<>|]/g, '_');
  return { filename: `${safeName}_结果_${stamp}.html`, html };
}

function exportResult() {
  if (!state.tool) return;
  if (!hasResult()) {
    toast('暂无可导出的结果，请先运行');
    return;
  }
  const { filename, html } = buildResultHtml();
  try {
    const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    appendLog(`结果已导出：${filename}`, 'ok');
  } catch (e) {
    toast('导出失败：' + e.message);
  }
}

async function exportDiagnosePackage() {
  const btn = $('pkgBtn');
  if (btn.disabled) return;
  const domainInput = $('f_domain');
  const note = domainInput && domainInput.value.trim()
    ? '诊断域名：' + domainInput.value.trim() : '';
  btn.disabled = true;
  appendLog('正在生成配置包（网卡 / 路由 / ARP / netstat / 代理 / 防火墙）…', 'muted');
  try {
    const resp = await fetch('/api/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note })
    });
    const d = await resp.json();
    if (!d.ok) throw new Error(d.error || ('HTTP ' + resp.status));
    const blob = new Blob([d.text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = d.filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    appendLog(`配置包已生成并下载：${d.filename}（${fmtBytes(d.size)}）`, 'ok');
    appendLog(`服务端保存位置：${d.path}`, 'muted');
  } catch (e) {
    appendLog('配置包导出失败：' + e.message, 'err');
  } finally {
    btn.disabled = state.running;
  }
}

function setupDnsNodes() {
  const provider = $('f_provider');
  const node = $('f_node');
  const server = $('f_server');
  if (!provider || !node || !server || typeof DNS_GROUPS === 'undefined') return;
  const fill = () => {
    const list = DNS_GROUPS[provider.value] || [];
    node.innerHTML = '';
    list.forEach(([label, ip]) => {
      const opt = document.createElement('option');
      opt.value = ip;
      opt.textContent = label + '  ' + ip;
      node.appendChild(opt);
    });
    server.value = list.length ? list[0][1] : '';
  };
  provider.onchange = fill;
  node.onchange = () => { server.value = node.value; };
  fill();
}

function stopRun() {
  if (state.es) { state.es.close(); state.es = null; }
  if (state.ctrl) { state.ctrl.abort(); state.ctrl = null; }
  state.running = false;
  setBusy(false);
}

window.APP_INFO = { platform: 'windows', os_label: 'Windows', features: {} };

function applyAppInfo(d) {
  if (!d || !d.ok) return;
  window.APP_INFO = d;
  const lab = document.getElementById('osLabel');
  if (lab && d.os_label) lab.textContent = d.os_label;
}

function isWindowsPlatform() {
  return (window.APP_INFO && window.APP_INFO.platform) ? window.APP_INFO.platform === 'windows' : true;
}

function renderTiles() {
  const grids = { detect: $('grid-detect'), query: $('grid-query'), adv: $('grid-adv') };
  TOOLS.forEach(t => {
    const tile = el('div', 'tile ' + t.color + (t.disabled ? ' disabled' : ''));
    tile.dataset.id = t.id;
    tile.title = t.sub || t.name;
    const icon = el('div', 'icon');
    icon.innerHTML = ICONS[t.icon] || '';
    tile.appendChild(icon);
    tile.appendChild(el('div', 'name', t.name));
    if (t.badge) tile.appendChild(el('span', 'badge', t.badge));
    tile.onclick = () => {
      if (t.disabled) { toast(t.badge === 'PC 不适用' ? 'PC 版不提供该功能' : '该工具将在第二批提供'); return; }
      openTool(t);
    };
    (grids[t.group] || grids.detect).appendChild(tile);
  });
}

const SEARCH_ALIASES = {
  ping: 'icmp 连通 ping',
  pingpp: 'ping++ pingplus 持续探测',
  traceroute: 'tracert 路由追踪 trace',
  mtr: 'mtr 逐跳 丢包',
  portscan: '端口探测 扫描 port scan',
  fetch: '抓取页面 http curl',
  download: '下载测试',
  probe: '服务器探测 tls 证书',
  timing: 'http速度 ttfb timing',
  speed: '测速 speedtest',
  dns: '域名解析 dns lookup',
  cndns: '全国dns 运营商',
  httpadv: 'http高级',
  iplocal: '你的ip信息 本机 网卡',
  iploc: 'ip查询 归属地 whois',
  dnsip: 'dnsip 正反查 ptr',
  ipcalc: 'ip计算器 cidr 掩码',
  ts: '时间转化 时间戳 timestamp',
  codec: '编码 加密 base64 md5 sha',
  qr: '二维码 qrcode',
  tcping: 'tcping tcp ping',
  superping: '超级ping 多主机',
  ipscan: 'ip扫描 网段',
  lanscan: '扫描局域网 arp 设备',
  triprobe: '三网拨测 阿里云 boce',
  wlan: 'wlan wifi 无线 热点',
  telnet: 'telnet banner',
  windiag: 'windows诊断 体检',
  diagnose: '网络诊断',
  sitecompare: '站点对比',
  batch: '批量任务',
  dig: 'dig dns',
  whois: 'whois 域名',
  ua: 'useragent user-agent ua',
  jsonfmt: 'json格式化',
  baseconv: '进制转换 hex',
  wol: '唤醒 wake-on-lan wol 魔术包',
  iperf3: 'iperf 吞吐',
  mtu: 'mtu 分片',
  netstat: '端口占用 连接 netstat',
  routes: '路由表 route',
  arp: 'arp 表 邻居 mac',
  ifstat: '网卡流量 速率 bandwidth',
  nattype: 'nat 类型 stun 锥型 对称',
  mux: '网卡叠加 聚合 多网卡 hypomux bond 代理 socks',
  svrextract: '服务器信息提取 合营云 工单 cmdb sn bmc',
  ssh: 'ssh 终端 远程 shell putty'
};

function toolSearchHay(t) {
  return [t.id, t.name, t.sub || '', SEARCH_ALIASES[t.id] || ''].join(' ').toLowerCase();
}

function applyToolSearch(q) {
  const needle = (q || '').trim().toLowerCase();
  let visible = 0;
  TOOLS.forEach(t => {
    const tile = document.querySelector('.tile[data-id="' + t.id + '"]');
    if (!tile) return;
    const show = !needle || toolSearchHay(t).indexOf(needle) !== -1;
    tile.classList.toggle('search-miss', !show);
    if (show) visible++;
  });
  ['detect', 'query', 'adv'].forEach(g => {
    const grid = $('grid-' + g);
    if (!grid) return;
    const any = grid.querySelectorAll('.tile:not(.search-miss)').length > 0;
    grid.classList.toggle('search-empty', !any);
  });
  const empty = $('searchEmpty');
  if (empty) empty.hidden = !needle || visible > 0;
  return visible;
}

function bindToolSearch() {
  const input = $('toolSearch');
  if (!input) return;
  const onInput = () => applyToolSearch(input.value);
  input.addEventListener('input', onInput);
  input.addEventListener('search', onInput);
  input.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      input.value = '';
      applyToolSearch('');
      return;
    }
    if (e.key !== 'Enter') return;
    e.preventDefault();
    const q = input.value.trim().toLowerCase();
    if (!q) return;
    const hits = TOOLS.filter(t => {
      const tile = document.querySelector('.tile[data-id="' + t.id + '"]');
      return tile && !tile.classList.contains('search-miss') && !t.disabled;
    });
    if (hits.length === 1) openTool(hits[0]);
  });
}

function openTool(tool) {
  stopRun();
  if (window.PANELS && state.tool && state.tool.mode === 'panel' && PANELS._leave) {
    try { PANELS._leave(state.tool.id); } catch (e) {}
  }
  state.tool = tool;
  clearOutputs();
  setStatus('就绪', '');
  $('toolIcon').innerHTML = ICONS[tool.icon] || '';
  $('toolName').textContent = tool.name;
  $('toolSub').textContent = tool.sub || '';
  const form = $('toolForm');
  const panel = $('customPanel');
  form.innerHTML = '';
  if (panel) { panel.hidden = true; panel.innerHTML = ''; }
  if (tool.mode === 'panel') {
    form.hidden = true;
    if (panel) {
      panel.hidden = false;
      if (window.PANELS && typeof PANELS[tool.id] === 'function') PANELS[tool.id](panel);
    }
    $('pkgBtn').hidden = true;
    $('cmpBtn').hidden = true;
    $('console').classList.remove('tall');
    const hideRun = tool.id === 'svrextract';
    $('runBtn').hidden = hideRun;
    $('stopBtn').hidden = hideRun;
    if (tool.id === 'mux') { $('runBtn').textContent = '启动聚合'; $('stopBtn').textContent = '停止聚合'; }
    else if (tool.id === 'ssh') { $('runBtn').textContent = '连接'; $('stopBtn').textContent = '断开'; }
    else { $('runBtn').textContent = '开始'; $('stopBtn').textContent = '停止'; }
    $('toolView').hidden = false;
    $('home').style.display = 'none';
    window.scrollTo(0, 0);
    document.title = tool.name + ' · 网络工具';
    return;
  }
  $('runBtn').hidden = false;
  $('stopBtn').hidden = false;
  $('runBtn').textContent = '开始';
  $('stopBtn').textContent = '停止';
  form.hidden = !(tool.fields && tool.fields.length);
  (tool.fields || []).forEach(f => {
    const wrap = el('div', 'field' + (f.wide ? ' wide' : ''));
    wrap.appendChild(el('label', '', f.label));
    let input;
    if (f.type === 'select') {
      input = el('select');
      (f.options || []).forEach(([v, label]) => {
        const o = el('option', '', label);
        o.value = v;
        input.appendChild(o);
      });
      input.value = f.value;
    } else if (f.type === 'textarea') {
      input = el('textarea');
      input.placeholder = f.ph || f.placeholder || '';
      input.value = f.value || '';
    } else {
      input = el('input');
      input.type = f.type || 'text';
      input.placeholder = f.ph || f.placeholder || '';
      if (f.min != null) input.min = f.min;
      if (f.max != null) input.max = f.max;
      if (f.step != null) input.step = f.step;
      input.value = f.value;
    }
    input.id = 'f_' + f.k;
    wrap.appendChild(input);
    form.appendChild(wrap);
  });
  const note = $('noteCard');
  note.innerHTML = tool.note || '';
  note.hidden = !tool.note;
  if (tool.id === 'cndns') setupDnsNodes();
  $('console').classList.toggle('tall', tool.id === 'diagnose');
  $('pkgBtn').hidden = tool.id !== 'diagnose';
  $('cmpBtn').hidden = tool.id !== 'cndns';
  $('toolView').hidden = false;
  $('home').style.display = 'none';
  window.scrollTo(0, 0);
  document.title = tool.name + ' · 网络工具';
}

function closeTool() {
  stopRun();
  if (window.PANELS && state.tool && state.tool.mode === 'panel' && PANELS._leave) {
    try { PANELS._leave(state.tool.id); } catch (e) {}
  }
  const panel = $('customPanel');
  if (panel) { panel.hidden = true; panel.innerHTML = ''; }
  $('runBtn').hidden = false;
  $('stopBtn').hidden = false;
  $('runBtn').textContent = '开始';
  $('stopBtn').textContent = '停止';
  state.tool = null;
  $('toolView').hidden = true;
  $('home').style.display = '';
  document.title = '网络工具 · Windows';
}

function fieldValue(f) {
  const node = $('f_' + f.k);
  return node ? node.value : f.value;
}

function buildSSEUrl(tool) {
  const params = new URLSearchParams();
  (tool.fields || []).forEach(f => params.set(f.k, fieldValue(f)));
  return tool.endpoint + '?' + params.toString();
}

function buildJsonBody(tool) {
  const body = {};
  (tool.fields || []).forEach(f => {
    let v = fieldValue(f);
    if (f.k === 'follow') v = v === '1';
    body[f.k] = v;
  });
  return body;
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (e) {}
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch (e) {}
  ta.remove();
  return ok;
}

async function runTriProbe() {
  const f = $('f_url');
  const target = ((f && f.value) || '').trim();
  if (!target) { toast('请输入域名或 URL'); return; }
  stopRun();
  clearOutputs();
  appendLog(`目标：${target}`, 'ok');
  const opened = await openInApp('https://boce.aliyun.com/detect/http', '阿里云三网拨测');
  appendLog(opened ? '已在软件内打开阿里云网络拨测窗口。' : '未能打开拨测窗口。', opened ? 'info' : 'err');
  const copied = await copyText(target);
  if (copied) {
    appendLog('域名已复制，点击页面输入框后 Ctrl+V 即可。', 'ok');
  } else {
    if (f) { f.focus(); f.select(); }
    appendLog('浏览器未允许写剪贴板，已选中域名，按 Ctrl+C 复制。', 'warn');
  }
  appendLog('在阿里云页面选择运营商/地域后点「立即检测」，可看三网各城市状态、耗时和导出报表。', 'muted');
  appendLog('说明：该页面禁止 iframe 嵌入（CSP frame-ancestors），本工具采用独立窗口直接引用，结果以阿里云页面为准。', 'muted');
  setStatus('已打开阿里云拨测', 'ok');
  setBusy(false);
}

function run() {
  const tool = state.tool;
  if (!tool) return;
  if (tool.id === 'triprobe') { runTriProbe(); return; }
  if (tool.mode === 'panel' && window.PANELS && typeof PANELS.run === 'function') {
    PANELS.run(tool.id);
    return;
  }
  stopRun();
  clearOutputs();
  setBusy(true);
  state.running = true;
  setStatus('运行中…', 'busy');
  if (tool.id === 'ua') {
    const f = $('f_ua');
    if (f && !f.value.trim()) f.value = navigator.userAgent;
  }
  if (tool.mode === 'sse') {
    startSSE(buildSSEUrl(tool));
  } else {
    runJson(tool.endpoint, buildJsonBody(tool));
  }
}

function startSSE(url) {
  const es = new EventSource(url);
  state.es = es;
  es.onmessage = ev => {
    if (!state.running) return;
    let d;
    try { d = JSON.parse(ev.data); } catch (e) { return; }
    if (d.type === 'done') {
      handleEvent(d);
      stopRun();
      setStatus('完成', 'ok');
    } else if (d.type === 'error') {
      handleEvent(d);
      stopRun();
      setStatus('失败', 'err');
    } else {
      handleEvent(d);
    }
  };
  es.onerror = () => {
    if (state.running) {
      stopRun();
      setStatus('连接结束', 'warn');
    }
  };
}

async function fetchJson(url, body) {
  const resp = await fetch(url, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  let data;
  try { data = await resp.json(); } catch (e) { throw new Error('HTTP ' + resp.status + '，返回非 JSON'); }
  if (!data.ok) throw new Error(data.error || ('HTTP ' + resp.status));
  return data;
}

async function runDnsCompare() {
  const provider = $('f_provider');
  const name = $('f_name');
  if (!provider || typeof DNS_GROUPS === 'undefined') return;
  const list = DNS_GROUPS[provider.value] || [];
  if (!list.length) { toast('当前分组没有可用节点'); return; }
  stopRun();
  clearOutputs();
  setBusy(true);
  state.running = true;
  setStatus('组内对比中…', 'busy');
  try {
    const domain = (name && name.value.trim()) || 'www.baidu.com';
    const data = await fetchJson('/api/cndns', {
      name: domain, servers: list.map(x => x[1]), type: 'A', timeout: 3
    });
    const labels = {};
    Object.values(DNS_GROUPS).forEach(g => g.forEach(([label, ip]) => { labels[ip] = label; }));
    data.results.forEach(r => { r.label = labels[r.server] || r.server; });
    data.provider = provider.value;
    RESULT_HANDLERS.cndns(data);
    setStatus('完成', 'ok');
  } catch (e) {
    appendLog(e.message, 'err');
    setStatus('失败', 'err');
  } finally {
    state.running = false;
    setBusy(false);
  }
}

const AI_PRESETS = {
  dashscope: ['https://dashscope.aliyuncs.com/compatible-mode/v1', 'qwen-plus'],
  deepseek: ['https://api.deepseek.com/v1', 'deepseek-chat'],
  openai: ['https://api.openai.com/v1', 'gpt-4o-mini'],
  ollama: ['http://127.0.0.1:11434/v1', 'qwen2.5:7b']
};

async function loadAiConfig() {
  try {
    const r = await fetch('/api/ai/config');
    const d = await r.json();
    if (!d.ok) return;
    state.ai = d;
    const link = $('aiSetLink');
    link.textContent = d.configured ? 'AI 已配置' : 'AI 设置';
    link.title = d.configured ? `AI：${d.model}` : 'AI 尚未配置';
  } catch (e) {}
}

function aiMsg(text, cls) {
  const m = $('aiMsg');
  m.textContent = text;
  m.className = 'modal-msg' + (cls ? ' ' + cls : '');
}

function openAiSettings() {
  const cfg = state.ai || {};
  $('aiBase').value = cfg.base_url || '';
  $('aiModel').value = cfg.model || '';
  $('aiKey').value = '';
  $('aiKey').placeholder = cfg.has_key ? '已保存（留空保持不变）' : '填写 API Key';
  $('aiSystem').value = cfg.system_prompt || '';
  $('aiPreset').value = 'custom';
  Object.entries(AI_PRESETS).forEach(([k, [base, model]]) => {
    if (base === cfg.base_url && model === cfg.model) $('aiPreset').value = k;
  });
  aiMsg('');
  $('aiModal').hidden = false;
}

function closeAiSettings() {
  $('aiModal').hidden = true;
}

function aiFormBody() {
  return {
    base_url: $('aiBase').value.trim(),
    model: $('aiModel').value.trim(),
    api_key: $('aiKey').value,
    system_prompt: $('aiSystem').value
  };
}

async function saveAiSettings() {
  try {
    const d = await fetchJson('/api/ai/config', aiFormBody());
    state.ai = d;
    await loadAiConfig();
    aiMsg('已保存', 'ok');
    setTimeout(closeAiSettings, 400);
    return true;
  } catch (e) {
    aiMsg(e.message, 'err');
    return false;
  }
}

async function testAiSettings() {
  aiMsg('保存并测试中…');
  try {
    const saved = await fetchJson('/api/ai/config', aiFormBody());
    state.ai = saved;
    const d = await fetchJson('/api/ai/test', {});
    aiMsg(`连接成功：${d.reply || 'OK'}（${d.model}）`, 'ok');
    loadAiConfig();
  } catch (e) {
    aiMsg(e.message, 'err');
  }
}

function collectResultText() {
  const tool = state.tool;
  const parts = [];
  const params = ((tool && tool.fields) || [])
    .map(f => [f.label, String(fieldValue(f) == null ? '' : fieldValue(f)).trim()])
    .filter(x => x[1] !== '');
  if (params.length) parts.push('参数：\n' + params.map(([k, v]) => `${k}: ${v}`).join('\n'));
  const metrics = Array.from(document.querySelectorAll('#metrics .metric'))
    .map(m => `${m.querySelector('.k').textContent}: ${m.querySelector('.v').innerText.trim()}`);
  if (metrics.length) parts.push('指标：\n' + metrics.join('\n'));
  const table = document.querySelector('#tableWrap table');
  if (table) parts.push('表格：\n' + table.innerText.trim());
  const logs = Array.from(document.querySelectorAll('#console div')).map(d => d.textContent).filter(Boolean);
  if (logs.length) parts.push('输出日志：\n' + logs.join('\n'));
  if (!$('raw').hidden && $('raw').textContent.trim()) {
    parts.push('原始输出：\n' + $('raw').textContent.trim());
  }
  return parts.join('\n\n').slice(0, 15000);
}

function setAiBusy(on) {
  state.aiRunning = on;
  $('runBtn').disabled = on;
  $('clearBtn').disabled = on;
  $('exportBtn').disabled = on || !hasResult();
  $('aiBtn').disabled = on || !hasResult();
  if (!$('pkgBtn').hidden) $('pkgBtn').disabled = on;
  if (!$('cmpBtn').hidden) $('cmpBtn').disabled = on;
}

async function runAiAnalyze() {
  if (state.aiRunning) return;
  if (!state.ai.configured) {
    openAiSettings();
    toast('请先配置 AI 接口');
    return;
  }
  const result = collectResultText();
  if (!result) { toast('暂无可分析的结果，请先运行工具'); return; }
  const box = $('aiBox');
  box.hidden = false;
  $('aiText').textContent = '';
  $('aiState').textContent = '分析中…';
  setAiBusy(true);
  state.aiCtrl = new AbortController();
  const focusNode = $('f_focus');
  const focus = state.tool.id === 'windiag' && focusNode ? focusNode.value.trim() : '';
  try {
    const resp = await fetch('/api/ai/analyze/stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tool: state.tool.name, params: '', result, focus }),
      signal: state.aiCtrl.signal
    });
    if (!resp.ok || !resp.body) throw new Error('HTTP ' + resp.status);
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    let got = false;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let idx;
      while ((idx = buf.indexOf('\n\n')) >= 0) {
        const chunk = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        const line = chunk.split('\n').find(l => l.startsWith('data: '));
        if (!line) continue;
        let ev;
        try { ev = JSON.parse(line.slice(6)); } catch (e) { continue; }
        if (ev.type === 'delta') {
          got = true;
          $('aiText').textContent += ev.text;
          $('aiText').scrollTop = $('aiText').scrollHeight;
        } else if (ev.type === 'error') {
          throw new Error(ev.message || 'AI 分析失败');
        }
      }
    }
    $('aiState').textContent = got ? '完成' : '无返回内容';
  } catch (e) {
    if (e.name === 'AbortError') {
      $('aiState').textContent = '已停止';
    } else {
      $('aiState').textContent = '失败';
      $('aiText').textContent += ($('aiText').textContent ? '\n\n' : '') + '错误：' + e.message;
    }
  } finally {
    state.aiCtrl = null;
    setAiBusy(false);
  }
}

async function runJson(url, body) {
  state.ctrl = new AbortController();
  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: state.ctrl.signal
    });
    let data;
    try { data = await resp.json(); } catch (e) { throw new Error('HTTP ' + resp.status + '，返回非 JSON'); }
    if (!data.ok) throw new Error(data.error || ('HTTP ' + resp.status));
    handleResult(data);
    stopRun();
    setStatus('完成', 'ok');
  } catch (e) {
    if (e.name === 'AbortError') return;
    appendLog(e.message, 'err');
    stopRun();
    setStatus('失败', 'err');
  }
}

function tickClock() {
  const d = new Date();
  const p = n => String(n).padStart(2, '0');
  $('clock').textContent = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function bootUI() {
  renderTiles();
  bindToolSearch();
  tickClock();
  setInterval(tickClock, 15000);
  $('runBtn').onclick = run;
  $('stopBtn').onclick = () => {
    if (state.tool && state.tool.mode === 'panel' && window.PANELS && typeof PANELS.stop === 'function') {
      PANELS.stop(state.tool.id);
      return;
    }
    if (!state.running) return;
    stopRun();
    appendLog('已停止', 'warn');
    setStatus('已停止', 'warn');
  };
  $('clearBtn').onclick = () => {
    if (state.running) return;
    clearOutputs();
    setStatus('就绪', '');
  };
  $('exportBtn').onclick = exportResult;
  $('pkgBtn').onclick = exportDiagnosePackage;
  $('cmpBtn').onclick = runDnsCompare;
  $('aiBtn').onclick = runAiAnalyze;
  $('aiSetLink').onclick = e => { e.preventDefault(); openAiSettings(); };
  $('aiPreset').onchange = () => {
    const p = AI_PRESETS[$('aiPreset').value];
    if (p) { $('aiBase').value = p[0]; $('aiModel').value = p[1]; }
  };
  $('aiSave').onclick = saveAiSettings;
  $('aiTest').onclick = testAiSettings;
  $('aiCancel').onclick = closeAiSettings;
  $('aiCancel2').onclick = closeAiSettings;
  $('aiModal').addEventListener('click', e => {
    if (e.target === $('aiModal')) closeAiSettings();
  });
  $('aiClose').onclick = () => { $('aiBox').hidden = true; };
  $('aiCopy').onclick = async () => {
    const text = $('aiText').textContent.trim();
    if (!text) return;
    toast(await copyText(text) ? 'AI 分析已复制' : '复制失败，请手动选择文本');
  };
  fetch('/api/wlan/status').then(r => r.json()).then(d => {
    if (d.ok && !d.available) {
      const tile = document.querySelector('.tile[data-id="wlan"]');
      if (tile) tile.remove();
    }
  }).catch(() => {});
  loadAiConfig();
  $('backBtn').onclick = closeTool;
  $('toolForm').addEventListener('submit', e => { e.preventDefault(); run(); });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && !$('aiModal').hidden) { closeAiSettings(); return; }
    if (e.key === 'Escape' && !$('toolView').hidden) closeTool();
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && !$('toolView').hidden) run();
  });
}

function init() {
  fetch('/api/settings').then(r => r.json()).then(applyAppInfo).catch(() => {}).finally(bootUI);
}

init();
