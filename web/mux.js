/* 网卡叠加面板 */
window.PANELS = window.PANELS || {};

(function () {
  const $id = id => document.getElementById(id);
  let poll = null;
  let loaded = false;

  function fmtRate(bps) {
    const n = Number(bps) || 0;
    if (n < 1000) return n.toFixed(0) + ' B/s';
    if (n < 1e6) return (n / 1000).toFixed(1) + ' KB/s';
    return (n * 8 / 1e6).toFixed(2) + ' Mbps';
  }

  function selected() {
    return Array.from(document.querySelectorAll('#muxNics .nic-row input[type=checkbox]:checked')).map(cb => ({
      id: cb.value,
      weight: parseInt(($id('mux-w-' + cb.value) || {}).value || '1', 10) || 1
    }));
  }

  async function refreshAdapters() {
    const box = $id('muxNics');
    if (!box) return;
    box.textContent = '正在读取网卡…';
    try {
      const r = await fetch('/api/mux/adapters');
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || '读取失败');
      const list = d.adapters || [];
      if (!list.length) {
        box.innerHTML = '<p class="meta">没有发现带 IPv4 的活动网卡。</p>';
        return;
      }
      box.innerHTML = '';
      list.forEach(a => {
        const row = document.createElement('label');
        row.className = 'nic-row';
        row.innerHTML =
          `<input type="checkbox" value="${esc(a.id)}" ${a.gateway ? 'checked' : ''}>` +
          `<div><div class="nm">${esc(a.name)} · ${esc(a.kind || '')}</div>` +
          `<div class="meta">${esc(a.ipv4)}${a.prefix ? '/' + a.prefix : ''}　网关 ${esc(a.gateway || '—')}　索引 ${esc(a.ifindex)}　${esc(a.speed || '')}</div></div>` +
          `<span class="meta">权重</span>` +
          `<input type="number" id="mux-w-${esc(a.id)}" min="1" max="100" value="1">`;
        box.appendChild(row);
      });
    } catch (e) {
      box.textContent = e.message || '读取网卡失败';
    }
  }

  function renderStatus(d) {
    if (!d) return;
    const running = !!d.running;
    setBusy(running);
    state.running = running;
    setStatus(running ? '聚合运行中' : '已停止', running ? 'busy' : '');
    const addrs = [];
    if (d.http) addrs.push('HTTP ' + d.http);
    if (d.socks) addrs.push('SOCKS5 ' + d.socks);
    setMetrics([
      { k: '状态', v: running ? '运行中' : '已停止' },
      { k: '策略', v: d.strategy === 'weighted' ? '按权重' : '轮询' },
      { k: 'HTTP 代理', v: d.http || '—' },
      { k: 'SOCKS5', v: d.socks || '—' },
      { k: '系统代理', v: d.system_proxy ? '已接管' : '未接管' }
    ]);
    const rows = d.adapters || [];
    if (rows.length) {
      showTable(['网卡', 'IPv4', '权重', '连接数', '下行', '上行'],
        rows.map(a => [a.name, a.ipv4, a.weight, a.connections, fmtRate(a.down_bps), fmtRate(a.up_bps)]));
    }
    if (d.error) appendLog(d.error, 'warn');
  }

  async function tick() {
    try {
      const r = await fetch('/api/mux/status');
      const d = await r.json();
      if (d.ok) renderStatus(d);
    } catch (e) {}
  }

  function startPoll() {
    if (poll) return;
    poll = setInterval(tick, 1000);
  }
  function stopPoll() {
    if (poll) { clearInterval(poll); poll = null; }
  }

  async function startMux() {
    const adapters = selected();
    if (!adapters.length) { toast('请至少勾选一张网卡'); return; }
    const strategy = ($id('muxStrategy') || {}).value || 'rr';
    const system_proxy = !!($id('muxSysProxy') && $id('muxSysProxy').checked);
    setStatus('正在启动…', 'busy');
    try {
      const r = await fetch('/api/mux/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ adapters, strategy, system_proxy })
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || '启动失败');
      clearOutputs();
      appendLog('聚合已启动。只有走系统代理或手动填写本地代理的应用才会分流。', 'ok');
      appendLog('HTTP：' + d.http + '　SOCKS5：' + d.socks, 'info');
      if (d.system_proxy) appendLog('已接管当前用户的 Windows 系统代理；停止或退出时会自动恢复。', 'info');
      renderStatus(d);
      startPoll();
      toast('网卡叠加已启动');
    } catch (e) {
      setStatus('启动失败', 'err');
      appendLog(e.message || '启动失败', 'err');
    }
  }

  async function stopMux() {
    try {
      const r = await fetch('/api/mux/stop', { method: 'POST' });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || '停止失败');
      renderStatus({ running: false, strategy: 'rr', adapters: [] });
      appendLog('已停止聚合，并恢复原先的系统代理（若曾接管）。', 'warn');
      setStatus('已停止', 'warn');
      setBusy(false);
      state.running = false;
      toast('已停止网卡叠加');
    } catch (e) {
      appendLog(e.message || '停止失败', 'err');
    }
  }

  PANELS.mux = function (panel) {
    loaded = true;
    panel.innerHTML = `
      <div class="mux-note">
        这是<strong>连接级</strong>负载分配：每条新的 TCP 会绑定到一张已选网卡（源地址 + Windows IP_UNICAST_IF）。
        <b>不会</b>拆开单条 TCP，也不是网卡绑线（bonding），<b>不要指望单连接测速等于多条网络之和</b>。
        适合浏览器、IDM、Steam 等多连接下载。同一路由器下的有线 + Wi-Fi 仍然共享出口带宽。
        只有遵循系统代理或手动填写下方本地代理的应用才会走聚合；本工具本身不创建虚拟网卡 / TUN。
      </div>
      <div class="mux-toolbar">
        <button type="button" class="btn ghost" id="muxRefresh">刷新网卡</button>
      </div>
      <div class="nic-list" id="muxNics"></div>
      <div class="mux-opts">
        <label>调度策略
          <select id="muxStrategy">
            <option value="rr">轮询（默认）</option>
            <option value="weighted">按权重</option>
          </select>
        </label>
        <label><input type="checkbox" id="muxSysProxy" checked> 接管 Windows 系统代理（当前用户，无需管理员）</label>
      </div>
      <div class="mux-warn">停止聚合、退出程序或异常退出时会尝试恢复原先的系统代理。策略变更只影响之后的新连接，已建立的 TCP 不会迁移。</div>
    `;
    $id('muxRefresh').onclick = refreshAdapters;
    refreshAdapters();
    tick().then(() => {
      const d = state; // if already running, keep polling
    });
    fetch('/api/mux/status').then(r => r.json()).then(d => {
      if (d.ok) {
        renderStatus(d);
        if (d.running) {
          appendLog('聚合已在运行。HTTP：' + d.http + '　SOCKS5：' + d.socks, 'info');
          startPoll();
        }
      }
    }).catch(() => {});
  };

  const prevRun = PANELS.run;
  const prevStop = PANELS.stop;
  const prevLeave = PANELS._leave;
  PANELS.run = function (id) {
    if (id === 'mux') return startMux();
    if (typeof prevRun === 'function') return prevRun(id);
  };
  PANELS.stop = function (id) {
    if (id === 'mux') return stopMux();
    if (typeof prevStop === 'function') return prevStop(id);
  };
  PANELS._leave = function (id) {
    if (id === 'mux') stopPoll();
    if (typeof prevLeave === 'function') prevLeave(id);
  };
})();
