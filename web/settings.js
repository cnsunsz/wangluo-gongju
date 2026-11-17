/* 应用设置：开机自启；关闭窗口始终留在后台 */
(function () {
  const $ = id => document.getElementById(id);

  function openSettings() {
    const m = $('settingsModal');
    if (!m) return;
    m.hidden = false;
    $('settingsMsg').textContent = '';
    $('settingsMsg').className = 'modal-msg';
    fetch('/api/settings').then(r => r.json()).then(d => {
      if (!d.ok) return;
      $('setAutostart').checked = !!d.autostart;
      if (d.run_dir) {
        $('settingsPath').textContent = '配置与日志保存在：' + d.run_dir + '（不会在程序目录创建 data 文件夹）';
      }
      const hint = $('autostartHint');
      if (hint) {
        if (d.platform === 'macos') {
          hint.textContent = '登录 macOS 后自动启动并显示主窗口（写入当前用户 LaunchAgents）。点关闭仍会隐藏到菜单栏 / Dock。';
        } else if (d.platform === 'windows') {
          hint.textContent = '登录 Windows 后自动启动并显示主窗口。点关闭仍会隐藏到托盘。';
        }
      }
      if (d.features && d.features.autostart === false) {
        const row = $('setAutostart') && $('setAutostart').closest('.switch-row');
        if (row) row.hidden = true;
      }
    }).catch(() => {});
  }

  function closeSettings() {
    const m = $('settingsModal');
    if (m) m.hidden = true;
  }

  async function saveSettings() {
    const msg = $('settingsMsg');
    msg.className = 'modal-msg';
    msg.textContent = '正在保存…';
    try {
      const resp = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          autostart: $('setAutostart').checked
        })
      });
      const d = await resp.json();
      if (!d.ok) throw new Error(d.error || '保存失败');
      msg.className = 'modal-msg ok';
      msg.textContent = (d.platform === 'macos') ? '已保存。点黄灯会最小化到 Dock；点关闭才隐藏到后台。只有菜单栏「退出」或「退出程序」才会结束进程。' : '已保存。点减号会最小化到任务栏；点关闭才进入托盘。只有托盘「退出」或「退出程序」才会结束进程。';
      if (typeof toast === 'function') toast('设置已保存');
    } catch (e) {
      msg.className = 'modal-msg err';
      msg.textContent = e.message || '保存失败';
    }
  }

  async function exitApp() {
    if (!confirm('确定退出网络工具？会结束进程（包括正在运行的网卡叠加和 SSH 会话）。')) return;
    try {
      await fetch('/api/shutdown', { method: 'POST' });
    } catch (e) {}
  }

  function openHelp() {
    const m = $('helpModal');
    const f = $('helpFrame');
    if (!m || !f) { window.location.href = 'help.html'; return; }
    if (!f.getAttribute('data-loaded')) {
      f.src = 'help.html';
      f.setAttribute('data-loaded', '1');
    }
    m.hidden = false;
  }
  function closeHelp() {
    const m = $('helpModal');
    if (m) m.hidden = true;
  }

  function bind() {
    const link = $('settingsLink');
    if (link) link.onclick = e => { e.preventDefault(); openSettings(); };
    const help = $('helpLink');
    if (help) help.onclick = e => { e.preventDefault(); openHelp(); };
    const sc = $('settingsClose'), sc2 = $('settingsCancel'), ss = $('settingsSave');
    const se = $('settingsExit');
    if (sc) sc.onclick = closeSettings;
    if (sc2) sc2.onclick = closeSettings;
    if (ss) ss.onclick = saveSettings;
    if (se) se.onclick = exitApp;
    const hc = $('helpClose');
    if (hc) hc.onclick = closeHelp;
    const sm = $('settingsModal');
    if (sm) sm.addEventListener('click', e => { if (e.target === sm) closeSettings(); });
    const hm = $('helpModal');
    if (hm) hm.addEventListener('click', e => { if (e.target === hm) closeHelp(); });
    document.addEventListener('keydown', e => {
      if (e.key !== 'Escape') return;
      if (sm && !sm.hidden) { closeSettings(); e.stopPropagation(); }
      if (hm && !hm.hidden) { closeHelp(); e.stopPropagation(); }
    }, true);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bind);
  else bind();
})();
