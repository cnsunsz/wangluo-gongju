/* SSH 终端：可保存常用主机（本机配置目录，密码可选加密保存） */
window.PANELS = window.PANELS || {};

(function () {
  const $id = id => document.getElementById(id);
  let term = null;
  let fit = null;
  let es = null;
  let sid = null;
  let writing = false;
  let buf = [];
  let hosts = [];

  function FitCtor() {
    if (window.FitAddon && window.FitAddon.FitAddon) return window.FitAddon.FitAddon;
    if (window.FitAddon) return window.FitAddon;
    return null;
  }

  function formData() {
    return {
      id: ($id('sshId') && $id('sshId').value) || '',
      name: ($id('sshName') && $id('sshName').value.trim()) || '',
      host: ($id('sshHost') && $id('sshHost').value.trim()) || '',
      port: parseInt(($id('sshPort') && $id('sshPort').value) || '22', 10) || 22,
      username: ($id('sshUser') && $id('sshUser').value.trim()) || '',
      auth: ($id('sshAuth') && $id('sshAuth').value) || 'password',
      key_path: ($id('sshKey') && $id('sshKey').value.trim()) || '',
      password: ($id('sshPass') && $id('sshPass').value) || '',
      passphrase: ($id('sshPhrase') && $id('sshPhrase').value) || '',
      remember: !!( $id('sshRemember') && $id('sshRemember').checked )
    };
  }

  function fillForm(h, keepPass) {
    if ($id('sshId')) $id('sshId').value = h.id || '';
    if ($id('sshName')) $id('sshName').value = h.name || '';
    if ($id('sshHost')) $id('sshHost').value = h.host || '';
    if ($id('sshPort')) $id('sshPort').value = h.port || 22;
    if ($id('sshUser')) $id('sshUser').value = h.username || '';
    if ($id('sshAuth')) $id('sshAuth').value = h.auth || 'password';
    if ($id('sshKey')) $id('sshKey').value = h.key_path || '';
    if ($id('sshRemember')) $id('sshRemember').checked = !!h.remember;
    if (!keepPass && $id('sshPass') && !h.password) $id('sshPass').value = '';
    if (h.password && $id('sshPass')) $id('sshPass').value = h.password;
    syncAuth();
  }

  function syncAuth() {
    const auth = ($id('sshAuth') && $id('sshAuth').value) || 'password';
    const show = auth === 'key';
    ['sshKeyRow', 'sshKey', 'sshPickKey', 'sshPickKey2'].forEach(id => {
      const n = $id(id);
      if (n) n.style.display = show ? '' : 'none';
    });
  }

  async function loadHosts() {
    const box = $id('sshHosts');
    if (!box) return;
    try {
      const r = await fetch('/api/ssh/hosts');
      const d = await r.json();
      hosts = d.hosts || [];
    } catch (e) {
      hosts = [];
    }
    if (!hosts.length) {
      box.innerHTML = '<p class="meta" style="color:#6b7785;font-size:12.5px">还没有保存的主机。填好下面的连接信息后点「保存主机」。主机名单只存在本机配置目录，不会上传。</p>';
      return;
    }
    box.innerHTML = '';
    hosts.forEach(h => {
      const card = document.createElement('div');
      card.className = 'host-card';
      const addr = (h.username ? h.username + '@' : '') + h.host + ':' + h.port;
      card.innerHTML =
        `<div><div class="title">${esc(h.name || addr)}</div><div class="addr">${esc(addr)}${h.auth === 'key' ? ' · 私钥' : ''}${h.has_password ? ' · 已记住密码' : ''}</div></div>` +
        `<div class="actions">` +
        `<button type="button" class="btn ghost" data-act="use">填入并连接</button>` +
        `<button type="button" class="btn ghost" data-act="edit">编辑</button>` +
        `<button type="button" class="btn ghost" data-act="del">删除</button>` +
        `</div>`;
      card.querySelector('[data-act=use]').onclick = () => useHost(h, true);
      card.querySelector('[data-act=edit]').onclick = () => useHost(h, false);
      card.querySelector('[data-act=del]').onclick = () => deleteHost(h);
      box.appendChild(card);
    });
  }

  async function useHost(h, connectAfter) {
    try {
      const r = await fetch('/api/ssh/hosts/' + encodeURIComponent(h.id));
      const d = await r.json();
      fillForm(d.ok && d.host ? d.host : h);
    } catch (e) {
      fillForm(h);
    }
    if (connectAfter) connect();
  }

  async function saveHost() {
    const data = formData();
    if (!data.host) { toast('请填写主机地址'); return; }
    if (!data.name) data.name = (data.username ? data.username + '@' : '') + data.host + ':' + data.port;
    try {
      const r = await fetch('/api/ssh/hosts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || '保存失败');
      if (d.host && $id('sshId')) $id('sshId').value = d.host.id;
      await loadHosts();
      toast('主机已保存到本机配置目录');
      appendLog('已保存：' + (d.host && d.host.name), 'ok');
    } catch (e) {
      toast(e.message || '保存失败');
    }
  }

  async function deleteHost(h) {
    if (!confirm('删除已存主机「' + (h.name || h.host) + '」？')) return;
    try {
      const r = await fetch('/api/ssh/hosts/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: h.id })
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || '删除失败');
      if ($id('sshId') && $id('sshId').value === h.id) $id('sshId').value = '';
      await loadHosts();
      toast('已删除');
    } catch (e) {
      toast(e.message || '删除失败');
    }
  }

  function ensureTerm() {
    const box = $id('sshTerm');
    if (!box) return null;
    box.hidden = false;
    if (term) {
      try { if (fit) fit.fit(); } catch (e) {}
      return term;
    }
    if (!window.Terminal) {
      appendLog('终端组件未加载（web/vendor/xterm.js）', 'err');
      return null;
    }
    term = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: 'Cascadia Mono, Consolas, Courier New, monospace',
      theme: { background: '#0d1621', foreground: '#c9d8ea' },
      scrollback: 4000
    });
    const Ctor = FitCtor();
    if (Ctor) {
      fit = new Ctor();
      term.loadAddon(fit);
    }
    term.open(box);
    try { if (fit) fit.fit(); } catch (e) {}
    term.onData(ch => {
      if (!sid) return;
      buf.push(ch);
      flushWrite();
    });
    window.addEventListener('resize', onResize);
    return term;
  }

  function onResize() {
    if (!term || !fit || !sid) return;
    try { fit.fit(); } catch (e) {}
    fetch('/api/ssh/resize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sid, cols: term.cols, rows: term.rows })
    }).catch(() => {});
  }

  function flushWrite() {
    if (writing || !buf.length || !sid) return;
    writing = true;
    const data = buf.join('');
    buf = [];
    const payload = { sid, data };
    fetch('/api/ssh/write', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).catch(() => {}).finally(() => {
      writing = false;
      if (buf.length) flushWrite();
    });
  }

  function detachStream() {
    if (es) { try { es.close(); } catch (e) {} es = null; }
  }

  function attachStream(newSid) {
    detachStream();
    sid = newSid;
    es = new EventSource('/api/ssh/stream?sid=' + encodeURIComponent(sid));
    es.onmessage = ev => {
      let d;
      try { d = JSON.parse(ev.data); } catch (e) { return; }
      if (d.type === 'data' && d.b64 && term) {
        try {
          const bin = atob(d.b64);
          const arr = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
          term.write(arr);
        } catch (e) {}
      } else if (d.type === 'error') {
        appendLog(d.message || 'SSH 错误', 'err');
      } else if (d.type === 'closed') {
        appendLog('SSH 会话已结束', 'warn');
        setStatus('已断开', 'warn');
        setBusy(false);
        state.running = false;
        sid = null;
        detachStream();
      }
    };
    es.onerror = () => {
      if (!sid) return;
    };
  }

  async function connect() {
    const data = formData();
    if (!data.host) { toast('请填写主机地址'); return; }
    if (!data.username) { toast('请填写用户名'); return; }
    if (data.auth !== 'key' && !data.password) { toast('请填写密码，或改用私钥登录'); return; }
    if (data.auth === 'key' && !data.key_path) { toast('请选择本机私钥文件路径'); return; }
    const t = ensureTerm();
    if (!t) return;
    t.clear();
    t.reset();
    setBusy(true);
    state.running = true;
    setStatus('正在连接…', 'busy');
    appendLog('连接 ' + data.username + '@' + data.host + ':' + data.port + ' …', 'info');
    try {
      const cols = t.cols || 120, rows = t.rows || 32;
      const r = await fetch('/api/ssh/open', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(Object.assign({}, data, { cols, rows, host_id: data.id }))
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || '连接失败');
      attachStream(d.sid);
      setStatus('已连接 ' + d.username + '@' + d.host, 'ok');
      appendLog('已连接。关闭窗口不会断开，返回本工具可继续操作；点「断开」或退出程序才会结束会话。', 'ok');
      t.focus();
      try { if (fit) fit.fit(); } catch (e) {}
    } catch (e) {
      setBusy(false);
      state.running = false;
      setStatus('连接失败', 'err');
      appendLog(e.message || '连接失败', 'err');
    }
  }

  async function disconnect() {
    const cur = sid;
    detachStream();
    sid = null;
    state.running = false;
    setBusy(false);
    if (cur) {
      try {
        await fetch('/api/ssh/close', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sid: cur })
        });
      } catch (e) {}
    }
    setStatus('已断开', 'warn');
    appendLog('已断开 SSH', 'warn');
  }

  async function pickKey() {
    let path = '';
    try {
      if (window.pywebview && window.pywebview.api && window.pywebview.api.pick_file) {
        path = await window.pywebview.api.pick_file('选择私钥文件');
      }
    } catch (e) {}
    if (path && $id('sshKey')) $id('sshKey').value = path;
    else if (!path) toast('也可直接把本机私钥的完整路径粘贴到输入框');
  }

  PANELS.ssh = function (panel) {
    panel.innerHTML = `
      <p class="ssh-hint">在软件内连接 SSH 终端。常用主机保存在本机 <code>%LOCALAPPDATA%\\网络工具\\config\\</code>，不会进安装包或 Git 仓库。
      密码默认不保存；若勾选「记住密码」，会用 Windows 当前用户的 DPAPI 加密后另存，公用电脑请勿勾选。私钥只引用本机路径，不会把密钥内容写入配置。</p>
      <div id="sshHosts" class="host-list"></div>
      <form class="ssh-form" id="sshForm" autocomplete="off" onsubmit="return false">
        <input type="hidden" id="sshId">
        <label>备注名</label><input id="sshName" placeholder="例如 生产跳板，保存前可改">
        <label>主机地址</label><input id="sshHost" placeholder="IP 或域名">
        <label>端口</label><input id="sshPort" type="number" min="1" max="65535" value="22">
        <label>用户名</label><input id="sshUser" placeholder="root">
        <label>认证方式</label>
        <select id="sshAuth"><option value="password">密码</option><option value="key">私钥文件</option></select>
        <label>密码</label><input id="sshPass" type="password" placeholder="连接时使用，默认不保存">
        <label id="sshKeyRow" style="display:none">私钥路径</label>
        <div id="sshPickWrap" style="display:contents">
          <input id="sshKey" placeholder="本机私钥文件路径，例如 C:\\Users\\…\\id_rsa" style="display:none">
        </div>
        <label></label>
        <div>
          <button type="button" class="btn ghost" id="sshPickKey" style="display:none">选择私钥文件</button>
          <label class="chk-risk" style="display:block;margin-top:8px">
            <input type="checkbox" id="sshRemember"> 记住密码（加密存在本机，仅当前 Windows 用户可解密；默认关闭，公用电脑请勿勾选）
          </label>
        </div>
      </form>
      <div class="ssh-toolbar">
        <button type="button" class="btn ghost" id="sshSave">保存主机</button>
        <button type="button" class="btn ghost" id="sshReset">清空表单</button>
        <button type="button" class="btn ghost" id="sshPickKey2">选择私钥</button>
      </div>
      <div id="sshTerm" class="ssh-term" hidden></div>
    `;
    // key path visibility: put input on key row
    const keyInput = $id('sshKey');
    const keyLabel = $id('sshKeyRow');
    if (keyLabel && keyInput) {
      keyInput.style.display = '';
      keyLabel.insertAdjacentElement('afterend', keyInput);
    }
    $id('sshAuth').onchange = syncAuth;
    $id('sshSave').onclick = saveHost;
    $id('sshReset').onclick = () => fillForm({ port: 22, auth: 'password' });
    $id('sshPickKey').onclick = pickKey;
    $id('sshPickKey2').onclick = pickKey;
    syncAuth();
    loadHosts();
    if (sid && term) {
      const box = $id('sshTerm');
      if (box) {
        box.hidden = false;
        // xterm already exists from previous open; reopen in new container
        try { term.dispose(); } catch (e) {}
        term = null;
        fit = null;
        ensureTerm();
        setBusy(true);
        state.running = true;
        setStatus('已连接（会话仍在）', 'ok');
      }
    }
  };

  const prevRun = PANELS.run;
  const prevStop = PANELS.stop;
  const prevLeave = PANELS._leave;
  PANELS.run = function (id) {
    if (id === 'ssh') return connect();
    if (typeof prevRun === 'function') return prevRun(id);
  };
  PANELS.stop = function (id) {
    if (id === 'ssh') return disconnect();
    if (typeof prevStop === 'function') return prevStop(id);
  };
  PANELS._leave = function (id) {
    if (id === 'ssh') {
      window.removeEventListener('resize', onResize);
      // 离开页面不断开会话，只拆掉终端 UI
      detachStream();
      if (term) {
        try { term.dispose(); } catch (e) {}
        term = null;
        fit = null;
      }
      // 保持 sid，下次打开可提示已有会话；简化起见离开即断开流但会话仍在后端。
      // 重新进入时无法把旧 PTY 画面接回来（已 dispose），因此离开时断开。
      if (sid) {
        const cur = sid;
        sid = null;
        fetch('/api/ssh/close', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sid: cur })
        }).catch(() => {});
      }
      state.running = false;
    }
    if (typeof prevLeave === 'function') prevLeave(id);
  };
})();
