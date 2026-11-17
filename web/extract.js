/* 服务器信息提取（复用合营云 parse.js / ServerInfoParse） */
window.PANELS = window.PANELS || {};

(function () {
  const $id = id => document.getElementById(id);
  let inputs = {};

  function getData() {
    const r = ServerInfoParse.emptyResult();
    Object.keys(inputs).forEach(k => { r[k] = inputs[k].value.trim(); });
    r.region = ($id('exRegion') && $id('exRegion').value.trim()) || '';
    return r;
  }

  function setData(r) {
    r = r || ServerInfoParse.emptyResult();
    Object.keys(inputs).forEach(k => { inputs[k].value = r[k] || ''; });
    if ($id('exRegion')) $id('exRegion').value = r.region || '';
    sync(true);
  }

  function sync(refreshTitle) {
    if (!window.ServerInfoParse) return;
    const data = getData();
    if ($id('exPreview')) $id('exPreview').value = ServerInfoParse.formatTemplate(data);
    if (refreshTitle && $id('exTitle')) $id('exTitle').value = ServerInfoParse.formatTitle(data);
  }

  function countFilled(data) {
    return ['host', 'sn', 'mgmt', 'bmc', 'model', 'room', 'fault'].filter(k => data && data[k]).length;
  }

  function setExStatus(msg, err) {
    const el = $id('exStatus');
    if (!el) return;
    el.textContent = msg || '';
    el.className = 'extract-status' + (err ? ' err' : '');
    setStatus(msg || '就绪', err ? 'err' : (msg ? 'ok' : ''));
  }

  function parseRaw(source) {
    if (!window.ServerInfoParse) {
      setExStatus('解析库未加载', true);
      return false;
    }
    const text = ($id('exRaw') && $id('exRaw').value) || '';
    if (!String(text).trim()) {
      setExStatus('原文为空：请先粘贴或读取剪贴板', true);
      return false;
    }
    try {
      const data = ServerInfoParse.parseText(text);
      setData(data);
      const n = countFilled(data);
      const regionNote = data.region ? '' : ' · 未识别到区域，请在「区域」补上如 华东-无锡';
      setExStatus((source || '已解析') + ' · 识别 ' + n + ' 项' + (n === 0 ? '（内容可能不含主机信息）' : '') + regionNote);
      return true;
    } catch (e) {
      setExStatus('解析出错：' + (e && e.message ? e.message : e), true);
      return false;
    }
  }

  async function readClipboardText() {
    if (navigator.clipboard && navigator.clipboard.readText) {
      try {
        const t = await Promise.race([
          navigator.clipboard.readText(),
          new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 1500))
        ]);
        if (typeof t === 'string' && t.length) return t;
      } catch (e) {}
    }
    try {
      const raw = $id('exRaw');
      const prev = raw.value;
      raw.focus();
      raw.select();
      const ok = document.execCommand('paste');
      if (ok && raw.value && raw.value !== prev) return raw.value;
      raw.value = prev;
    } catch (e) {}
    return null;
  }

  function currentTitle() {
    const v = $id('exTitle') && $id('exTitle').value.trim();
    return v || ServerInfoParse.formatTitle(getData());
  }

  PANELS.svrextract = function (panel) {
    if (typeof ServerInfoParse === 'undefined') {
      panel.innerHTML = '<p class="extract-hint">解析库未加载（web/vendor/server-info-parse.js）。</p>';
      return;
    }
    const fieldsHtml = ServerInfoParse.FIELDS.map(f => {
      const lab = f.label.replace('：', '');
      return `<label>${lab}</label><input type="text" data-key="${f.key}" placeholder="${lab}">`;
    }).join('');
    panel.innerHTML = `
      <p class="extract-hint">从告警、CMDB 或页面文本中识别主机名、物理机 SN、管理 IP、BMC IP、型号、机房和故障，并生成工单标题。
      标题格式固定为【合营云】{区域}Server业务{主机名}硬件故障。桌面版没有「从当前页提取」，请粘贴或读取剪贴板。</p>
      <div class="extract-toolbar">
        <button type="button" class="btn primary" id="exClip">读取剪贴板并解析</button>
        <button type="button" class="btn ghost" id="exParse">解析原文</button>
        <button type="button" class="btn ghost" id="exClear">清空</button>
      </div>
      <label class="block-label" style="display:block;font-size:12px;color:#6b7785;margin:0 0 6px">原始文本（点此框后 Ctrl+V 粘贴，会自动解析）</label>
      <textarea id="exRaw" class="extract-raw" rows="7" placeholder="1）点「读取剪贴板」&#10;2）或在此框 Ctrl+V 粘贴 CloudCMDB / 告警原文&#10;3）再点「解析原文」"></textarea>
      <div class="extract-grid" id="exFields" style="margin-top:12px">${fieldsHtml}
        <label>区域</label><input id="exRegion" type="text" placeholder="未识别时可手填，例如 华东-无锡">
      </div>
      <label class="block-label" style="display:block;font-size:12px;color:#6b7785;margin:0 0 6px">工单标题（改区域或主机名会重算；也可手改）</label>
      <textarea id="exTitle" class="extract-title" rows="2"></textarea>
      <label class="block-label" style="display:block;font-size:12px;color:#6b7785;margin:8px 0 6px">信息模板</label>
      <textarea id="exPreview" class="extract-preview" rows="7" readonly></textarea>
      <div class="extract-toolbar">
        <button type="button" class="btn primary" id="exCopyAll">一键复制标题+信息</button>
        <button type="button" class="btn ghost" id="exCopyTitle">只复制标题</button>
        <button type="button" class="btn ghost" id="exCopyTpl">只复制模板</button>
      </div>
      <p id="exStatus" class="extract-status">就绪：复制页面文字后，在原文框按 Ctrl+V</p>
    `;
    inputs = {};
    panel.querySelectorAll('#exFields input[data-key]').forEach(inp => {
      inputs[inp.dataset.key] = inp;
      inp.addEventListener('input', () => sync(inp.dataset.key === 'host'));
    });
    $id('exRegion').addEventListener('input', () => sync(true));
    $id('exClear').onclick = () => {
      $id('exRaw').value = '';
      setData(ServerInfoParse.emptyResult());
      setExStatus('已清空');
      $id('exRaw').focus();
    };
    $id('exParse').onclick = () => parseRaw('手动解析');
    $id('exClip').onclick = async () => {
      setExStatus('正在读取剪贴板…');
      const t = await readClipboardText();
      if (t && t.trim()) {
        $id('exRaw').value = t;
        parseRaw('剪贴板');
        return;
      }
      $id('exRaw').focus();
      setExStatus('无法直接读剪贴板（WebView 限制）。请在上方原文框按 Ctrl+V，会自动解析', true);
    };
    $id('exRaw').addEventListener('paste', () => {
      setExStatus('已粘贴，解析中…');
      setTimeout(() => parseRaw('粘贴'), 0);
    });
    $id('exRaw').addEventListener('input', () => {
      if ($id('exRaw').value.trim().length > 12) parseRaw('输入');
    });
    $id('exCopyTpl').onclick = async () => {
      if (!$id('exPreview').value.trim() && $id('exRaw').value.trim()) parseRaw();
      const text = ServerInfoParse.formatTemplate(getData());
      if (!text.trim() || countFilled(getData()) === 0) {
        setExStatus('没有可复制的内容，请先粘贴解析', true);
        return;
      }
      const ok = await copyText(text);
      setExStatus(ok ? '已复制模板' : '复制失败：请手动全选模板框复制', !ok);
    };
    $id('exCopyTitle').onclick = async () => {
      const data = getData();
      if (!data.region && !data.host) {
        setExStatus('没有可复制的标题，请先解析或手填区域/主机名', true);
        return;
      }
      const ok = await copyText(currentTitle());
      setExStatus(ok ? '已复制标题' : '复制失败：请手动全选标题框复制', !ok);
    };
    $id('exCopyAll').onclick = async () => {
      if (!$id('exPreview').value.trim() && $id('exRaw').value.trim()) parseRaw();
      const data = getData();
      if (countFilled(data) === 0 && !data.region) {
        setExStatus('没有可复制的内容，请先粘贴解析', true);
        return;
      }
      const bundle = currentTitle() + '\n\n' + ServerInfoParse.formatTemplate(data);
      const ok = await copyText(bundle);
      const warn = data.region ? '' : '（区域为空，建议先补上再贴）';
      setExStatus(ok ? '已复制标题和信息' + warn : '复制失败：请分别复制标题和模板', !ok);
    };
    sync(true);
  };
})();
