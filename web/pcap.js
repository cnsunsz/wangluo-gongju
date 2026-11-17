/* 抓包分析：列表 / 报文分析（分析结论 + 整次抓包结论） / 逐层详情 / 字节 */
window.PANELS = window.PANELS || {};

(function () {
  const $id = id => document.getElementById(id);
  const ROW_H = 26;
  const COLS = [
    { k: 'no', w: 56, label: '序号' },
    { k: 'time', w: 88, label: '时间' },
    { k: 'src', w: 168, label: '源地址' },
    { k: 'dst', w: 168, label: '目的地址' },
    { k: 'protocol', w: 72, label: '协议' },
    { k: 'length', w: 56, label: '长度' },
    { k: 'info', w: 0, label: 'Info' }
  ];

  let packets = [];
  let filtered = [];
  let selectedNo = 0;
  let currentDetail = null;
  let highlight = null;
  let rawBytes = new Uint8Array(0);
  let pollTimer = null;
  let running = false;
  let firstTs = 0;
  let cap = null;
  let listAtBottom = true;
  let listHeight = 280;
  let treeHeight = 340;
  let bytesHeight = 240;

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function fmtRel(ts) {
    if (!firstTs) firstTs = ts || 0;
    const d = (ts || 0) - firstTs;
    if (d < 0) return '0.000000';
    return d.toFixed(6);
  }

  function fmtAbs(ts) {
    if (!ts) return '';
    const d = new Date(ts * 1000);
    if (isNaN(d.getTime())) return String(ts);
    const ms = ('000000' + Math.floor((ts % 1) * 1e6)).slice(-6);
    const p = n => ('0' + n).slice(-2);
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) +
      ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds()) + '.' + ms;
  }

  function protoClass(p) {
    p = (p || '').toLowerCase();
    if (p === 'tcp') return 'p-tcp';
    if (p === 'udp') return 'p-udp';
    if (p === 'dns') return 'p-dns';
    if (p === 'http') return 'p-http';
    if (p === 'tls' || p === 'ssl') return 'p-tls';
    if (p === 'arp') return 'p-arp';
    if (p === 'icmp' || p === 'icmpv6') return 'p-icmp';
    return '';
  }

  function setPcapStatus(text, kind) {
    const el = $id('pcapStatus');
    if (!el) return;
    el.textContent = text || '';
    el.className = 'pcap-status' + (kind ? ' ' + kind : '');
  }

  function showBanner(capInfo) {
    const box = $id('pcapBanner');
    if (!box || !capInfo) return;
    const short = capInfo.banner_short || '';
    const msgs = (capInfo.messages || []).slice();
    const hints = capInfo.hints || [];
    if (capInfo.live_available && !short) {
      box.hidden = true;
      box.innerHTML = '';
      return;
    }
    const line = short || msgs[0] || '打开 pcap 仍可用于离线分析。';
    const url = capInfo.npcap_url || 'https://npcap.com/';
    const needLink = !capInfo.live_available && capInfo.platform === 'windows';
    let html = '<div class="pcap-banner-line"><span class="pcap-banner-msg">' + esc(line) + '</span>';
    if (needLink) html += '<a href="' + esc(url) + '" id="pcapNpcapLink">Npcap 官网</a>';
    const details = [];
    msgs.forEach(m => { if (m && m !== line) details.push(m); });
    hints.forEach(h => { if (h) details.push(h); });
    if (details.length) html += '<button type="button" class="btn ghost small" id="pcapBannerMore">详情</button>';
    html += '<button type="button" class="btn ghost small pcap-banner-x" id="pcapBannerClose" title="关闭提示">×</button></div>';
    if (details.length) {
      html += '<div class="pcap-banner-detail" id="pcapBannerDetail" hidden><ul>' +
        details.map(h => '<li>' + esc(h) + '</li>').join('') + '</ul></div>';
    }
    box.innerHTML = html;
    box.hidden = false;
    box.className = 'pcap-banner' + ((capInfo.banner_kind || (!capInfo.live_available ? 'warn' : '')) ? ' ' + (capInfo.banner_kind || 'warn') : '');
    const link = $id('pcapNpcapLink');
    if (link) {
      link.addEventListener('click', ev => {
        ev.preventDefault();
        if (typeof openInApp === 'function') openInApp(url, 'Npcap');
        else window.open(url);
      });
    }
    const more = $id('pcapBannerMore');
    if (more) {
      more.addEventListener('click', () => {
        const d = $id('pcapBannerDetail');
        if (!d) return;
        d.hidden = !d.hidden;
        more.textContent = d.hidden ? '详情' : '收起';
      });
    }
    const clo = $id('pcapBannerClose');
    if (clo) clo.addEventListener('click', () => { box.hidden = true; });
  }

  async function loadCapability() {
    try {
      const r = await fetch('/api/pcap/interfaces');
      const d = await r.json();
      cap = d;
      showBanner(d);
      const sel = $id('pcapIface');
      if (sel) {
        const cur = sel.value;
        sel.innerHTML = '';
        const list = d.interfaces || [];
        if (!list.length) {
          const o = document.createElement('option');
          o.value = '';
          o.textContent = d.live_available ? '未发现网卡' : '实时抓包不可用（仍可打开文件）';
          sel.appendChild(o);
        } else {
          list.forEach(a => {
            const o = document.createElement('option');
            o.value = a.id;
            const ips = (a.addresses || []).join(', ');
            o.textContent = (a.name || a.id) + (ips ? '  ·  ' + ips : '') + (a.loopback ? '  (loopback)' : '');
            sel.appendChild(o);
          });
          if (cur) sel.value = cur;
        }
      }
      const pre = $id('pcapPreset');
      if (pre && !(pre.options && pre.options.length)) {
        (d.presets || []).forEach(p => {
          const o = document.createElement('option');
          o.value = p.expr;
          o.textContent = p.label;
          pre.appendChild(o);
        });
      }
      const startBtn = $id('pcapStart');
      if (startBtn) startBtn.disabled = !d.live_available;
      return d;
    } catch (e) {
      showBanner({ messages: ['读取抓包能力失败：' + (e.message || e)], live_available: false, hints: [] });
    }
  }

  function currentBpf() {
    const custom = ($id('pcapBpf').value || '').trim();
    if (custom) return custom;
    return ($id('pcapPreset').value || '').trim();
  }

  function renderList() {
    const body = $id('pcapListBody');
    const spacer = $id('pcapListSpacer');
    if (!body || !spacer) return;
    const q = ($id('pcapFilter') && $id('pcapFilter').value) || '';
    // 过滤在服务端也可做；这里用已缓存摘要在前端再滤一次，即时输入更跟手
    if (typeof matchFilterLocal === 'function') {
      /* no-op placeholder */
    }
    filtered = filterLocal(packets, q);
    const n = filtered.length;
    spacer.style.height = (n * ROW_H) + 'px';
    const top = body.scrollTop;
    const vis = Math.max(20, Math.ceil(body.clientHeight / ROW_H) + 8);
    let start = Math.max(0, Math.floor(top / ROW_H) - 2);
    let end = Math.min(n, start + vis);
    const rows = $id('pcapListRows');
    rows.style.transform = 'translateY(' + (start * ROW_H) + 'px)';
    let html = '';
    for (let i = start; i < end; i++) {
      const p = filtered[i];
      const sel = p.no === selectedNo ? ' selected' : '';
      const time = fmtRel(p.ts);
      html += '<div class="pcap-row ' + protoClass(p.protocol) + sel + '" data-no="' + p.no + '" style="height:' + ROW_H + 'px">' +
        '<span class="c-no">' + p.no + '</span>' +
        '<span class="c-time" title="' + esc(fmtAbs(p.ts)) + '">' + esc(time) + '</span>' +
        '<span class="c-src" title="' + esc(p.src) + '">' + esc(p.src) + '</span>' +
        '<span class="c-dst" title="' + esc(p.dst) + '">' + esc(p.dst) + '</span>' +
        '<span class="c-proto">' + esc(p.protocol) + '</span>' +
        '<span class="c-len">' + esc(p.length) + '</span>' +
        '<span class="c-info" title="' + esc(p.info) + '">' + esc(p.info) + '</span>' +
        '</div>';
    }
    rows.innerHTML = html;
    const countEl = $id('pcapCount');
    if (countEl) countEl.textContent = (q.trim() ? (filtered.length + ' / ' + packets.length) : String(packets.length)) + ' 包';
  }

  function filterLocal(list, q) {
    q = (q || '').trim();
    if (!q) return list.slice();
    const ql = q.toLowerCase();
    return list.filter(p => {
      const text = [p.src, p.dst, p.protocol, p.info, p.ip_src, p.ip_dst, p.sport, p.dport, p.no].join(' ').toLowerCase();
      // 简单包含；复杂表达式再走与后端一致的宽松匹配
      const tokens = ql.replace(/\s*==\s*/g, '==').split(/\s+or\s+|\s+\|\|\s+/i);
      if (tokens.length > 1) return tokens.some(t => matchOne(p, text, t.trim()));
      return matchOne(p, text, ql);
    });
  }

  function matchOne(p, text, q) {
    if (!q) return true;
    const parts = q.split(/\s+/);
    for (let t of parts) {
      t = t.trim();
      if (!t) continue;
      if (/^(tcp|udp|dns|http|tls|arp|icmp|ipv4|ipv6)$/.test(t)) {
        if (String(p.protocol || '').toLowerCase() !== t && text.indexOf(t) < 0) return false;
        continue;
      }
      const mPort = t.match(/^(?:port|tcp\.port|udp\.port)(?:=+|:)(\d+)$/) || t.match(/^port:(\d+)$/);
      if (mPort) {
        if (Number(mPort[1]) !== p.sport && Number(mPort[1]) !== p.dport) return false;
        continue;
      }
      if (t === 'port' || t === 'host') continue;
      const mHost = t.match(/^(?:host|ip\.addr|ip)==(.+)$/);
      if (mHost) {
        const h = mHost[1];
        if (h !== p.src && h !== p.dst && h !== p.ip_src && h !== p.ip_dst) return false;
        continue;
      }
      if (/^\d+$/.test(t)) {
        const n = Number(t);
        if (n !== p.sport && n !== p.dport && text.indexOf(t) < 0) return false;
        continue;
      }
      if (text.indexOf(t) < 0) return false;
    }
    return true;
  }

  async function selectPacket(no) {
    selectedNo = no;
    renderList();
    const tree = $id('pcapTree');
    const bytes = $id('pcapBytes');
    const ana = $id('pcapPktAnaBody');
    if (tree) tree.innerHTML = '<div class="pcap-empty">正在解析…</div>';
    if (ana) ana.innerHTML = '<div class="pcap-empty">正在分析…</div>';
    try {
      const r = await fetch('/api/pcap/packet/' + no);
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || '读取失败');
      if (selectedNo !== no) return;
      currentDetail = d;
      rawBytes = b64ToBytes(d.raw_b64 || '');
      highlight = null;
      renderTree(d.layers || []);
      if (tree) tree.scrollTop = 0;
      renderBytes();
      if (bytes) bytes.scrollTop = 0;
      renderPacketAnalysis(d.analysis);
    } catch (e) {
      if (tree) tree.innerHTML = '<div class="pcap-empty err">' + esc(e.message || e) + '</div>';
      if (ana) ana.innerHTML = '<div class="pcap-empty err">' + esc(e.message || e) + '</div>';
    }
  }

  function b64ToBytes(s) {
    try {
      const bin = atob(s);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    } catch (e) { return new Uint8Array(0); }
  }

  function renderTree(layers) {
    const tree = $id('pcapTree');
    if (!tree) return;
    if (!layers.length) {
      tree.innerHTML = '<div class="pcap-empty">没有解析结果</div>';
      return;
    }
    const root = document.createElement('div');
    layers.forEach(n => root.appendChild(treeNode(n, true)));
    tree.innerHTML = '';
    tree.appendChild(root);
  }

  function treeNode(n, open) {
    const wrap = document.createElement('div');
    wrap.className = 'pcap-tnode';
    const kids = n.children || [];
    const row = document.createElement('div');
    row.className = 'pcap-trow' + (kids.length ? ' has-kids' : '');
    row.dataset.off = String(n.offset || 0);
    row.dataset.len = String(n.length || 0);
    const twist = document.createElement('span');
    twist.className = 'twist';
    twist.textContent = kids.length ? (open ? '▾' : '▸') : '•';
    const lab = document.createElement('span');
    lab.className = 'tlab';
    const title = n.summary || (n.value != null && n.value !== '' ? (n.name + ': ' + n.value) : n.name);
    lab.textContent = title;
    if (n.value != null && n.summary) {
      lab.textContent = n.name + ': ' + (n.summary || n.value);
    }
    row.appendChild(twist);
    row.appendChild(lab);
    if (n.length) {
      const meta = document.createElement('span');
      meta.className = 'tmeta';
      meta.textContent = n.offset + ':' + n.length;
      row.appendChild(meta);
    }
    row.addEventListener('click', ev => {
      ev.stopPropagation();
      tree.querySelectorAll('.pcap-trow.active').forEach(x => x.classList.remove('active'));
      row.classList.add('active');
      highlight = { offset: Number(row.dataset.off) || 0, length: Number(row.dataset.len) || 0 };
      renderBytes();
      if (kids.length && ev.target === twist) {
        const body = wrap.querySelector('.pcap-tkids');
        if (body) {
          const show = body.hidden;
          body.hidden = !show;
          twist.textContent = show ? '▾' : '▸';
        }
      }
    });
    if (kids.length) {
      twist.addEventListener('click', ev => {
        ev.stopPropagation();
        const body = wrap.querySelector('.pcap-tkids');
        if (!body) return;
        const show = body.hidden;
        body.hidden = !show;
        twist.textContent = show ? '▾' : '▸';
      });
    }
    wrap.appendChild(row);
    if (kids.length) {
      const body = document.createElement('div');
      body.className = 'pcap-tkids';
      body.hidden = !open;
      kids.forEach(ch => body.appendChild(treeNode(ch, false)));
      wrap.appendChild(body);
    }
    return wrap;
  }

  function renderBytes() {
    const box = $id('pcapBytes');
    if (!box) return;
    const data = rawBytes;
    if (!data.length) {
      box.innerHTML = '<div class="pcap-empty">选择一条报文以查看原始字节</div>';
      return;
    }
    const hl0 = highlight && highlight.length ? highlight.offset : -1;
    const hl1 = highlight && highlight.length ? highlight.offset + highlight.length : -1;
    let html = '';
    for (let i = 0; i < data.length; i += 16) {
      let hex = '';
      let asc = '';
      for (let j = 0; j < 16; j++) {
        const off = i + j;
        if (off >= data.length) {
          hex += '<span class="b pad">  </span>' + (j === 7 ? ' ' : '');
          continue;
        }
        const on = hl0 >= 0 && off >= hl0 && off < hl1;
        const cls = 'b' + (on ? ' on' : '');
        const hx = ('0' + data[off].toString(16)).slice(-2);
        const ch = (data[off] >= 32 && data[off] < 127) ? String.fromCharCode(data[off]) : '.';
        hex += '<span class="' + cls + '" data-off="' + off + '">' + hx + '</span>' + (j === 7 ? ' ' : '');
        asc += '<span class="' + cls + '" data-off="' + off + '">' + esc(ch) + '</span>';
      }
      html += '<div class="pcap-bline"><span class="boff">' + ('0000' + i.toString(16)).slice(-4) + '</span>' +
        '<span class="bhex">' + hex + '</span><span class="basc">' + asc + '</span></div>';
    }
    box.innerHTML = html;
    if (hl0 >= 0) {
      const el = box.querySelector('.b.on');
      if (el) {
        const r = el.getBoundingClientRect();
        const br = box.getBoundingClientRect();
        if (r.top < br.top || r.bottom > br.bottom) el.scrollIntoView({ block: 'nearest' });
      }
    }
  }

  function applyStatus(d) {
    if (!d) return;
    running = !!d.running;
    const startBtn = $id('pcapStart');
    const stopBtn = $id('pcapStop');
    if (startBtn) startBtn.disabled = running || !!(cap && cap.live_available === false);
    if (stopBtn) stopBtn.disabled = !running;
    let msg = running ? '正在抓包…' : (d.source === 'file' ? ('已打开 ' + (d.file_name || '文件')) : '就绪');
    if (d.count) msg += '　' + d.count + ' 包';
    if (d.bytes) msg += '　' + fmtBytes(d.bytes);
    if (d.dropped_old) msg += '　已丢弃最旧 ' + d.dropped_old;
    let kind = running ? 'busy' : '';
    if (d.warning) { msg += '　' + d.warning; kind = 'warn'; }
    if (d.error) { msg += '　' + d.error; kind = 'err'; }
    if (d.file_warnings && d.file_warnings.length && !d.warning) {
      msg += '　' + d.file_warnings.join('；');
      kind = kind || 'warn';
    }
    setPcapStatus(msg, kind);
    if (typeof setStatus === 'function') {
      setStatus(d.error ? '抓包出错' : (running ? '抓包中' : '就绪'), d.error ? 'err' : (running ? 'busy' : ''));
      if (typeof setBusy === 'function') setBusy(running);
    }
  }

  function fmtBytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / (1024 * 1024)).toFixed(1) + ' MB';
  }

  async function pull(reset) {
    if (reset) {
      packets = [];
      firstTs = 0;
      selectedNo = 0;
      currentDetail = null;
      rawBytes = new Uint8Array(0);
    }
    const after = packets.length ? packets[packets.length - 1].no : 0;
    const r = await fetch('/api/pcap/packets?after=' + after + '&limit=2000');
    const d = await r.json();
    if (!d.ok) throw new Error(d.error || '读取失败');
    applyStatus(d);
    const add = d.packets || [];
    if (add.length) {
      if (!firstTs && add[0].ts) firstTs = add[0].ts;
      // 若服务端因上限丢掉了最旧包，前端缓存可能对不齐：简单检测 no 不连续则重拉
      packets.push.apply(packets, add);
      if ((d.dropped_old || 0) > 0 && packets.length && packets[0].no > 1) {
        // 丢弃前端中已被淘汰的
        const keepMin = packets[packets.length - 1].no - (d.count || packets.length) + 1;
        packets = packets.filter(p => p.no >= keepMin);
      }
    }
    renderList();
    const body = $id('pcapListBody');
    if (body && running && listAtBottom) body.scrollTop = body.scrollHeight;
    if (add.length || reset) scheduleDiagnose();
    if (!selectedNo && (filtered.length || packets.length)) selectFirstVisible();
    return d;
  }

  function startPoll() {
    stopPoll();
    pollTimer = setInterval(() => {
      pull(false).catch(e => setPcapStatus(e.message || String(e), 'err'));
    }, 450);
  }

  function stopPoll() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }

  async function startCap() {
    const iface = ($id('pcapIface') && $id('pcapIface').value) || '';
    if (!iface) { toast('请先选择网卡，或改为打开 pcap 文件'); return; }
    const maxp = parseInt(($id('pcapMax') && $id('pcapMax').value) || '10000', 10) || 10000;
    const onLimit = ($id('pcapOnLimit') && $id('pcapOnLimit').value) || 'drop';
    try {
      setPcapStatus('正在开始抓包…', 'busy');
      const r = await fetch('/api/pcap/start', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ iface, bpf: currentBpf(), max_packets: maxp, on_limit: onLimit, promiscuous: true })
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || '开始失败');
      packets = [];
      firstTs = 0;
      selectedNo = 0;
      applyStatus(d);
      renderList();
      startPoll();
    } catch (e) {
      setPcapStatus(e.message || String(e), 'err');
      toast(e.message || '无法开始抓包');
    }
  }

  async function stopCap() {
    try {
      const r = await fetch('/api/pcap/stop', { method: 'POST' });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || '停止失败');
      applyStatus(d);
      stopPoll();
      await pull(false);
    } catch (e) {
      setPcapStatus(e.message || String(e), 'err');
    }
  }

  async function clearCap() {
    try {
      const r = await fetch('/api/pcap/clear', { method: 'POST' });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || '清空失败');
      packets = [];
      firstTs = 0;
      selectedNo = 0;
      currentDetail = null;
      rawBytes = new Uint8Array(0);
      applyStatus(d);
      renderList();
      scheduleDiagnose();
      const tree = $id('pcapTree');
      const bytes = $id('pcapBytes');
      const ana = $id('pcapPktAnaBody');
      if (tree) tree.innerHTML = '<div class="pcap-empty">选择一条报文，查看逐层字段</div>';
      if (bytes) bytes.innerHTML = '<div class="pcap-empty">选择一条报文以查看原始字节</div>';
      const root = $id('pcapAnalysis');
      if (root) root.classList.remove('has-packet');
      if (ana) ana.innerHTML = '<div class="pcap-empty">打开或抓取报文后，将自动选中第一条并给出分析结论</div>';
    } catch (e) {
      setPcapStatus(e.message || String(e), 'err');
    }
  }

  async function openPcap() {
    const maxp = parseInt(($id('pcapMax') && $id('pcapMax').value) || '10000', 10) || 10000;
    let path = '';
    try {
      if (window.pywebview && window.pywebview.api && window.pywebview.api.pick_file) {
        path = await window.pywebview.api.pick_file('打开抓包文件', ['Pcap files (*.pcap;*.pcapng;*.cap)']);
      }
    } catch (e) { path = ''; }
    if (path) {
      try {
        setPcapStatus('正在打开…', 'busy');
        const r = await fetch('/api/pcap/open', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path, max_packets: maxp })
        });
        const d = await r.json();
        if (!d.ok) throw new Error(d.error || '打开失败');
        await afterOpen(d);
        return;
      } catch (e) {
        setPcapStatus(e.message || String(e), 'err');
        toast(e.message || '打开失败');
        return;
      }
    }
    const input = $id('pcapFile');
    if (input) input.click();
  }

  async function uploadFile(file) {
    if (!file) return;
    const maxp = parseInt(($id('pcapMax') && $id('pcapMax').value) || '10000', 10) || 10000;
    const fd = new FormData();
    fd.append('file', file, file.name);
    fd.append('max_packets', String(maxp));
    try {
      setPcapStatus('正在打开 ' + file.name + '…', 'busy');
      const r = await fetch('/api/pcap/upload', { method: 'POST', body: fd });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || '打开失败');
      await afterOpen(d);
    } catch (e) {
      setPcapStatus(e.message || String(e), 'err');
      toast(e.message || '打开失败');
    }
  }

  async function afterOpen(d) {
    stopPoll();
    packets = [];
    firstTs = 0;
    selectedNo = 0;
    applyStatus(d);
    await pull(true);
    selectFirstVisible(true);
    scheduleDiagnose();
    toast('已载入 ' + (d.count || packets.length) + ' 个报文');
  }

  async function savePcap() {
    if (!packets.length) { toast('没有可保存的报文'); return; }
    let path = '';
    try {
      if (window.pywebview && window.pywebview.api && window.pywebview.api.pick_save) {
        path = await window.pywebview.api.pick_save('保存为 pcap', 'capture.pcap', ['Pcap (*.pcap)']);
      }
    } catch (e) { path = ''; }
    if (path) {
      try {
        const r = await fetch('/api/pcap/save', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path })
        });
        const d = await r.json();
        if (!d.ok) throw new Error(d.error || '保存失败');
        toast('已保存 ' + (d.count || '') + ' 个包');
        setPcapStatus('已保存到 ' + d.path, 'ok');
        return;
      } catch (e) {
        toast(e.message || '保存失败');
        return;
      }
    }
    // 回退为浏览器下载
    try {
      const r = await fetch('/api/pcap/download');
      if (!r.ok) throw new Error('下载失败');
      const blob = await r.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'capture.pcap';
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (e) {
      toast(e.message || '保存失败');
    }
  }

  function closeModal() {
    const m = $id('pcapModal');
    if (m) m.hidden = true;
  }

  function openModal(title, bodyHtml) {
    const m = $id('pcapModal');
    if (!m) return;
    $id('pcapModalTitle').textContent = title;
    $id('pcapModalBody').innerHTML = bodyHtml;
    m.hidden = false;
  }

  async function showStats() {
    try {
      const r = await fetch('/api/pcap/stats');
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || '统计失败');
      let html = '<h4>按协议</h4><table class="pcap-table"><thead><tr><th>协议</th><th>包数</th><th>字节</th></tr></thead><tbody>';
      (d.protocols || []).forEach(p => {
        html += '<tr><td>' + esc(p.protocol) + '</td><td>' + p.count + '</td><td>' + fmtBytes(p.bytes) + '</td></tr>';
      });
      html += '</tbody></table>';
      html += '<h4>会话 / 对端</h4><table class="pcap-table"><thead><tr><th>协议</th><th>端点 A</th><th>端点 B</th><th>包数</th><th>字节</th></tr></thead><tbody>';
      (d.conversations || []).slice(0, 200).forEach(c => {
        html += '<tr><td>' + esc(c.protocol) + '</td><td>' + esc(c.endpoint_a) + '</td><td>' + esc(c.endpoint_b) +
          '</td><td>' + c.packets + '</td><td>' + fmtBytes(c.bytes) + '</td></tr>';
      });
      html += '</tbody></table>';
      if (!(d.conversations || []).length) html += '<p class="pcap-empty">还没有会话</p>';
      openModal('统计', html);
    } catch (e) {
      toast(e.message || '统计失败');
    }
  }

  async function followStream() {
    if (!selectedNo) { toast('请先选择一条 TCP 报文'); return; }
    try {
      const r = await fetch('/api/pcap/follow/' + selectedNo);
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || '无法跟踪该流');
      let html = '<p class="pcap-meta">TCP　' + esc(d.endpoint_a) + '  ↔  ' + esc(d.endpoint_b) +
        '　' + d.packet_count + ' 个报文　' + fmtBytes(d.bytes) +
        (d.is_binary ? '　（含较多二进制，文本以点表示）' : '') + '</p>';
      html += '<pre class="pcap-follow">' + esc(d.is_binary ? (d.hex || d.text || '') : (d.text || d.hex || '')) + '</pre>';
      openModal('跟踪 TCP 流', html);
    } catch (e) {
      toast(e.message || '无法跟踪该流');
    }
  }

  function conclusionCards(list) {
    return '<ul class="pcap-diag-list pcap-concl-list">' + list.map(c =>
      '<li class="pcap-diag-item ' + esc(c.level || 'info') + '"><b>' + esc(c.title) +
      '</b><span class="pcap-concl-detail">' + esc(c.detail) + '</span>' +
      (c.evidence ? '<small class="pcap-concl-ev">依据：' + esc(c.evidence) + '</small>' : '') +
      '</li>').join('') + '</ul>';
  }

  function setHasPacket(on) {
    const root = $id('pcapAnalysis');
    if (root) root.classList.toggle('has-packet', !!on);
  }

  function selectFirstVisible(force) {
    const list = filtered.length ? filtered : packets;
    if (!list.length) {
      setHasPacket(false);
      return;
    }
    if (!force && selectedNo && list.some(p => p.no === selectedNo)) return;
    selectPacket(list[0].no);
  }

  function renderPacketAnalysis(ana) {
    const box = $id('pcapPktAnaBody');
    if (!box) return;
    const list = (ana && ana.conclusions) || [];
    if (list.length) {
      setHasPacket(true);
      box.innerHTML = conclusionCards(list);
      return;
    }
    if (ana && ana.summary) {
      setHasPacket(true);
      let html = '<p class="pcap-ana-summary">' + esc(ana.summary) + '</p>';
      if (ana.points && ana.points.length) {
        html += '<ul class="pcap-ana-points">' + ana.points.map(p => '<li>' + esc(p) + '</li>').join('') + '</ul>';
      }
      if (ana.hints && ana.hints.length) {
        html += '<ul class="pcap-ana-hints">' + ana.hints.map(h =>
          '<li class="' + esc(h.level || 'note') + '">' + esc(h.text) + '</li>').join('') + '</ul>';
      }
      box.innerHTML = html;
      return;
    }
    setHasPacket(false);
    box.innerHTML = '<div class="pcap-empty">没有分析结论</div>';
  }

  let diagTimer = null;
  function scheduleDiagnose() {
    if (diagTimer) clearTimeout(diagTimer);
    diagTimer = setTimeout(loadDiagnose, 280);
  }

  async function loadDiagnose() {
    const body = $id('pcapDiagBody');
    if (!body) return;
    if (!packets.length) {
      body.innerHTML = '<div class="pcap-empty">打开或抓取报文后，将在此给出整次抓包的结论</div>';
      return;
    }
    const q = ($id('pcapFilter') && $id('pcapFilter').value) || '';
    try {
      const r = await fetch('/api/pcap/diagnose?q=' + encodeURIComponent(q));
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || '诊断失败');
      const list = d.conclusions || [];
      if (!list.length) {
        body.innerHTML = '<div class="pcap-empty">暂无结论</div>';
        return;
      }
      body.innerHTML = '<ul class="pcap-diag-list">' + list.map(c =>
        '<li class="pcap-diag-item ' + esc(c.level || 'info') + '"><b>' + esc(c.title) +
        '</b><span class="pcap-concl-detail">' + esc(c.detail) + '</span>' +
        (c.evidence ? '<small class="pcap-concl-ev">依据：' + esc(c.evidence) + '</small>' : '') +
        '</li>').join('') + '</ul>';
    } catch (e) {
      body.innerHTML = '<div class="pcap-empty err">' + esc(e.message || e) + '</div>';
    }
  }

  async function deepAnalyze() {
    if (!packets.length) { toast('请先打开 pcap 或开始抓包'); return; }
    const q = ($id('pcapFilter') && $id('pcapFilter').value) || '';
    try {
      const cfgR = await fetch('/api/ai/config');
      const cfg = await cfgR.json();
      if (!cfg.configured) {
        if (typeof openAiSettings === 'function') openAiSettings();
        toast('请先在 AI 设置中配置接口后再做深度分析');
        return;
      }
    } catch (e) { /* 仍尝试请求，由接口返回引导 */ }
    openModal(
      '深度分析',
      '<p class="pcap-meta">将脱敏后的摘要、离线诊断和统计发给已配置的模型，不会发送完整原始报文。</p>' +
      '<pre class="pcap-follow" id="pcapAiText"></pre>'
    );
    const textEl = () => $id('pcapAiText');
    try {
      const resp = await fetch('/api/pcap/deep-analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ no: selectedNo || 0, filter: q })
      });
      const ct = (resp.headers.get('content-type') || '').toLowerCase();
      if (!resp.ok && ct.indexOf('json') >= 0) {
        const d = await resp.json();
        if (d.need_config && typeof openAiSettings === 'function') {
          closeModal();
          openAiSettings();
        }
        throw new Error(d.error || '无法开始深度分析');
      }
      if (!resp.ok || !resp.body) throw new Error('HTTP ' + resp.status);
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
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
          try { ev = JSON.parse(line.slice(6)); } catch (err) { continue; }
          if (ev.type === 'delta' && textEl()) textEl().textContent += ev.text;
          else if (ev.type === 'error') throw new Error(ev.message || '分析失败');
        }
      }
      if (textEl() && !textEl().textContent) textEl().textContent = '模型没有返回内容。';
    } catch (e) {
      if (textEl()) textEl().textContent += (textEl().textContent ? '\n\n' : '') + '错误：' + (e.message || e);
      else toast(e.message || '深度分析失败');
    }
  }

  function bindSplitters(root) {
    const list = $id('pcapListPane');
    const tree = $id('pcapTreePane');
    const bytes = $id('pcapBytesPane');
    function apply() {
      if (list) {
        list.style.flex = '0 0 auto';
        list.style.height = listHeight + 'px';
      }
      if (tree) {
        tree.style.flex = '0 0 auto';
        tree.style.height = treeHeight + 'px';
      }
      if (bytes) {
        bytes.style.flex = '0 0 auto';
        bytes.style.height = bytesHeight + 'px';
      }
    }
    apply();
    root.querySelectorAll('.pcap-split-h').forEach(h => {
      h.addEventListener('mousedown', ev => {
        ev.preventDefault();
        const target = h.dataset.split || '';
        const startY = ev.clientY;
        const startH = target === 'list' ? listHeight : (target === 'tree' ? treeHeight : bytesHeight);
        function move(e) {
          const next = Math.max(160, Math.min(900, startH + (e.clientY - startY)));
          if (target === 'list') listHeight = next;
          else if (target === 'tree') treeHeight = next;
          else bytesHeight = next;
          apply();
        }
        function up() {
          document.removeEventListener('mousemove', move);
          document.removeEventListener('mouseup', up);
        }
        document.addEventListener('mousemove', move);
        document.addEventListener('mouseup', up);
      });
    });
  }

  function mount(panel) {
    panel.innerHTML = `
      <div class="pcap-app">
        <div class="pcap-banner" id="pcapBanner" hidden></div>
        <div class="pcap-toolbar pcap-toolbar-main">
          <label>网卡 <select id="pcapIface"></select></label>
          <button type="button" class="btn ghost small" id="pcapRefreshIf">刷新</button>
          <span class="pcap-actions">
            <button type="button" class="btn primary small" id="pcapStart">开始抓包</button>
            <button type="button" class="btn ghost small" id="pcapStop" disabled>停止</button>
            <button type="button" class="btn ghost small" id="pcapClear">清空</button>
            <button type="button" class="btn ghost small" id="pcapOpen">打开 pcap</button>
            <button type="button" class="btn ghost small" id="pcapSave">保存 pcap</button>
          </span>
          <input type="file" id="pcapFile" hidden accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap">
        </div>
        <div class="pcap-toolbar pcap-toolbar-filters">
          <label>捕获过滤 <select id="pcapPreset"></select></label>
          <input id="pcapBpf" type="text" placeholder="自定义 BPF，例如 tcp port 443" spellcheck="false">
          <label>上限 <input id="pcapMax" type="number" min="100" max="200000" value="10000" title="内存中最多保留的报文数"></label>
          <label>到达上限
            <select id="pcapOnLimit">
              <option value="drop">丢弃最旧</option>
              <option value="stop">停止抓包</option>
            </select>
          </label>
          <span class="pcap-actions">
            <button type="button" class="btn ghost small" id="pcapFollow">跟踪 TCP 流</button>
            <button type="button" class="btn ghost small" id="pcapStats">统计</button>
            <button type="button" class="btn ghost small" id="pcapDeep">深度分析</button>
          </span>
        </div>
        <div class="pcap-filter-row">
          <label>显示过滤</label>
          <input id="pcapFilter" type="search" placeholder="协议、地址、端口或关键字，例如 tcp port 80、ip.addr==10.0.0.1、dns" spellcheck="false">
          <span id="pcapCount">0 包</span>
          <span class="pcap-status" id="pcapStatus">就绪（不会自动开始抓包）</span>
        </div>
        <div class="pcap-panes pcap-panes-long">
          <div class="pcap-pane pcap-list-pane" id="pcapListPane">
            <div class="pcap-list-head">
              <span class="c-no">序号</span><span class="c-time">时间</span><span class="c-src">源地址</span>
              <span class="c-dst">目的地址</span><span class="c-proto">协议</span><span class="c-len">长度</span>
              <span class="c-info">Info</span>
            </div>
            <div class="pcap-list-body" id="pcapListBody">
              <div id="pcapListSpacer"></div>
              <div id="pcapListRows" class="pcap-list-rows"></div>
            </div>
          </div>
          <div class="pcap-split pcap-split-h" data-split="list" title="拖动调整报文列表高度"></div>
            <div class="pcap-pane pcap-analysis-pane" id="pcapAnalysisPane">
              <div class="pcap-pane-label">报文分析</div>
              <div class="pcap-analysis" id="pcapAnalysis">
                <section class="pcap-pkt-ana" id="pcapPktAnaSection">
                  <h3>本包分析结论</h3>
                  <div id="pcapPktAnaBody"><div class="pcap-empty">打开或抓取报文后，将自动选中第一条并给出分析结论</div></div>
                </section>
                <section class="pcap-diag" id="pcapDiagSection">
                  <details class="pcap-diag-fold" id="pcapDiagFold">
                    <summary>整次抓包结论</summary>
                    <div id="pcapDiagBody"><div class="pcap-empty">打开或抓取报文后，将在此给出整次抓包的结论</div></div>
                  </details>
                </section>
              </div>
            </div>
            <div class="pcap-split pcap-split-h" data-split="tree" title="拖动调整报文详情高度"></div>
            <div class="pcap-pane pcap-tree-pane" id="pcapTreePane">
              <div class="pcap-pane-label">报文详情</div>
              <div class="pcap-tree" id="pcapTree"><div class="pcap-empty">选择一条报文，查看逐层字段</div></div>
            </div>
          <div class="pcap-split pcap-split-h" data-split="bytes" title="拖动调整报文字节高度"></div>
          <div class="pcap-pane pcap-bytes-pane" id="pcapBytesPane">
            <div class="pcap-pane-label">报文字节</div>
            <div class="pcap-bytes" id="pcapBytes"><div class="pcap-empty">选择一条报文以查看原始字节</div></div>
          </div>
        </div>
        <div class="pcap-modal" id="pcapModal" hidden>
          <div class="pcap-modal-box">
            <div class="pcap-modal-head"><b id="pcapModalTitle"></b><button type="button" class="modal-close" id="pcapModalClose">&times;</button></div>
            <div class="pcap-modal-body" id="pcapModalBody"></div>
          </div>
        </div>
      </div>
    `;
    const view = $id('toolView');
    if (view) view.classList.add('pcap-mode');
    const runBar = document.querySelector('#toolView .run-bar');
    if (runBar) {
      runBar.hidden = true;
      runBar.setAttribute('hidden', '');
    }
    ['runBtn', 'stopBtn', 'clearBtn', 'exportBtn', 'aiBtn', 'pkgBtn', 'cmpBtn'].forEach(id => {
      const b = $id(id); if (b) b.hidden = true;
    });

    $id('pcapStart').onclick = startCap;
    $id('pcapStop').onclick = stopCap;
    $id('pcapClear').onclick = clearCap;
    $id('pcapOpen').onclick = openPcap;
    $id('pcapSave').onclick = savePcap;
    $id('pcapFollow').onclick = followStream;
    $id('pcapStats').onclick = showStats;
    $id('pcapDeep').onclick = deepAnalyze;
    $id('pcapRefreshIf').onclick = () => loadCapability();
    $id('pcapPreset').onchange = () => {
      if (!$id('pcapBpf').value || $id('pcapBpf').dataset.fromPreset === '1') {
        $id('pcapBpf').value = $id('pcapPreset').value;
        $id('pcapBpf').dataset.fromPreset = '1';
      }
    };
    $id('pcapBpf').addEventListener('input', () => { $id('pcapBpf').dataset.fromPreset = '0'; });
    $id('pcapFilter').addEventListener('input', () => { renderList(); scheduleDiagnose(); selectFirstVisible(); });
    $id('pcapFile').addEventListener('change', ev => {
      const f = ev.target.files && ev.target.files[0];
      ev.target.value = '';
      uploadFile(f);
    });
    $id('pcapModalClose').onclick = closeModal;
    $id('pcapModal').addEventListener('click', ev => { if (ev.target.id === 'pcapModal') closeModal(); });

    const body = $id('pcapListBody');
    body.addEventListener('scroll', () => {
      listAtBottom = body.scrollTop + body.clientHeight >= body.scrollHeight - 24;
      renderList();
    });
    body.addEventListener('click', ev => {
      const row = ev.target.closest('.pcap-row');
      if (!row) return;
      selectPacket(Number(row.dataset.no));
    });
    body.addEventListener('keydown', ev => {
      if (ev.key !== 'ArrowDown' && ev.key !== 'ArrowUp') return;
      ev.preventDefault();
      const idx = filtered.findIndex(p => p.no === selectedNo);
      const next = ev.key === 'ArrowDown' ? idx + 1 : idx - 1;
      if (next >= 0 && next < filtered.length) {
        selectPacket(filtered[next].no);
        const y = next * ROW_H;
        if (y < body.scrollTop) body.scrollTop = y;
        if (y + ROW_H > body.scrollTop + body.clientHeight) body.scrollTop = y - body.clientHeight + ROW_H * 2;
      }
    });
    body.tabIndex = 0;
    $id('pcapBytes').addEventListener('click', ev => {
      const b = ev.target.closest('[data-off]');
      if (!b || !currentDetail) return;
      const off = Number(b.dataset.off);
      const hit = findNodeAt(currentDetail.layers || [], off);
      if (hit) {
        highlight = { offset: hit.offset || 0, length: hit.length || 1 };
        renderBytes();
        // 尝试点亮树上对应行
        const tree = $id('pcapTree');
        if (tree) {
          tree.querySelectorAll('.pcap-trow').forEach(row => {
            const match = Number(row.dataset.off) === (hit.offset || 0) && Number(row.dataset.len) === (hit.length || 0);
            row.classList.toggle('active', match);
            if (match) {
              let p = row.parentElement;
              while (p && p !== tree) {
                if (p.classList.contains('pcap-tkids')) p.hidden = false;
                p = p.parentElement;
              }
              row.scrollIntoView({ block: 'nearest' });
            }
          });
        }
      }
    });

    bindSplitters(panel);
    loadCapability().then(() => {
      pull(true).then(d => {
        if (d && d.running) startPoll();
        selectFirstVisible();
        scheduleDiagnose();
      }).catch(() => {});
    });
  }

  function findNodeAt(nodes, off, best) {
    (nodes || []).forEach(n => {
      const a = n.offset || 0, l = n.length || 0;
      if (l > 0 && off >= a && off < a + l) {
        if (!best || l < best.length) best = n;
      }
      if (n.children) best = findNodeAt(n.children, off, best);
    });
    return best;
  }

  function unmount() {
    stopPoll();
    if (diagTimer) { clearTimeout(diagTimer); diagTimer = null; }
    const view = $id('toolView');
    if (view) view.classList.remove('pcap-mode');
    const runBar = document.querySelector('#toolView .run-bar');
    if (runBar) runBar.hidden = false;
  }

  PANELS.pcap = mount;

  const prevRun = PANELS.run;
  const prevStop = PANELS.stop;
  const prevLeave = PANELS._leave;
  PANELS.run = function (id) {
    if (id === 'pcap') return startCap();
    if (typeof prevRun === 'function') return prevRun(id);
  };
  PANELS.stop = function (id) {
    if (id === 'pcap') return stopCap();
    if (typeof prevStop === 'function') return prevStop(id);
  };
  PANELS._leave = function (id) {
    if (id === 'pcap') unmount();
    if (typeof prevLeave === 'function') prevLeave(id);
  };
})();
