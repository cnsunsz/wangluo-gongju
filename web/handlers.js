/* 各工具的事件渲染 */

function handleEvent(d) {
  const tool = state.tool;
  if (!tool) return;
  if (d.type === 'error') {
    appendLog(d.message || '发生错误', 'err');
    return;
  }
  const fn = EVENT_HANDLERS[tool.id];
  if (fn) fn(d);
}

function handleResult(data) {
  const tool = state.tool;
  if (!tool) return;
  const fn = RESULT_HANDLERS[tool.id] || RESULT_HANDLERS._default;
  fn(data);
}

const MTR_HEAD = ['跳', '地址', '丢包', '最小 ms', '平均 ms', '最大 ms', '最近 ms'];

function renderMtrTable(round) {
  const hops = Object.keys(state.mtr).map(Number).sort((a, b) => a - b);
  const rows = hops.map(h => {
    const a = state.mtr[h];
    const n = a.rtts.length;
    const min = n ? Math.min(...a.rtts) : '—';
    const max = n ? Math.max(...a.rtts) : '—';
    const avg = n ? Math.round((a.rtts.reduce((x, y) => x + y, 0) / n) * 10) / 10 : '—';
    return [h, a.ip || '*', n ? '—' : '无响应', min, avg, max, n ? a.rtts[n - 1] : '—'];
  });
  showTable(MTR_HEAD, rows);
  setMetrics([{ k: '采样轮次', v: round }, { k: '发现跳数', v: rows.length }]);
}

const EVENT_HANDLERS = {
  ping: pingEvent,
  pingpp: pingEvent,

  traceroute(d) {
    if (d.type === 'start') {
      appendLog(`traceroute ${d.host}，最多 ${d.maxhops} 跳，每跳超时 ${d.timeout} ms`, 'head');
      setStatus('追踪中…', 'busy');
    } else if (d.type === 'hop') {
      const rtt = d.rtts.length ? d.rtts.map(x => x + ' ms').join('  ') : '* * *';
      appendLog(`${String(d.hop).padStart(2, ' ')}  ${rtt.padEnd(26, ' ')} ${d.ip || ''}`, d.ip ? '' : 'muted');
      setStatus(`追踪中 · 第 ${d.hop} 跳`, 'busy');
    } else if (d.type === 'log') {
      appendLog(d.text, 'muted');
    } else if (d.type === 'done') {
      appendLog(`追踪结束，共 ${d.hops} 跳`, 'info');
    }
  },

  mtr(d) {
    if (d.type === 'start') {
      state.mtr = {};
      appendLog(`MTR ${d.host}：${d.samples} 轮 tracert 采样，最大 ${d.maxhops} 跳`, 'head');
      appendLog('逐跳表格随探测实时刷新，可随时停止。', 'muted');
      setStatus('采样中…', 'busy');
    } else if (d.type === 'probe') {
      const a = state.mtr[d.hop] || (state.mtr[d.hop] = { rtts: [], ip: null });
      if (d.ip) a.ip = d.ip;
      a.rtts.push(...d.rtts);
      renderMtrTable(d.round);
      setStatus(`第 ${d.round} 轮 · 第 ${d.hop} 跳`, 'busy');
    } else if (d.type === 'round') {
      const rows = d.hops.map(h => [h.hop, h.ip || '*', h.loss + '%', h.min, h.avg, h.max, h.last]);
      showTable(MTR_HEAD, rows);
      setMetrics([{ k: '采样轮次', v: d.round }, { k: '发现跳数', v: d.hops.length }]);
    } else if (d.type === 'done') {
      appendLog(`采样完成，共 ${d.rounds} 轮`, 'info');
    }
  },

  download(d) {
    if (d.type === 'start') {
      appendLog(`开始下载：${d.url}`, 'head');
      appendLog(`时长 ${d.seconds}s，上限 ${d.max_mb} MB`, 'muted');
      setStatus('连接中…', 'busy');
    } else if (d.type === 'resp') {
      appendLog(`HTTP ${d.status}${d.total ? '，文件大小 ' + fmtBytes(d.total) : ''}`, 'info');
      setStatus('下载中…', 'busy');
    } else if (d.type === 'progress') {
      setMetrics([
        { k: '当前速率', v: d.cur_mbps, u: 'Mbps' },
        { k: '平均速率', v: d.avg_mbps, u: 'Mbps' },
        { k: '已下载', v: fmtBytes(d.downloaded) },
        { k: '已用时', v: d.elapsed, u: 's' }
      ]);
      setStatus(`下载中 · ${d.avg_mbps} Mbps`, 'busy');
      if (++state.dlTick % 10 === 0) {
        appendLog(`${d.elapsed}s  ${fmtBytes(d.downloaded)}  ${d.cur_mbps} Mbps`, '');
      }
    } else if (d.type === 'done') {
      setMetrics([
        { k: '平均速率', v: d.avg_mbps, u: 'Mbps' },
        { k: '下载量', v: fmtBytes(d.downloaded) },
        { k: '用时', v: d.elapsed, u: 's' }
      ]);
      appendLog(`下载完成：${fmtBytes(d.downloaded)} / ${d.elapsed}s，平均 ${d.avg_mbps} Mbps`, 'ok');
    }
  },

  speed(d) {
    const name = { latency: '延时', download: '下行', upload: '上行' };
    if (d.type === 'stage' && d.status === 'start') {
      appendLog(`— ${name[d.stage] || d.stage} —`, 'head');
      setStatus(`${name[d.stage]}测试中…`, 'busy');
    } else if (d.type === 'latency') {
      state.sp.lat = d;
      appendLog(d.avg == null ? '延时：全部超时' : `延时 ${d.avg} ms，抖动 ${d.jitter} ms，丢包 ${d.loss}%`,
        d.avg == null ? 'err' : 'info');
      refreshSpeedMetrics();
    } else if (d.type === 'result') {
      state.sp[d.stage] = d.mbps;
      appendLog(`${name[d.stage]}：${d.mbps} Mbps`, 'ok');
      refreshSpeedMetrics();
    } else if (d.type === 'stage_error') {
      appendLog(d.message, 'err');
    } else if (d.type === 'done') {
      appendLog(`测速结束：下行 ${d.download_mbps ?? '—'} Mbps，上行 ${d.upload_mbps ?? '—'} Mbps`, 'info');
    }
  }
};

function refreshSpeedMetrics() {
  const sp = state.sp;
  setMetrics([
    { k: '延时', v: sp.lat && sp.lat.avg != null ? sp.lat.avg : '—', u: 'ms' },
    { k: '抖动', v: sp.lat ? sp.lat.jitter : '—', u: 'ms' },
    { k: '下行', v: sp.download ?? '—', u: 'Mbps' },
    { k: '上行', v: sp.upload ?? '—', u: 'Mbps' }
  ]);
}

function pingEvent(d) {
  if (d.type === 'start') {
    appendLog(`PING ${d.host}（${d.family === 6 ? 'IPv6' : 'IPv4'}）包大小 ${d.size} 字节`, 'head');
  } else if (d.type === 'reply') {
    if (d.ok) {
      appendLog(`#${d.seq} 来自 ${d.ip || '?'}：时间=${d.rtt} ms  TTL=${d.ttl ?? '-'}`, 'ok');
    } else {
      appendLog(`#${d.seq} 超时或不可达  ${d.msg || ''}`, 'err');
    }
  } else if (d.type === 'stats') {
    setMetrics([
      { k: '已发送', v: d.sent }, { k: '已接收', v: d.recv },
      { k: '丢包率', v: d.loss, u: '%' }, { k: '最小', v: d.min, u: 'ms' },
      { k: '平均', v: d.avg, u: 'ms' }, { k: '最大', v: d.max, u: 'ms' },
      { k: '抖动', v: d.jitter, u: 'ms' }
    ]);
    setStatus(`运行中 · 丢包 ${d.loss}% · 平均 ${d.avg} ms`, 'busy');
  } else if (d.type === 'done') {
    appendLog(`完成：发送 ${d.sent}，接收 ${d.recv}，丢包 ${d.loss}%，平均 ${d.avg} ms`, 'info');
  }
}

const RESULT_HANDLERS = {
  _default(data) {
    appendLog(JSON.stringify(data, null, 2), '');
  },

  portscan(data) {
    const rows = data.open.map(p => [p.port, p.service || '-', p.banner || '-']);
    showTable(['端口', '服务', 'Banner'], rows);
    setMetrics([
      { k: '目标 IP', v: data.ip },
      { k: '扫描端口', v: data.scanned },
      { k: '开放端口', v: data.open.length },
      { k: '耗时', v: data.duration, u: 's' }
    ]);
    appendLog(`扫描完成：${data.scanned} 个 TCP 端口，开放 ${data.open.length} 个`, data.open.length ? 'ok' : 'warn');
    appendLog(data.note, 'muted');
  },

  fetch(data) {
    renderResponse(data);
  },

  httpadv(data) {
    renderResponse(data);
  },

  probe(data) {
    const hops = data.redirects || [];
    setMetrics([
      { k: '状态', v: data.status },
      { k: '解析 IP', v: data.ip },
      { k: '总耗时', v: data.metrics.total, u: 'ms' },
      { k: '跳转', v: Math.max(hops.length - 1, 0), u: '次' },
      { k: '证书剩余', v: data.cert ? data.cert.days_left : '—', u: '天' }
    ]);
    appendLog(`${data.status}  ${data.server || ''}  ${data.content_type || ''}`, 'ok');
    appendLog(`地址 ${data.url}  →  ${data.ip}`, 'muted');
    Object.entries(data.headers || {}).forEach(([k, v]) => appendLog(`${k}: ${v}`, 'info'));

    if (hops.length > 1) {
      showTable(['#', 'URL', '状态', '跳转目标', '耗时'], hops.map((h, i) => [
        i + 1, h.url, h.status, h.location || '—', h.ms + ' ms'
      ]));
      appendLog(`跳转链 ${hops.length - 1} 次，最终地址：${data.final_url}`, 'warn');
    } else {
      appendLog('无 301/302 跳转', 'muted');
    }

    if (data.cert) {
      appendLog(`TLS ${data.cert.tls_version} · ${data.cert.cipher}`, 'head');
      appendLog(`颁发者：${data.cert.issuer}`, '');
      appendLog(`主体：${data.cert.subject}`, '');
      appendLog(`有效期：${data.cert.not_before} → ${data.cert.not_after}`, '');
      if (data.cert.days_left != null) {
        appendLog(`剩余 ${data.cert.days_left} 天${data.cert.days_left < 30 ? '，注意续期' : ''}`,
          data.cert.days_left < 30 ? 'warn' : 'ok');
      }
    } else {
      appendLog('未使用 TLS（HTTP）', 'muted');
    }
    (data.cert_chain || []).forEach((c, i) => {
      appendLog(`证书链 ${i + 1}：${c.subject} ← ${c.issuer}  至 ${c.not_after}（剩 ${c.days_left} 天）`,
        c.days_left < 30 ? 'warn' : '');
    });
    if ((data.tls_versions || []).length) {
      const vers = data.tls_versions.join(' / ');
      appendLog(`支持协议：${vers}`, data.tls_versions.includes('TLS 1.3') ? 'ok' : 'warn');
    }
  },

  timing(data) {
    const m = data.metrics;
    setMetrics([
      { k: 'DNS', v: m.dns, u: 'ms' }, { k: 'TCP', v: m.tcp, u: 'ms' },
      { k: 'TLS', v: m.tls == null ? '—' : m.tls, u: 'ms' },
      { k: '首字节', v: m.ttfb, u: 'ms' }, { k: '总耗时', v: m.total, u: 'ms' }
    ]);
    appendLog(`HTTP ${data.status}  ${data.server || ''}  ${fmtBytes(data.size)}${data.truncated ? '（超过 2MB，仅计时到此处）' : ''}`, 'ok');
    appendLog(`DNS ${m.dns} ms → TCP ${m.tcp} ms → TLS ${m.tls ?? '-'} ms → 首字节 ${m.ttfb} ms → 总计 ${m.total} ms`, 'info');
    appendLog(`地址 ${data.url}  →  ${data.ip}`, 'muted');
    const parts = [['dns', 'DNS 解析'], ['tcp', 'TCP 连接'], ['tls', 'TLS 握手'], ['ttfb', '等待首字节']]
      .filter(([k]) => m[k] != null);
    if (parts.length) {
      const slow = parts.reduce((a, b) => (m[a[0]] >= m[b[0]] ? a : b));
      appendLog(`耗时占比最大：${slow[1]}（${m[slow[0]]} ms）`, 'warn');
    }
  },

  dns(data) {
    const rows = [];
    Object.entries(data.records || {}).forEach(([type, list]) => {
      list.forEach(v => rows.push([type, v]));
    });
    if (rows.length) showTable(['类型', '记录'], rows);
    const count = rows.length;
    setMetrics([
      { k: '查询对象', v: data.name },
      { k: 'DNS', v: data.server },
      { k: '记录数', v: count }
    ]);
    if (count) appendLog(`解析成功，共 ${count} 条记录`, 'ok');
    Object.entries(data.errors || {}).forEach(([t, msg]) => appendLog(`${t}: ${msg}`, 'warn'));
  },

  dnsip(data) {
    RESULT_HANDLERS.dns(data);
  },

  iplocal(d) {
    const locals = d.local || [];
    const dns = (d.dns || []).join(', ');
    showTable(['项目', '内容'], [
      ['网络信息', d.ssid ? 'WiFi · ' + d.ssid : (d.adapter || '未知网卡')],
      ['地址信息', d.address || '获取失败'],
      ['DNS IP', dns || '—'],
      ['IPv4信息', d.public_v4 || '获取失败'],
      ['IPv4来源', d.public_v4_source || '—'],
      ['IPv6信息', d.public_v6 || '不支持 IPv6 或超时'],
      ['IPv6来源', d.public_v6_source || '—'],
      ['归属地来源', (d.geo && d.geo.source) || '—'],
      ['网关信息', d.gateway || '无网关'],
      ['内网信息', d.local_ipv4 || '—'],
      ['信息详情', [d.mac, d.speed, d.desc].filter(Boolean).join(' · ') || '—']
    ]);
    setMetrics([
      { k: '公网 IPv4', v: d.public_v4 || '—' },
      { k: '内网 IP', v: d.local_ipv4 || '—' },
      { k: '地址', v: d.address || '—' },
      { k: '网关', v: d.gateway || '—' }
    ]);
    appendLog(`${d.adapter || '网卡'} · ${d.local_ipv4 || '—'}`, 'ok');
    if (d.public_v4) appendLog(`公网 IPv4：${d.public_v4}${d.address ? '（' + d.address + '）' : ''}`, '');
    appendLog(d.public_v6 ? `公网 IPv6：${d.public_v6}` : '公网 IPv6：不支持或超时',
      d.public_v6 ? '' : 'warn');
    appendLog(`来源说明：公网 IPv4 取自 ${d.public_v4_source || '—'}，IPv6 取自 ${d.public_v6_source || '—'}；归属地取自 ${(d.geo && d.geo.source) || '—'}（主用 ip-api.com、备用 ipinfo.io），仅代表 IP 登记地，非实时位置，仅供参考。`, 'muted');
    appendLog(`网关：${d.gateway || '无'}    DNS：${dns || '—'}`, 'muted');
    if (d.mac) appendLog(`MAC：${d.mac}   速率：${d.speed || '—'}`, 'muted');
    if (d.info_error) appendLog('网络信息获取异常：' + d.info_error, 'err');
    if (locals.length > 1) appendLog(`共发现 ${locals.length} 个网卡地址，多网卡明细可在「网络诊断」查看。`, 'muted');
  },

  iploc(data) {
    const backupSrc = data.source === 'ipinfo.io';
    const srcLabel = (data.source || '第三方接口') + (backupSrc ? '（备用源）' : '（主用源）');
    setMetrics([
      { k: '国家', v: data.country }, { k: '省/州', v: data.region },
      { k: '城市', v: data.city }, { k: '运营商', v: data.isp },
      { k: '数据来源', v: data.source || '—', u: backupSrc ? ' 备用' : ' 主用' }
    ]);
    showTable(['项目', '内容'], [
      ['IP来源', data.is_self ? '本机公网出口（未指定 IP）' : '手动指定'],
      ['查询 IP', data.ip || '—'],
      ['国家/地区', `${data.country || '—'}${data.country_code ? ' (' + data.country_code + ')' : ''}`],
      ['省/州', data.region || '—'],
      ['城市', data.city || '—'],
      ['运营商', data.isp || '—'],
      ['机构', data.org || '—'],
      ['ASN', data.as || '—'],
      ['经纬度', `${data.lat == null ? '—' : data.lat}, ${data.lon == null ? '—' : data.lon}`],
      ['时区', data.timezone || '—'],
      ['数据来源', srcLabel]
    ]);
    appendLog(`查询对象：${data.ip}（${data.is_self ? '取自本机公网出口' : '手动输入'}）`, 'ok');
    appendLog(`数据来源：${data.source || '第三方接口'}；主用 ip-api.com，失败自动切换 ipinfo.io。归属地仅代表 IP 登记地，非实时位置，企业专线/VPN 常显示运营商出口位置。`, 'muted');
    if (backupSrc) appendLog('主源 ip-api.com 不可用，本次结果来自备用源 ipinfo.io', 'warn');
  },

  ipcalc(d) {
    setMetrics([
      { k: '网段', v: `${d.network}/${d.prefix}` },
      { k: '掩码', v: d.netmask },
      { k: '广播', v: d.broadcast || '—' },
      { k: '可用主机', v: d.usable }
    ]);
    showTable(['项目', '值'], [
      ['IP', d.ip], ['网段', `${d.network}/${d.prefix}`], ['掩码', d.netmask],
      ['反掩码', d.wildcard], ['广播', d.broadcast || '—'], ['首地址', d.first],
      ['末地址', d.last], ['总地址数', d.total], ['可用主机', d.usable],
      ['地址类别', d.class || '—'], ['私有地址', d.private ? '是' : '否'],
      ['二进制 IP', d.binary_ip || '—'], ['二进制掩码', d.binary_mask || '—']
    ]);
    appendLog(`${d.ip}/${d.prefix} → 网段 ${d.network}，可用 ${d.usable} 个地址`, 'ok');
  },

  ts(d) {
    setMetrics([
      { k: '时间戳(s)', v: d.timestamp_s },
      { k: 'UTC', v: d.utc },
      { k: '本地 ' + d.offset, v: d.local }
    ]);
    showTable(['项目', '值'], [
      ['时间戳(秒)', d.timestamp_s], ['时间戳(毫秒)', d.timestamp_ms],
      ['UTC', d.utc], [`本地 ${d.offset}`, d.local], ['ISO 8601', d.iso],
      ['星期', '星期' + d.weekday], ['ISO 周', d.week], ['年内第几天', d.day_of_year],
      ['数据来源', d.source]
    ]);
    appendLog(`${d.source} → ${d.timestamp_s} / ${d.local} ${d.offset}`, 'ok');
  },

  codec(d) {
    setMetrics([{ k: '操作', v: d.op }, { k: '结果长度', v: d.length }]);
    const raw = $('raw');
    raw.hidden = false;
    raw.textContent = d.result;
    appendLog(`${d.op} 完成，长度 ${d.length}`, 'ok');
    appendLog('结果在下方文本框，可直接选中复制。', 'muted');
  },

  qr(d) {
    const box = $('imgBox');
    box.hidden = false;
    box.innerHTML = '';
    const img = document.createElement('img');
    img.src = d.data_url;
    img.alt = '二维码';
    box.appendChild(img);
    appendLog(`二维码已生成（${d.size}px）`, 'ok');
  },

  cndns(d) {
    showTable(['DNS', '节点', '耗时', '结果'], d.results.map(r => [
      r.label || r.server, r.server, r.ms + ' ms', r.ok ? r.answers.join('\n') : r.error
    ]));
    const ok = d.results.filter(r => r.ok).length;
    const metrics = [
      { k: '域名', v: d.name }, { k: '类型', v: d.type },
      { k: '响应', v: `${ok}/${d.results.length}` },
      { k: '最快', v: d.fastest == null ? '—' : d.fastest, u: 'ms' }
    ];
    if (d.provider) metrics.unshift({ k: '分组', v: d.provider });
    setMetrics(metrics);
    appendLog(d.consistent ? '所有 DNS 返回结果一致' : `结果存在差异（${d.groups} 组）`, d.consistent ? 'ok' : 'warn');
    if (!d.consistent) appendLog('差异可能来自 DNS 污染、CDN 就近调度或节点缓存，建议结合解析 IP 归属判断。', 'info');
  }
};

function normUrl(u) {
  return String(u || '').replace(/\/+$/, '').toLowerCase();
}

function renderResponse(data) {
  setMetrics([
    { k: '状态', v: data.status },
    { k: '耗时', v: data.elapsed_ms, u: 'ms' },
    { k: '大小', v: fmtBytes(data.downloaded) },
    { k: '跳转后', v: normUrl(data.final_url) === normUrl(data.url) ? '否' : '是' }
  ]);
  appendLog(`HTTP ${data.status} ${data.reason || ''}  ${data.elapsed_ms} ms`, 'ok');
  appendLog(`最终地址：${data.final_url}`, 'muted');
  Object.entries(data.headers || {}).forEach(([k, v]) => appendLog(`${k}: ${v}`, 'info'));
  const body = data.body || '';
  appendLog('', '');
  appendLog(body.length > 12000 ? body.slice(0, 12000) + '\n…（内容已截断）' : body, '');
  if (data.truncated) appendLog('注意：仅读取了前 256 KB 内容', 'warn');
}
