/* 第三批工具的事件与结果渲染 */
Object.assign(EVENT_HANDLERS, {
  tcping(d) {
    if (d.type === 'start') {
      appendLog(`TCPing ${d.host}:${d.port}`, 'head');
    } else if (d.type === 'reply') {
      if (d.ok) {
        appendLog(`#${d.seq} 连接成功 ${d.ms} ms`, 'ok');
      } else {
        appendLog(`#${d.seq} 连接失败 ${d.error || ''}`, 'err');
      }
    } else if (d.type === 'stats') {
      setMetrics([
        { k: '已发送', v: d.sent }, { k: '已接收', v: d.recv },
        { k: '失败率', v: d.loss, u: '%' }, { k: '最小', v: d.min, u: 'ms' },
        { k: '平均', v: d.avg, u: 'ms' }, { k: '最大', v: d.max, u: 'ms' },
        { k: '抖动', v: d.jitter, u: 'ms' }
      ]);
      setStatus(`运行中 · 失败 ${d.loss}% · 平均 ${d.avg} ms`, 'busy');
    } else if (d.type === 'done') {
      appendLog(`完成：${d.recv}/${d.sent} 次成功，平均 ${d.avg} ms`, 'info');
    }
  },

  superping(d) {
    if (d.type === 'start') {
      appendLog(`超级Ping：${d.hosts.join('、')}`, 'head');
      setStatus('探测中…', 'busy');
    } else if (d.type === 'reply') {
      setStatus(`第 ${d.seq} 轮 · ${d.host} ${d.ok ? d.rtt + ' ms' : '超时'}`, 'busy');
    } else if (d.type === 'stats') {
      showTable(['主机', 'IP', '发送', '接收', '丢包', '最小 ms', '平均 ms', '最大 ms'],
        d.rows.map(r => [r.host, r.ip || '—', r.sent, r.recv, r.loss + '%', r.min, r.avg, r.max]));
      setMetrics([{ k: '轮次', v: d.seq }, { k: '主机数', v: d.rows.length }]);
    } else if (d.type === 'done') {
      appendLog(`探测完成，共 ${d.rounds} 轮`, 'info');
    }
  },

  iperf3(d) {
    if (d.type === 'start') {
      appendLog(`iperf3 → ${d.host}:${d.port}，${d.seconds}s`, 'head');
      if (d.exe) appendLog('使用 ' + d.exe, 'muted');
      else appendLog('未检测到 iperf3.exe，见下方提示。', 'warn');
      setStatus('运行中…', 'busy');
    } else if (d.type === 'cmd') {
      appendLog('> ' + d.text, 'muted');
    } else if (d.type === 'log') {
      appendLog(d.text, '');
    } else if (d.type === 'done') {
      appendLog(`iperf3 结束，退出码 ${d.code}`, d.code === 0 ? 'ok' : 'warn');
    }
  }
});

Object.assign(RESULT_HANDLERS, {
  telnet(d) {
    setMetrics([
      { k: '结果', v: d.reachable ? '连接成功' : '连接失败' },
      { k: '耗时', v: d.ms, u: 'ms' },
      { k: '端口', v: d.port }
    ]);
    if (!d.reachable) {
      appendLog(`${d.host}:${d.port} 连接失败：${d.error}`, 'err');
      return;
    }
    appendLog(`${d.host}:${d.port} 可连接（${d.ms} ms）`, 'ok');
    if (d.banner) {
      const raw = $('raw');
      raw.hidden = false;
      raw.textContent = d.banner;
      appendLog('已收到 Banner，内容在下方。', 'info');
    } else {
      appendLog('未收到 Banner（服务端连上后没有主动发送数据）。', 'muted');
    }
  },

  ipscan(d) {
    setMetrics([
      { k: '网段', v: d.cidr }, { k: '扫描地址', v: d.scanned },
      { k: '存活', v: d.alive.length }, { k: '耗时', v: d.duration, u: 's' }
    ]);
    showTable(['IP', '延时 ms'], d.alive.map(x => [x.ip, x.rtt]));
    appendLog(`扫描 ${d.scanned} 个地址，存活 ${d.alive.length} 个`, d.alive.length ? 'ok' : 'warn');
  },

  lanscan(d) {
    setMetrics([
      { k: '网段', v: d.cidr }, { k: '本机', v: d.local_ip || '—' },
      { k: '网关', v: d.gateway || '—' }, { k: '设备', v: d.devices.length }
    ]);
    showTable(['IP', 'MAC', '延时 ms'],
      d.devices.map(x => [x.ip, x.mac || '—', x.rtt == null ? '—' : x.rtt]));
    appendLog(`发现 ${d.devices.length} 台设备，耗时 ${d.duration}s`, d.devices.length ? 'ok' : 'warn');
    appendLog('仅列响应 Ping 或 ARP 真实表项；代理 ARP / 组播 MAC 已过滤。', 'muted');
  },

  whois(d) {
    const raw = $('raw');
    raw.hidden = false;
    raw.textContent = d.text;
    setMetrics([
      { k: '域名', v: d.domain }, { k: 'WHOIS 服务器', v: d.server },
      { k: '字符数', v: d.text.length }
    ]);
    appendLog(`WHOIS ${d.domain} ← ${d.server}`, 'ok');
    appendLog('完整文本在下方，可直接选中复制。', 'muted');
  },

  sitecompare(d) {
    const statusOnly = d.mode === 'status';
    const dash = v => (v == null || v === '' ? '—' : v);
    if (statusOnly) {
      showTable(['URL', '状态', '耗时 ms', '服务器'],
        d.rows.map(r => r.ok
          ? [r.url, r.status, r.total, r.server || '—']
          : [r.url, '失败', '—', '—']));
    } else {
      showTable(['URL', '状态', 'IP', '总计 ms', 'DNS', 'TCP', 'TLS', '首字节'],
        d.rows.map(r => r.ok
          ? [r.url, r.status, r.ip, r.total, r.dns, r.tcp, dash(r.tls), r.ttfb]
          : [r.url, '失败', '—', '—', '—', '—', '—', '—']));
    }
    setMetrics([
      { k: '站点数', v: d.count },
      { k: '最快', v: d.fastest == null ? '—' : d.fastest, u: 'ms' },
      { k: '模式', v: statusOnly ? '只查状态' : '完整分段' }
    ]);
    d.rows.filter(r => !r.ok).forEach(r => appendLog(`${r.url} 失败：${r.error}`, 'err'));
    const codes = {};
    d.rows.filter(r => r.ok).forEach(r => { codes[r.status] = (codes[r.status] || 0) + 1; });
    if (Object.keys(codes).length) {
      appendLog('状态分布：' + Object.entries(codes).map(([k, v]) => `${k}×${v}`).join('，'),
        Object.keys(codes).every(k => String(k).startsWith('2')) ? 'ok' : 'warn');
    }
    appendLog(`对比完成，最快 ${d.fastest == null ? '—' : d.fastest + ' ms'}`, 'ok');
  },

  wlan(d) {
    if (!d.available) {
      setMetrics([{ k: '无线网卡', v: '未检测到' }]);
      appendLog(d.message || '未检测到无线网卡', 'warn');
      return;
    }
    const rows = d.rows || [];
    if (!rows.length) {
      setMetrics([{ k: '无线网卡', v: '已检测到' }, { k: '周边热点', v: 0 }]);
      appendLog('未扫描到周边热点，可能在信号极弱或扫描被系统禁用', 'warn');
      return;
    }
    showTable(['SSID', 'BSSID', '信号', '信道', '频段', '加密', '无线类型'],
      rows.map(r => [
        r.ssid || '（隐藏）', r.bssid, r.signal + '%', r.channel || '—',
        r.band || '—', r.enc || '—', r.radio || '—'
      ]));
    const n24 = rows.filter(r => r.band === '2.4G').length;
    const n5 = rows.filter(r => r.band === '5G').length;
    setMetrics([
      { k: '热点', v: rows.length }, { k: '2.4G', v: n24 }, { k: '5G', v: n5 },
      { k: '最强', v: rows[0].signal, u: '%' }
    ]);
    if (d.ssid) appendLog(`当前连接：${d.ssid}`, 'ok');
    appendLog(`扫描到 ${rows.length} 个 BSSID（2.4G ${n24} / 5G ${n5}），最强 ${rows[0].ssid || '隐藏'} ${rows[0].signal}%`, 'ok');
    const chCount = {};
    rows.forEach(r => { if (r.channel) chCount[r.channel] = (chCount[r.channel] || 0) + 1; });
    const busy = Object.entries(chCount).sort((a, b) => b[1] - a[1])[0];
    if (busy && busy[1] >= 4) {
      appendLog(`信道 ${busy[0]} 上有 ${busy[1]} 个热点，干扰较大，建议换到空闲信道`, 'warn');
    }
  },

  dig(d) {
    const rows = [];
    [['answer', 'ANSWER'], ['authority', 'AUTHORITY'], ['additional', 'ADDITIONAL']].forEach(([key, label]) => {
      (d[key] || []).forEach(r => rows.push([label, r.name, r.ttl, r.type, r.data]));
    });
    if (rows.length) showTable(['区段', '名称', 'TTL', '类型', '数据'], rows);
    setMetrics([
      { k: '状态', v: d.status }, { k: '耗时', v: d.ms, u: 'ms' },
      { k: '记录', v: rows.length }, { k: '标志', v: d.flags.join(' ') }
    ]);
    appendLog(`;; ${d.name} ${d.type} @ ${d.server} → ${d.status} (${d.ms} ms)`,
      d.status === 'NOERROR' ? 'ok' : 'warn');
    if (d.error) appendLog(d.error, 'err');
  },

  jsonfmt(d) {
    const raw = $('raw');
    raw.hidden = false;
    raw.textContent = d.result;
    setMetrics([
      { k: '模式', v: d.mode }, { k: '根类型', v: d.type }, { k: '长度', v: d.length }
    ]);
    appendLog(`JSON ${d.mode}完成，输出 ${d.length} 字符`, 'ok');
  },

  baseconv(d) {
    setMetrics([
      { k: '结果', v: d.result }, { k: '十进制', v: d.dec }, { k: '十六进制', v: d.hex }
    ]);
    showTable(['进制', '值'], [
      ['2 进制', d.bin], ['8 进制', d.oct], ['10 进制', d.dec], ['16 进制', d.hex],
      [`${d.from} → ${d.to}`, d.result]
    ]);
    appendLog(`${d.value}（${d.from} 进制）→ ${d.result}（${d.to} 进制）`, 'ok');
  },

  wol(d) {
    setMetrics([
      { k: 'MAC', v: d.mac }, { k: '广播', v: d.broadcast }, { k: '端口', v: d.port }
    ]);
    appendLog(`已发送魔术包 ${d.bytes} 字节 → ${d.broadcast}:${d.port}`, 'ok');
    appendLog('目标机需在同一广播域，且网卡/主板已开启 Wake-on-LAN。', 'muted');
  },

  ua(d) {
    setMetrics([
      { k: '浏览器', v: `${d.browser} ${d.version}`.trim() },
      { k: '系统', v: d.os }, { k: '内核', v: d.engine }, { k: '设备', v: d.device }
    ]);
    const raw = $('raw');
    raw.hidden = false;
    raw.textContent = d.ua;
    appendLog(`解析：${d.browser} ${d.version} / ${d.os} / ${d.engine} / ${d.device}`, 'ok');
  },

  batch(d) {
    if (d.mode === 'port') {
      showTable(['主机', 'IP', '开放端口', '错误'],
        d.rows.map(r => [r.host, r.ip || '—', (r.open || []).join(', ') || '—', r.error || '—']));
    } else {
      showTable(['主机', 'IP', '发送', '接收', '丢包', '最小 ms', '平均 ms', '最大 ms'],
        d.rows.map(r => [r.host, r.ip || '—', r.sent, r.recv, r.loss + '%', r.min, r.avg, r.max]));
    }
    setMetrics([
      { k: '任务', v: d.mode === 'port' ? '端口检查' : 'Ping' },
      { k: '主机数', v: d.count }
    ]);
    appendLog(`批量任务完成，共 ${d.count} 个主机`, 'ok');
  }
});

/* 全国DNS：按分组提供节点；选中节点自动回填 DNS IP */
const DNS_GROUPS = {
  '公共': [
    ['114DNS', '114.114.114.114'],
    ['114DNS 备用', '114.114.115.115'],
    ['阿里 AliDNS', '223.5.5.5'],
    ['阿里 备用', '223.6.6.6'],
    ['腾讯 DNSPod', '119.29.29.29'],
    ['腾讯 备用', '182.254.116.116'],
    ['百度 DNS', '180.76.76.76'],
    ['谷歌', '8.8.8.8'],
    ['谷歌 备用', '8.8.4.4'],
    ['Cloudflare', '1.1.1.1']
  ],
  '电信': [
    ['北京电信', '219.141.136.10'],
    ['上海电信', '61.129.41.154'],
    ['广东电信', '202.96.128.86'],
    ['广东电信 备用', '202.96.128.166'],
    ['江苏电信', '218.2.2.2'],
    ['浙江电信', '61.153.177.196'],
    ['四川电信', '61.139.2.69'],
    ['福建电信', '218.85.152.99'],
    ['重庆电信', '61.128.128.68']
  ],
  '联通': [
    ['北京联通', '123.123.123.123'],
    ['北京联通 备用', '202.106.0.20'],
    ['上海联通', '210.22.70.3'],
    ['广东联通', '210.21.196.6'],
    ['广东联通 备用', '221.5.88.88'],
    ['江苏联通', '221.6.4.66'],
    ['山东联通', '202.102.128.68'],
    ['湖北联通', '218.104.111.114'],
    ['河南联通', '202.102.224.68']
  ],
  '移动': [
    ['广东移动', '211.136.192.6'],
    ['广东移动 备用', '211.136.20.203'],
    ['北京移动', '221.130.33.52'],
    ['上海移动', '211.136.112.200'],
    ['浙江移动', '211.140.13.188'],
    ['江苏移动', '221.131.143.69'],
    ['山东移动', '218.201.96.130'],
    ['四川移动', '211.137.96.205'],
    ['重庆移动', '218.201.4.3']
  ]
};

Object.assign(EVENT_HANDLERS, {
  diagnose(d) {
    if (d.type === 'start') {
      setStatus('诊断中…', 'busy');
    } else if (d.type === 'stage') {
      appendStage(`${d.step} / 6   ${d.text}`);
      if (d.text.includes('traceroute')) setStatus('traceroute 追踪中…', 'busy');
      else if (d.text.includes('TCP')) setStatus('TCP 连接测试中…', 'busy');
      else if (d.text.includes('网页')) setStatus('网页分析中…', 'busy');
      else if (d.text.includes('完成')) setStatus('完成', 'ok');
    } else if (d.type === 'log') {
      appendLog(d.text, '');
      const t = d.text;
      if (t.startsWith('开始traceroute')) setStatus('traceroute 追踪中…', 'busy');
      else if (t.startsWith('开始TCP')) setStatus('TCP 连接测试中…', 'busy');
      else if (t.startsWith('诊断完成')) setStatus('完成', 'ok');
    }
  },

  windiag(d) {
    if (d.type === 'start') {
      state.win = [];
      setStatus('系统体检中…', 'busy');
      appendLog(`诊断范围：${d.scope === 'all' ? '全部 8 类' : d.scope}` +
        (d.focus ? ` · AI 关注：${d.focus}` : ''), 'info');
    } else if (d.type === 'stage') {
      appendStage(d.step ? `${d.step} / ${d.total}   ${d.text}` : `${d.text}（准备）`);
      setStatus(d.text + '…', 'busy');
    } else if (d.type === 'finding') {
      (state.win = state.win || []).push(d);
      const tag = { ok: '[通过]', warn: '[注意]', err: '[异常]', info: '[信息]' }[d.level] || '';
      const cls = d.level === 'ok' ? 'ok' : d.level === 'warn' ? 'warn'
        : d.level === 'err' ? 'err' : 'info';
      appendLog(`${tag} ${d.title}${d.detail ? '  — ' + d.detail : ''}`, cls);
    } else if (d.type === 'summary') {
      const c = d.counts || {};
      setMetrics([
        { k: '通过', v: c.ok || 0 }, { k: '注意', v: c.warn || 0 },
        { k: '异常', v: c.err || 0 }, { k: '检查项', v: d.total || 0 }
      ]);
      if ((d.issues || []).length) {
        showTable(['级别', '项目', '说明'], d.issues.map(x => [
          x.level === 'err' ? '异常' : '注意', x.title, x.detail || '—'
        ]));
      }
      appendLog(`体检完成：通过 ${c.ok || 0}，注意 ${c.warn || 0}，异常 ${c.err || 0}`,
        c.err ? 'warn' : 'ok');
      if (d.focus) appendLog('可点「AI分析」结合关注问题做深度排查建议。', 'muted');
    } else if (d.type === 'done') {
      setStatus('完成', 'ok');
    }
  }
});

Object.assign(EVENT_HANDLERS, {
  mtu(d) {
    if (d.type === 'start') {
      appendLog(`MTU 探测 ${d.host}（IPv${d.family}），协议开销 ${d.overhead} 字节`, 'head');
      setStatus('探测中…', 'busy');
    } else if (d.type === 'probe') {
      const label = { ok: '通过', frag: '需分片', timeout: '超时' }[d.result] || d.result;
      appendLog(`载荷 ${d.size} → MTU ${d.mtu}  ${label}`,
        d.result === 'ok' ? 'ok' : (d.result === 'frag' ? 'warn' : 'err'));
    } else if (d.type === 'result') {
      setMetrics([
        { k: '路径 MTU', v: d.mtu },
        { k: '最大载荷', v: d.payload, u: 'B' },
        { k: '协议开销', v: d.overhead, u: 'B' }
      ]);
      appendLog(`路径 MTU：${d.mtu}（最大不分片载荷 ${d.payload} 字节）` +
        (d.at_top ? '，已达测试上限' : ''), 'info');
    } else if (d.type === 'done') {
      appendLog('MTU 探测完成', 'info');
    }
  }
});

Object.assign(RESULT_HANDLERS, {
  netstat(d) {
    const c = d.counts || {};
    setMetrics([
      { k: '监听', v: c.listen }, { k: '已建立', v: c.established },
      { k: 'UDP', v: c.udp }, { k: '进程', v: c.processes }
    ]);
    showTable(['协议', '本地', '远端', '状态', 'PID', '进程'],
      (d.rows || []).map(r => [r.proto, r.local, r.remote === '*:*' ? '—' : r.remote,
        r.state || '—', r.pid, r.process || '—']));
    appendLog(`共 ${c.total} 条连接，显示 ${d.shown} 条${d.truncated ? '（已截断）' : ''}`, 'ok');
    if ((d.rows || []).length === 0) appendLog('没有匹配的连接，试试清空关键字。', 'warn');
  }
});
