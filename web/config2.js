/* 第三批工具：TCP/扫描/诊断/查询/本地工具 */
Object.assign(ICONS, {
  tcping: '<svg viewBox="0 0 24 24"><rect x="2" y="6.5" width="20" height="11" rx="3"/><text x="12" y="13.6" text-anchor="middle" font-size="6" fill="currentColor" stroke="none" font-family="Consolas">TCP</text></svg>',
  superping: '<svg viewBox="0 0 24 24"><path d="M2 15a13 13 0 0 1 17 0"/><path d="M6 18a8 8 0 0 1 9 0"/><circle cx="10.5" cy="21" r="1.2" fill="currentColor" stroke="none"/><path d="M16 4l5 5M21 4l-5 5"/></svg>',
  ipscan: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><path d="M12 12l7-5"/><circle cx="15.5" cy="9.5" r="1.2" fill="currentColor" stroke="none"/><circle cx="9" cy="15" r="1.2" fill="currentColor" stroke="none"/></svg>',
  lanscan: '<svg viewBox="0 0 24 24"><path d="M3 9a13 13 0 0 1 18 0"/><path d="M6.5 12.5a8.5 8.5 0 0 1 11 0"/><path d="M10 16a4 4 0 0 1 4 0"/><circle cx="12" cy="19.5" r="1.3" fill="currentColor" stroke="none"/></svg>',
  tri: '<svg viewBox="0 0 24 24"><path d="M4 20V10M12 20V4M20 20V13"/><circle cx="4" cy="7.5" r="1.6"/><circle cx="12" cy="1.6" r="1.6"/><circle cx="20" cy="10.5" r="1.6"/><path d="M2.5 20h19"/></svg>',
  wifi: '<svg viewBox="0 0 24 24"><path d="M3 9a13 13 0 0 1 18 0"/><path d="M6.5 12.5a8.5 8.5 0 0 1 11 0"/><path d="M10 16a4 4 0 0 1 4 0"/><circle cx="12" cy="19.5" r="1.3" fill="currentColor" stroke="none"/><path d="M17.5 4.5l4 4M21.5 4.5l-4 4"/></svg>',
  telnet: '<svg viewBox="0 0 24 24"><rect x="2.5" y="4" width="19" height="16" rx="2"/><path d="M6.5 9l3.5 3-3.5 3M12 16h5"/></svg>',
  diagnose: '<svg viewBox="0 0 24 24"><rect x="2.5" y="4" width="19" height="14" rx="2"/><path d="M4.5 12h4l2-4 3 8 2-4h4"/><path d="M9 21h6"/></svg>',
  windoctor: '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8M12 17v4"/><path d="M5.5 10h3l1.5-3 2.5 6 1.5-3h4.5"/></svg>',
  batch: '<svg viewBox="0 0 24 24"><path d="M12 2.5l9 4.5-9 4.5-9-4.5z"/><path d="M3 11.5l9 4.5 9-4.5M3 16l9 4.5 9-4.5"/></svg>',
  vs: '<svg viewBox="0 0 24 24"><path d="M9 4L4 20M15 4l5 16"/><circle cx="6.5" cy="12" r="1.2" fill="currentColor" stroke="none"/><circle cx="17.5" cy="12" r="1.2" fill="currentColor" stroke="none"/></svg>',
  whois: '<svg viewBox="0 0 24 24"><circle cx="10.5" cy="10.5" r="6.5"/><path d="M15.5 15.5L21 21"/><path d="M8 8.5h5M8 11.5h3"/></svg>',
  user: '<svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="3.8"/><path d="M4.5 21a7.5 7.5 0 0 1 15 0"/></svg>',
  json: '<svg viewBox="0 0 24 24"><path d="M8 4c-2 0-2 8-4 8 2 0 2 8 4 8M16 4c2 0 2 8 4 8-2 0-2 8-4 8"/><path d="M13 8h.01M13 12h.01M13 16h.01"/></svg>',
  bases: '<svg viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M7 9h2v6M12 9v6M16 9v6M7 12h2M16 12h2"/></svg>',
  power: '<svg viewBox="0 0 24 24"><path d="M12 2.5V11"/><path d="M7 5.5a8 8 0 1 0 10 0"/></svg>'
});

TOOLS.push(
  {
    id: 'tcping', name: 'TCPing', color: 'red', icon: 'tcping', group: 'detect',
    sub: 'TCP 端口握手延时', mode: 'sse', endpoint: '/api/tcping/stream',
    fields: [
      FIELD('host', '主机', 'www.baidu.com'),
      FIELD('port', '端口', '443', { type: 'number', min: 1, max: 65535 }),
      FIELD('count', '次数(0 为持续)', '4', { type: 'number', min: 0 }),
      FIELD('timeout', '超时(秒)', '2', { type: 'number', step: 0.5, min: 0.2 }),
      FIELD('interval', '间隔(秒)', '1', { type: 'number', step: 0.2, min: 0.2 })
    ]
  },
  {
    id: 'superping', name: '超级Ping', color: 'red', icon: 'superping', group: 'detect',
    sub: '多主机同时探测，一表对比', mode: 'sse', endpoint: '/api/superping/stream',
    fields: [
      FIELD('hosts', '主机列表（逗号分隔，最多 8 个）', '223.5.5.5,114.114.114.114,www.baidu.com', { wide: true }),
      FIELD('count', '次数(0 为持续)', '4', { type: 'number', min: 0 }),
      FIELD('interval', '间隔(秒)', '1', { type: 'number', step: 0.2, min: 0.2 }),
      FIELD('size', '包大小(字节)', '32', { type: 'number', min: 1 }),
      FIELD('timeout', '超时(ms)', '1000', { type: 'number', min: 100 })
    ]
  },
  {
    id: 'ipscan', name: 'IP扫描', color: 'red', icon: 'ipscan', group: 'detect',
    sub: '网段内存活主机（最多 /22）', mode: 'json', endpoint: '/api/ipscan',
    fields: [
      FIELD('cidr', '网段', '192.168.1.0/24', { wide: true, ph: '如 192.168.1.0/24' }),
      FIELD('timeout', '每主机超时(ms)', '600', { type: 'number', min: 100, max: 5000 })
    ]
  },
  {
    id: 'lanscan', name: '扫描局域网', color: 'red', icon: 'lanscan', group: 'detect',
    sub: '本网段设备 + MAC + 网关', mode: 'json', endpoint: '/api/lanscan',
    fields: [FIELD('cidr', '网段（留空=本机所在 /24）', '', { wide: true })]
  },
  {
    id: 'triprobe', name: '三网拨测', color: 'red', icon: 'tri', group: 'detect',
    sub: '阿里云全国节点 HTTP 拨测', mode: 'json', endpoint: '', fields: [
      FIELD('url', '目标域名或 URL', 'www.baidu.com', { wide: true, ph: '如 www.example.com' })
    ]
  },
  {
    id: 'wlan', name: 'WLAN 分析', color: 'red', icon: 'wifi', group: 'detect',
    windowsOnly: true,
    sub: '周边 SSID / 信号 / 信道（仅 Windows）', mode: 'json', endpoint: '/api/wlan', fields: []
  },
  {
    id: 'telnet', name: 'telnet', color: 'red', icon: 'telnet', group: 'detect',
    sub: 'TCP 连接并读取 Banner', mode: 'json', endpoint: '/api/telnet',
    fields: [
      FIELD('host', '主机', '127.0.0.1'),
      FIELD('port', '端口', '23', { type: 'number', min: 1, max: 65535 }),
      FIELD('timeout', '超时(秒)', '5', { type: 'number', min: 0.5 }),
      FIELD('send', '连接后发送（可选）', '')
    ]
  },
  {
    id: 'windiag', name: 'Windows 诊断', color: 'red', icon: 'windoctor', group: 'detect',
    windowsOnly: true,
    sub: '系统体检：启动 / 蓝屏 / 性能 / 更新 / 外设 / 激活（仅 Windows）', mode: 'sse', endpoint: '/api/windiag/stream',
    fields: [
      FIELD('scope', '诊断范围', 'all', {
        type: 'select', options: [
          ['all', '全部（8 类）'], ['boot', '启动与开机'], ['bsod', '蓝屏与异常重启'],
          ['perf', '性能与卡顿'], ['update', 'Windows 更新'], ['device', '网络 / 外设 / 音频'],
          ['files', '系统文件与权限'], ['license', '激活 / 磁盘 / 存储'], ['misc', '其他高频问题']
        ]
      }),
      FIELD('focus', 'AI 关注问题（可选）', '', {
        type: 'textarea', wide: true,
        ph: '如：开机慢、磁盘 100%、更新回滚、蓝屏、没声音；留空则做全局深度分析'
      })
    ]
  },
  {
    id: 'diagnose', name: '网络诊断', color: 'red', icon: 'diagnose', group: 'detect',
    sub: '设备信息 → 网页分析 → DNS → TCP → traceroute', mode: 'sse', endpoint: '/api/diagnose/stream',
    fields: [FIELD('domain', '诊断域名 / 网页地址', 'www.baidu.com', { wide: true, ph: 'www.baidu.com 或 https://www.baidu.com/' })]
  },
  {
    id: 'sitecompare', name: '站点对比', color: 'red', icon: 'vs', group: 'detect',
    sub: '多站点耗时 / 状态对比，最多 20 个', mode: 'json', endpoint: '/api/sitecompare',
    note: '<b>样例</b>：<code>https://www.baidu.com</code><code>https://www.qq.com</code><code>mirrors.aliyun.com</code>' +
      '换行、逗号或空格分隔，最多 20 个；不带协议默认按 <code>http://</code> 补全。<br>' +
      '<b>完整分段</b>：DNS（域名解析）→ TCP（建立连接）→ TLS（仅 https 握手）→ 首字节（发出请求到收到第一个响应字节）→ ' +
      '总计（从发起到读完响应，最多 2MB）；<code>—</code> 表示该站点不走这一阶段（如 http 无 TLS）。<br>' +
      '<b>只查状态</b>：每个站点发一次请求拿到状态码即断开，更快，只给状态 / 总耗时 / 服务器。<br>' +
      '<b>其他</b>：最多 10 个站点同时探测，表格按输入顺序排列；「最快」取总计最小的成功站点，失败原因见下方运行日志。',
    fields: [
      FIELD('urls', 'URL 列表（逗号或换行，最多 20 个）', 'https://www.baidu.com,https://www.qq.com', { type: 'textarea', wide: true }),
      FIELD('mode', '模式', 'full', { type: 'select', options: [['full', '完整分段计时'], ['status', '只查状态（更快）']] }),
      FIELD('timeout', '超时(秒)', '10', { type: 'number', min: 1 })
    ]
  },
  {
    id: 'batch', name: '批量任务', color: 'red', icon: 'batch', group: 'detect',
    sub: '批量 Ping / 批量端口检查', mode: 'json', endpoint: '/api/batch',
    fields: [
      FIELD('hosts', '主机列表（逗号或换行，最多 30 个）', '223.5.5.5,114.114.114.114', { type: 'textarea', wide: true }),
      FIELD('mode', '任务', 'ping', { type: 'select', options: [['ping', '批量 Ping'], ['port', '批量端口检查']] }),
      FIELD('ports', '端口（端口任务用）', '80,443', { wide: true }),
      FIELD('count', 'Ping 次数', '2', { type: 'number', min: 1, max: 10 })
    ]
  },
  {
    id: 'dig', name: 'dig命令', color: 'blue', icon: 'code', group: 'query',
    sub: 'DNS 原始应答 / 权威段', mode: 'json', endpoint: '/api/dig',
    fields: [
      FIELD('name', '域名', 'www.baidu.com'),
      FIELD('type', '类型', 'A', { type: 'select', options: [['A', 'A'], ['AAAA', 'AAAA'], ['CNAME', 'CNAME'], ['MX', 'MX'], ['TXT', 'TXT'], ['NS', 'NS'], ['SOA', 'SOA'], ['SRV', 'SRV'], ['CAA', 'CAA']] }),
      FIELD('server', 'DNS 服务器（留空用系统）', '', { ph: '如 8.8.8.8' })
    ]
  },
  {
    id: 'whois', name: 'Whois 域名查询', color: 'blue', icon: 'whois', group: 'query',
    sub: '注册信息原始文本', mode: 'json', endpoint: '/api/whois',
    fields: [FIELD('domain', '域名', 'baidu.com', { wide: true })]
  },
  {
    id: 'ua', name: 'User Agent', color: 'blue', icon: 'user', group: 'query',
    sub: '解析浏览器 / 系统 / 内核（留空=本机）', mode: 'json', endpoint: '/api/ua',
    fields: [FIELD('ua', 'User-Agent（留空自动取本机）', '', { type: 'textarea', wide: true })]
  },
  {
    id: 'jsonfmt', name: 'JSON格式化', color: 'blue', icon: 'json', group: 'query',
    sub: '格式化 / 压缩 / 校验', mode: 'json', endpoint: '/api/json',
    fields: [
      FIELD('text', 'JSON 内容', '{"name":"netmeter","items":[1,2,3]}', { type: 'textarea', wide: true }),
      FIELD('mode', '模式', 'pretty', { type: 'select', options: [['pretty', '格式化'], ['minify', '压缩']] })
    ]
  },
  {
    id: 'baseconv', name: '进制转换', color: 'blue', icon: 'bases', group: 'query',
    sub: '2-36 进制互转', mode: 'json', endpoint: '/api/base',
    fields: [
      FIELD('value', '数值', '255', { wide: true }),
      FIELD('from_base', '原进制', '10', { type: 'select', options: [['2', '2 进制'], ['8', '8 进制'], ['10', '10 进制'], ['16', '16 进制'], ['36', '36 进制']] }),
      FIELD('to_base', '目标进制', '16', { type: 'select', options: [['2', '2 进制'], ['8', '8 进制'], ['10', '10 进制'], ['16', '16 进制'], ['36', '36 进制']] })
    ]
  },
  {
    id: 'wol', name: '唤醒', color: 'pink', icon: 'power', group: 'adv',
    sub: 'Wake-on-LAN 魔术包', mode: 'json', endpoint: '/api/wol',
    fields: [
      FIELD('mac', 'MAC 地址', 'AA:BB:CC:DD:EE:FF', { wide: true }),
      FIELD('broadcast', '广播地址', '255.255.255.255'),
      FIELD('port', '端口', '9', { type: 'number', min: 1, max: 65535 })
    ]
  },
  {
    id: 'iperf3', name: 'iperf3', color: 'pink', icon: 'gauge', group: 'adv',
    sub: '内置 iperf3（打包时放入 bin/）', mode: 'sse', endpoint: '/api/iperf3/stream',
    fields: [
      FIELD('host', '服务端地址', '', { wide: true, ph: '如 10.1.2.3 或公网 iperf3 服务器' }),
      FIELD('port', '端口', '5201', { type: 'number', min: 1, max: 65535 }),
      FIELD('seconds', '时长(秒)', '10', { type: 'number', min: 1, max: 60 }),
      FIELD('reverse', '方向', '0', { type: 'select', options: [['0', '上传'], ['1', '下载(-R)']] })
    ]
  }
);

Object.assign(ICONS, {
  mtu: '<svg viewBox="0 0 24 24"><rect x="2.5" y="7" width="19" height="10" rx="1.5"/><path d="M6.5 7v5M10 7v7M13.5 7v5M17 7v7"/></svg>',
  conn: '<svg viewBox="0 0 24 24"><path d="M8 6h13M8 12h13M8 18h13"/><circle cx="4" cy="6" r="1.2" fill="currentColor" stroke="none"/><circle cx="4" cy="12" r="1.2" fill="currentColor" stroke="none"/><circle cx="4" cy="18" r="1.2" fill="currentColor" stroke="none"/></svg>',
  report: '<svg viewBox="0 0 24 24"><path d="M14 2.5H6a2 2 0 0 0-2 2v15a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2.5V8h5.5"/><path d="M12 11v8M9 16l3 3 3-3"/></svg>'
});

TOOLS.push(
  {
    id: 'mtu', name: 'MTU测试', color: 'red', icon: 'mtu', group: 'detect',
    sub: '路径 MTU / 分片探测', mode: 'sse', endpoint: '/api/mtu/stream',
    fields: [
      FIELD('host', '目标主机', '223.5.5.5', { wide: true }),
      FIELD('family', '协议', '4', { type: 'select', options: [['4', 'IPv4'], ['6', 'IPv6']] }),
      FIELD('timeout', '超时(ms)', '1200', { type: 'number', min: 300, max: 5000 })
    ]
  },
  {
    id: 'netstat', name: '端口占用', color: 'red', icon: 'conn', group: 'detect',
    sub: '本机监听 / 连接 / 进程', mode: 'json', endpoint: '/api/netstat',
    fields: [
      FIELD('state', '筛选', 'all', { type: 'select', options: [['all', '全部连接'], ['listen', '仅监听']] }),
      FIELD('query', '关键字（端口/IP/进程）', '')
    ]
  }
);

Object.assign(ICONS, {
  mux: '<svg viewBox="0 0 24 24"><path d="M4 7h6M4 12h6M4 17h6"/><path d="M10 7h4l6-3v6l-6-3zM10 17h4l6-3v6l-6-3z"/></svg>',
  table: '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M3 14h18M9 9v11M15 9v11"/></svg>',
  arp: '<svg viewBox="0 0 24 24"><circle cx="7" cy="12" r="3"/><circle cx="17" cy="7" r="3"/><circle cx="17" cy="17" r="3"/><path d="M10 12h4M14 9.5l-1.5 2.5M14 14.5L12.5 12"/></svg>',
  ifstat: '<svg viewBox="0 0 24 24"><path d="M4 18V10M9 18V6M14 18v-7M19 18V4"/><path d="M3 20h18"/></svg>',
  nat: '<svg viewBox="0 0 24 24"><rect x="3" y="8" width="7" height="8" rx="1.5"/><rect x="14" y="4" width="7" height="16" rx="1.5"/><path d="M10 12h4"/></svg>',
  extract: '<svg viewBox="0 0 24 24"><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/></svg>',
  ssh: '<svg viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M7 14l3-2-3-2M12 14h5"/></svg>',
  pcap: '<svg viewBox="0 0 24 24"><rect x="3" y="3.5" width="18" height="17" rx="2"/><path d="M6 8h12M6 12h12M6 16h8"/><circle cx="17.5" cy="16" r="1.4" fill="currentColor" stroke="none"/></svg>'
});

TOOLS.push(
  {
    id: 'routes', name: '路由表', color: 'blue', icon: 'table', group: 'query',
    sub: '本机 IPv4 / IPv6 路由', mode: 'json', endpoint: '/api/routes',
    fields: [
      FIELD('family', '协议', 'all', { type: 'select', options: [['all', '全部'], ['4', '仅 IPv4'], ['6', '仅 IPv6']] })
    ]
  },
  {
    id: 'arp', name: 'ARP 表', color: 'blue', icon: 'arp', group: 'query',
    sub: '邻居缓存：IP / MAC / 网卡', mode: 'json', endpoint: '/api/arp',
    fields: [FIELD('query', '关键字（IP / MAC / 网卡）', '')]
  },
  {
    id: 'ifstat', name: '网卡流量', color: 'red', icon: 'ifstat', group: 'detect',
    sub: '各网卡实时上下行速率', mode: 'sse', endpoint: '/api/ifstat/stream',
    fields: [
      FIELD('seconds', '时长(秒，0 为持续)', '0', { type: 'number', min: 0, max: 3600 })
    ]
  },
  {
    id: 'nattype', name: 'NAT 类型', color: 'red', icon: 'nat', group: 'detect',
    sub: 'STUN 检测锥型 / 对称型 NAT', mode: 'json', endpoint: '/api/nat', fields: []
  },
  {
    id: 'mux', name: '网卡叠加', color: 'pink', icon: 'mux', group: 'adv',
    sub: '连接级多网卡聚合（本机代理）', mode: 'panel'
  },
  {
    id: 'svrextract', name: '服务器信息提取', color: 'blue', icon: 'extract', group: 'query',
    sub: '告警 / CMDB 原文 → 工单标题与模板', mode: 'panel'
  },
  {
    id: 'ssh', name: 'SSH', color: 'pink', icon: 'ssh', group: 'adv',
    sub: '远程终端，可保存常用主机', mode: 'panel'
  }
);
TOOLS.push(
  {
    id: 'pcap', name: '抓包分析', color: 'red', icon: 'pcap', group: 'detect',
    sub: '报文列表 · 分析与离线诊断 · 逐层详情 · pcap', mode: 'panel'
  }
);
