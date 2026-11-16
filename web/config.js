/* 工具清单：网格、表单与接口定义 */
const ICONS = {
  ping: '<svg viewBox="0 0 24 24"><path d="M3 17a13 13 0 0 1 18 0"/><path d="M7 20a8 8 0 0 1 10 0"/><circle cx="12" cy="21.2" r="1.3" fill="currentColor" stroke="none"/></svg>',
  pingpp: '<svg viewBox="0 0 24 24"><path d="M2 16a13 13 0 0 1 17 0"/><path d="M6 19a8 8 0 0 1 9 0"/><circle cx="10.5" cy="21" r="1.2" fill="currentColor" stroke="none"/><path d="M18.5 3.5h5M21 1v5"/></svg>',
  route: '<svg viewBox="0 0 24 24"><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 16.5h.01M11 16.5h.01"/><path d="M12 13V6"/><path d="M9 4l3-2 3 2"/></svg>',
  mtr: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M12 1.5V6M12 18v4.5M1.5 12H6M18 12h4.5"/><path d="M9.5 12h5"/></svg>',
  port: '<svg viewBox="0 0 24 24"><path d="M9 2.5v5M15 2.5v5"/><rect x="5.5" y="7.5" width="13" height="7.5" rx="2"/><path d="M12 15v6.5"/></svg>',
  page: '<svg viewBox="0 0 24 24"><path d="M14 2.5H6a2 2 0 0 0-2 2v15a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2.5V8h5.5M8 13h8M8 17h5"/></svg>',
  down: '<svg viewBox="0 0 24 24"><path d="M7 18.5a4 4 0 0 1-.6-8A5.5 5.5 0 0 1 17 9.2a4.5 4.5 0 0 1 1 8.9"/><path d="M12 11v9M9 17l3 3 3-3"/></svg>',
  server: '<svg viewBox="0 0 24 24"><rect x="3" y="3.5" width="18" height="7" rx="1.5"/><rect x="3" y="13.5" width="18" height="7" rx="1.5"/><path d="M6.5 7h.01M6.5 17h.01M10 7h7M10 17h7"/></svg>',
  timing: '<svg viewBox="0 0 24 24"><circle cx="12" cy="13" r="8"/><path d="M12 9v4.2l2.6 2"/><path d="M9 2h6M12 2v3"/></svg>',
  gauge: '<svg viewBox="0 0 24 24"><path d="M3.5 18.5a9 9 0 1 1 17 0"/><path d="M12 14.5l4.2-4.2"/><circle cx="12" cy="15.5" r="1.4" fill="currentColor" stroke="none"/></svg>',
  globe: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3.2 3.6 3.2 14.4 0 18M12 3c-3.2 3.6-3.2 14.4 0 18"/></svg>',
  share: '<svg viewBox="0 0 24 24"><circle cx="18" cy="5" r="2.8"/><circle cx="6" cy="12" r="2.8"/><circle cx="18" cy="19" r="2.8"/><path d="M8.5 10.6l7-4M8.5 13.4l7 4"/></svg>',
  pin: '<svg viewBox="0 0 24 24"><path d="M12 21s7-6.2 7-11a7 7 0 1 0-14 0c0 4.8 7 11 7 11z"/><circle cx="12" cy="10" r="2.6"/></svg>',
  calc: '<svg viewBox="0 0 24 24"><rect x="4" y="2.5" width="16" height="19" rx="2"/><path d="M7.5 6.5h9M8 11h.01M12 11h.01M16 11h.01M8 15h.01M12 15h.01M16 15h.01M8 19h.01M12 19h.01M16 19h.01"/></svg>',
  clock: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 6.5V12l3.5 2"/></svg>',
  code: '<svg viewBox="0 0 24 24"><path d="M8 7l-5 5 5 5M16 7l5 5-5 5"/></svg>',
  qr: '<svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h3v3h-3zM20 14h1M14 20h1M18 18h3v3h-3z"/></svg>',
  http: '<svg viewBox="0 0 24 24"><path d="M8 7l-5 5 5 5M16 7l5 5-5 5"/></svg>'
};

const FIELD = (k, label, value, opts = {}) => Object.assign({ k, label, value }, opts);

const TOOLS = [
  {
    id: 'ping', name: 'Ping', color: 'red', icon: 'ping', group: 'detect',
    sub: '连通性 · 丢包 · 时延', mode: 'sse', endpoint: '/api/ping/stream',
    fields: [
      FIELD('host', '主机', '223.5.5.5', { ph: '域名或 IP' }),
      FIELD('count', '次数', '4', { type: 'number', min: 1, max: 2000 }),
      FIELD('size', '包大小(字节)', '32', { type: 'number', min: 1, max: 65500 }),
      FIELD('timeout', '超时(ms)', '1000', { type: 'number', min: 100 }),
      FIELD('interval', '间隔(秒)', '1', { type: 'number', step: 0.2, min: 0.2 }),
      FIELD('family', '协议', '4', { type: 'select', options: [['4', 'IPv4'], ['6', 'IPv6']] })
    ]
  },
  {
    id: 'pingpp', name: 'Ping++', color: 'red', icon: 'pingpp', group: 'detect',
    sub: '持续探测 · 抖动统计（0 次=一直跑）', mode: 'sse', endpoint: '/api/ping/stream',
    fields: [
      FIELD('host', '主机', '223.5.5.5', { ph: '域名或 IP' }),
      FIELD('count', '次数(0 为持续)', '0', { type: 'number', min: 0 }),
      FIELD('size', '包大小(字节)', '64', { type: 'number', min: 1, max: 65500 }),
      FIELD('timeout', '超时(ms)', '1000', { type: 'number', min: 100 }),
      FIELD('interval', '间隔(秒)', '1', { type: 'number', step: 0.2, min: 0.2 }),
      FIELD('family', '协议', '4', { type: 'select', options: [['4', 'IPv4'], ['6', 'IPv6']] })
    ]
  },
  {
    id: 'traceroute', name: 'traceroute', color: 'red', icon: 'route', group: 'detect',
    sub: '逐跳路径与耗时', mode: 'sse', endpoint: '/api/traceroute/stream',
    fields: [
      FIELD('host', '主机', 'www.baidu.com'),
      FIELD('maxhops', '最大跳数', '30', { type: 'number', min: 1, max: 64 }),
      FIELD('timeout', '每跳超时(ms)', '1000', { type: 'number', min: 100 }),
      FIELD('family', '协议', '4', { type: 'select', options: [['4', 'IPv4'], ['6', 'IPv6']] })
    ]
  },
  {
    id: 'mtr', name: 'MTR', color: 'red', icon: 'mtr', group: 'detect',
    sub: '逐跳丢包，边探测边出表', mode: 'sse', endpoint: '/api/mtr/stream',
    fields: [
      FIELD('host', '主机', 'www.baidu.com'),
      FIELD('maxhops', '最大跳数', '30', { type: 'number', min: 1, max: 64 }),
      FIELD('samples', '采样轮数', '2', { type: 'number', min: 1, max: 10 }),
      FIELD('timeout', '每探测超时(ms)', '600', { type: 'number', min: 100 }),
      FIELD('family', '协议', '4', { type: 'select', options: [['4', 'IPv4'], ['6', 'IPv6']] })
    ]
  },
  {
    id: 'portscan', name: '端口探测', color: 'red', icon: 'port', group: 'detect',
    sub: 'TCP 端口开放扫描', mode: 'json', endpoint: '/api/portscan',
    fields: [
      FIELD('host', '主机', '127.0.0.1'),
      FIELD('ports', '端口', '22,80,443,3306,3389,8080', { wide: true, ph: '例：80,443,1-1024' }),
      FIELD('timeout', '连接超时(秒)', '0.8', { type: 'number', step: 0.1, min: 0.1 })
    ]
  },
  {
    id: 'fetch', name: '抓取页面', color: 'red', icon: 'page', group: 'detect',
    sub: '拉取响应头与内容', mode: 'json', endpoint: '/api/fetch',
    fields: [
      FIELD('url', 'URL', 'https://www.baidu.com', { wide: true }),
      FIELD('method', '方法', 'GET', { type: 'select', options: [['GET', 'GET'], ['HEAD', 'HEAD'], ['POST', 'POST']] }),
      FIELD('follow', '跟随跳转', '1', { type: 'select', options: [['1', '是'], ['0', '否']] }),
      FIELD('timeout', '超时(秒)', '15', { type: 'number', min: 1 }),
      FIELD('headers', '请求头（每行 k: v）', '', { type: 'textarea', wide: true, ph: 'User-Agent: xxx' }),
      FIELD('body', '请求体', '', { type: 'textarea', wide: true })
    ]
  },
  {
    id: 'download', name: '下载测试', color: 'red', icon: 'down', group: 'detect',
    sub: '实时下载速率', mode: 'sse', endpoint: '/api/download/stream',
    fields: [
      FIELD('url', '下载地址', 'https://mirrors.aliyun.com/ubuntu/ls-lR.gz', { wide: true }),
      FIELD('seconds', '测试时长(秒)', '10', { type: 'number', min: 2 }),
      FIELD('max_mb', '最大下载(MB)', '200', { type: 'number', min: 1 })
    ]
  },
  {
    id: 'probe', name: '服务器探测', color: 'red', icon: 'server', group: 'detect',
    sub: '状态 · 跳转链 · TLS 证书链', mode: 'json', endpoint: '/api/probe',
    fields: [FIELD('url', 'URL', 'https://www.baidu.com', { wide: true })]
  },
  {
    id: 'timing', name: 'HTTP速度', color: 'red', icon: 'timing', group: 'detect',
    sub: 'DNS / TCP / TLS / 首字节分段计时', mode: 'json', endpoint: '/api/timing',
    fields: [FIELD('url', 'URL', 'https://www.baidu.com', { wide: true })]
  },
  {
    id: 'speed', name: '测速', color: 'red', icon: 'gauge', group: 'detect',
    sub: '延时 · 下行 · 上行，约 20 秒', mode: 'sse', endpoint: '/api/speed/stream',
    fields: [
      FIELD('down_url', '下载测速地址', 'https://mirrors.aliyun.com/ubuntu/ls-lR.gz', { wide: true }),
      FIELD('up_url', '上传测速地址', 'https://speed.cloudflare.com/__up', { wide: true })
    ]
  },
  {
    id: 'dns', name: '域名解析', color: 'red', icon: 'globe', group: 'detect',
    sub: 'A / AAAA / CNAME / MX / TXT / NS', mode: 'json', endpoint: '/api/dns',
    fields: [
      FIELD('name', '域名或 IP', 'www.baidu.com', { wide: true }),
      FIELD('types', '记录类型', 'A,AAAA,CNAME,MX,TXT,NS', { wide: true }),
      FIELD('server', '指定 DNS（留空用系统）', '', { ph: '如 223.5.5.5' })
    ]
  },
  {
    id: 'cndns', name: '全国DNS', color: 'pink', icon: 'globe', group: 'adv',
    sub: '选运营商/公共组，单点解析', mode: 'json', endpoint: '/api/dns',
    fields: [
      FIELD('provider', '分组', '公共', { type: 'select', options: [['公共', '公共'], ['电信', '电信'], ['联通', '联通'], ['移动', '移动']] }),
      FIELD('node', '节点', '', { type: 'select', options: [['', '加载中…']] }),
      FIELD('name', '域名', 'www.baidu.com'),
      FIELD('server', 'DNS IP（可手改）', '114.114.114.114'),
      FIELD('types', '记录类型', 'A,AAAA,CNAME', {
        type: 'select', options: [
          ['A', 'A'], ['AAAA', 'AAAA'], ['CNAME', 'CNAME'],
          ['A,AAAA,CNAME', 'A + AAAA + CNAME'],
          ['A,AAAA,CNAME,MX,TXT,NS', '全部常用']
        ]
      })
    ]
  },
  {
    id: 'httpadv', name: 'HTTP高级方法', color: 'pink', icon: 'http', group: 'adv',
    sub: '自定义方法 / 头 / 请求体', mode: 'json', endpoint: '/api/httpadv',
    fields: [
      FIELD('url', 'URL', 'https://www.baidu.com', { wide: true }),
      FIELD('method', '方法', 'GET', { type: 'select', options: [['GET', 'GET'], ['POST', 'POST'], ['PUT', 'PUT'], ['DELETE', 'DELETE'], ['PATCH', 'PATCH'], ['HEAD', 'HEAD'], ['OPTIONS', 'OPTIONS']] }),
      FIELD('follow', '跟随跳转', '1', { type: 'select', options: [['1', '是'], ['0', '否']] }),
      FIELD('timeout', '超时(秒)', '20', { type: 'number', min: 1 }),
      FIELD('headers', '请求头（每行 k: v）', 'Content-Type: application/json', { type: 'textarea', wide: true }),
      FIELD('body', '请求体', '{"hello": "world"}', { type: 'textarea', wide: true })
    ]
  },
  {
    id: 'share', name: '分享软件', color: 'red', icon: 'share', group: 'detect',
    sub: 'PC 端不适用', disabled: true, badge: 'PC 不适用'
  },
  {
    id: 'iplocal', name: '你的IP信息', color: 'blue', icon: 'globe', group: 'query',
    sub: '网卡 / 公网 / 网关 / DNS 一览', mode: 'json', endpoint: '/api/iplocal', fields: []
  },
  {
    id: 'iploc', name: 'IP查询', color: 'blue', icon: 'pin', group: 'query',
    sub: '归属地 / 运营商', mode: 'json', endpoint: '/api/iploc',
    fields: [FIELD('ip', 'IP 地址（留空查本机出口）', '', { wide: true, ph: '如 8.8.8.8' })]
  },
  {
    id: 'dnsip', name: 'DnsIP', color: 'blue', icon: 'globe', group: 'query',
    sub: '域名 ↔ IP 正反查', mode: 'json', endpoint: '/api/dnsip',
    fields: [FIELD('value', '域名或 IP', 'www.baidu.com', { wide: true })]
  },
  {
    id: 'ipcalc', name: 'IP计算器', color: 'blue', icon: 'calc', group: 'query',
    sub: '掩码 / 网段 / 广播 / 主机数', mode: 'json', endpoint: '/api/ipcalc',
    fields: [
      FIELD('ip', 'IP 或 CIDR', '192.168.1.10/24', { wide: true }),
      FIELD('mask', '掩码（CIDR 或点分，可留空）', '')
    ]
  },
  {
    id: 'ts', name: '时间转化', color: 'blue', icon: 'clock', group: 'query',
    sub: '时间戳 ↔ 日期时间', mode: 'json', endpoint: '/api/time',
    fields: [
      FIELD('value', '时间戳 / 日期（留空=现在）', '', { wide: true, ph: '1763000000 或 2026-11-13 23:30:00' }),
      FIELD('offset', '时区 UTC+', '8', { type: 'number', min: -12, max: 14 })
    ]
  },
  {
    id: 'codec', name: '编码与加密', color: 'blue', icon: 'code', group: 'query',
    sub: 'Base64 / URL / Hex / Unicode / 哈希', mode: 'json', endpoint: '/api/codec',
    fields: [
      FIELD('op', '操作', 'base64e', {
        type: 'select', options: [
          ['base64e', 'Base64 编码'], ['base64d', 'Base64 解码'],
          ['urle', 'URL 编码'], ['urld', 'URL 解码'],
          ['hexe', 'Hex 编码'], ['hexd', 'Hex 解码'],
          ['unicodee', 'Unicode 转义'], ['unicoded', 'Unicode 还原'],
          ['md5', 'MD5'], ['sha1', 'SHA1'], ['sha256', 'SHA256']
        ]
      }),
      FIELD('text', '内容', '', { type: 'textarea', wide: true })
    ]
  },
  {
    id: 'qr', name: '二维码生成', color: 'blue', icon: 'qr', group: 'query',
    sub: '文本 / 链接转二维码', mode: 'json', endpoint: '/api/qr',
    fields: [
      FIELD('text', '内容', 'https://www.baidu.com', { type: 'textarea', wide: true }),
      FIELD('size', '尺寸(px)', '240', { type: 'number', min: 120, max: 640 })
    ]
  }
];
