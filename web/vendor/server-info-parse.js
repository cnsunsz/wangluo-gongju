/**
 * 合营云服务器信息解析 v1.6.0
 * CloudCMDB：管理IPv4 / BMC IPv4 严格区分；过滤表头互串与表单占位符
 * 标题：【合营云】{区域}Server业务{主机名}硬件故障
 */
(function (root) {
  var FIELDS = [
    { key: "host", label: "主机名：" },
    { key: "sn", label: "物理机SN：" },
    { key: "mgmt", label: "管理IP：" },
    { key: "bmc", label: "BMC IP：" },
    { key: "model", label: "服务器型号：" },
    { key: "room", label: "机房：" },
    { key: "fault", label: "故障：" },
  ];

  function emptyResult() {
    return { host: "", sn: "", mgmt: "", bmc: "", model: "", room: "", fault: "", region: "" };
  }

  function grabIPv4(s) {
    var m = String(s || "").match(/(\d{1,3}(?:\.\d{1,3}){3})/);
    return m ? m[1] : "";
  }

  function clean(s) {
    return String(s || "")
      .replace(/^IPv4\s*[:：]?\s*/i, "")
      .replace(/^[\s:：]+|[\s:：]+$/g, "")
      .trim();
  }

  function isJunk(v) {
    v = String(v || "").trim();
    if (!v) return true;
    if (/必填|请输入|请选择|placeholder|OS主机名称|物理机的BMC|一致性校验|对主机名除了|cnnorth1c-POD01-Cascaded/i.test(v))
      return true;
    if (/^(SN|主机名|管理IP|BMC\s*IP|BMC\s*IPv4|管理IPv4|生命周期|主机类型|Region|AZ|POD|Region\s*AZ|起始U位|操作|物理机SN|服务器型号|机房|故障|使用中|正常|异常)$/i.test(v))
      return true;
    if (/^(Region|AZ|POD)(\s+(Region|AZ|POD))*$/i.test(v)) return true;
    return false;
  }

  function isHostname(s) {
    return /^cidcrp/i.test(String(s || "")) || /persistence|pod\d|-bm\d|-cna\d|-nws|-net-\d/i.test(String(s || ""));
  }

  function isSN(s) {
    s = String(s || "");
    if (/^[0-9a-f]{8}-[0-9a-f\-]+$/i.test(s)) return false;
    return /^[0-9A-Za-z]{10,}$/.test(s) && s.indexOf(".") < 0 && !isHostname(s);
  }

  function isModel(s) {
    s = String(s || "");
    return (
      /^(S920|R\d{3,4}|RS\d{2,4}|2288|5288|TaiShan|NW\d|RH\d|Atlas|Kunpeng|G\d{4})/i.test(s) ||
      /V\d$/i.test(s) ||
      /Compute\s*Node/i.test(s)
    );
  }

  function normRoom(s) {
    s = String(s || "").replace(/\t/g, " ").replace(/\s+/g, " ").trim();
    if (!s) return "";
    if (/u$/i.test(s)) return s;
    // 仅「空格 + U 位数字」才规范成 -Nu；不要把机架码末尾 -B16 / -A19 当成 U 位
    var m = s.match(/^(.+?)[ \t]+(\d{1,2})$/);
    if (m && parseInt(m[2], 10) >= 1 && parseInt(m[2], 10) <= 48) {
      return m[1].trim() + "-" + m[2] + "u";
    }
    return s;
  }

  /** 机架 + 起始U → 机房；U 必须来自「起始U位」而不是机架码里的数字 */
  function joinRackSlot(rack, slot) {
    rack = String(rack || "").replace(/[,，;；].*$/, "").trim();
    slot = String(slot || "").trim();
    if (!rack) return "";
    if (isHostname(rack) || /^cidcrp/i.test(rack)) return "";
    if (!slot) return rack;
    // 去掉已有 -Nu 尾
    rack = rack.replace(/-\d{1,2}u$/i, "");
    if (!/^\d{1,2}$/.test(slot)) {
      var sm = slot.match(/(\d{1,2})/);
      slot = sm ? sm[1] : "";
    }
    if (!slot) return rack;
    var n = parseInt(slot, 10);
    if (!(n >= 1 && n <= 48)) return rack;
    return rack + "-" + n + "u";
  }

  /** 取起始U位：标签后短距离内的 1–48，排除 3.07 这类版本号 */
  function takeStartU(text) {
    var t = String(text || "");
    var cands = [];

    function add(n, ctx) {
      n = parseInt(n, 10);
      if (!(n >= 1 && n <= 48)) return;
      // 版本号上下文：数字后面是 .数字
      if (ctx && /\d\.\d/.test(ctx)) return;
      cands.push(n);
    }

    // 1) 起始U位：18 / 起始U位 18（全角/半角冒号）
    var re = /起始\s*U\s*位\s*[:：]?\s*(\d{1,2})(?!\d)(?!\.\d)/gi;
    var m;
    while ((m = re.exec(t))) {
      add(m[1], t.slice(m.index, m.index + m[0].length + 3));
    }

    // 2) 每个「起始U位」出现点，向后看最多 60 字符（表格换行：标签与值靠近）
    re = /起始\s*U\s*位/gi;
    while ((m = re.exec(t))) {
      var slice = t.slice(m.index, m.index + 60);
      // 跳过「起始U位」本身后再找独立数字
      var rest = slice.replace(/^起始\s*U\s*位\s*[:：]?/i, "");
      var nm = rest.match(/^\s*(\d{1,2})(?!\d)(?!\.\d)/);
      if (nm) add(nm[1], rest.slice(0, 8));
      else {
        // 同行后面还有「操作」等时：找空白分隔的纯 U 数字
        nm = rest.match(/(?:^|[\s\|，,])(\d{1,2})(?!\d)(?!\.\d)(?=\s|$|[\|，,操作机架])/);
        if (nm) add(nm[1], rest);
      }
    }

    // 3) JSON / 接口字段
    re = /["'](?:startU|uPosition|startu|u_pos|beginU|uPos|start_u)["']\s*:\s*["']?(\d{1,2})/gi;
    while ((m = re.exec(t))) add(m[1], "");

    // 4) 我们自己 pushKV 的「起始U位：18」
    re = /起始U位\s*[:：]\s*(\d{1,2})(?!\d)/g;
    while ((m = re.exec(t))) add(m[1], "");

    // 5) 机架码后紧跟 U 位：…-B16 18 / JS-CZ-…-04  17
    re = /\b((?:CIDC[-_]?RP[-_]|GZHY|LF_|JS-|QD_|TJ_|BJ-|GD-|QH-|TZ_|\d?FIDCA)[A-Za-z0-9_\-]+)\s+(\d{1,2})(?!\d)(?!\.\d)/gi;
    while ((m = re.exec(t))) {
      add(m[2], m[0]);
    }

    // 6) 表头行含「起始U位」，下一数据行按列取值（空格分列，容错 BMC IP 两词）
    (function () {
      var lines = t.split(/\r?\n/);
      for (var i = 0; i < lines.length - 1; i++) {
        var head = lines[i];
        if (!/起始\s*U\s*位/i.test(head)) continue;
        if (!/(主机名|SN|机架|BMC|管理)/i.test(head)) continue;
        // 把「BMC IP」「管理 IP」收成一词再 split
        var norm = head
          .replace(/BMC\s*IP/gi, "BMCIP")
          .replace(/管理\s*IP/gi, "管理IP")
          .replace(/起始\s*U\s*位/gi, "起始U位");
        var headers = norm.trim().split(/\s+/);
        var uCol = -1;
        for (var h = 0; h < headers.length; h++) {
          if (headers[h] === "起始U位" || headers[h] === "U位") uCol = h;
        }
        if (uCol < 0) continue;
        var dataNorm = lines[i + 1]
          .replace(/BMC\s*IP/gi, "BMCIP")
          .trim();
        // 数据行：型号可能是 5288 V6 占两列，用正则抽独立 1-2 位数字 token
        var tokens = dataNorm.split(/\s+/);
        // 若列数对得上
        if (tokens.length === headers.length && /^\d{1,2}$/.test(tokens[uCol])) {
          add(tokens[uCol], "table-col");
          continue;
        }
        // 否则：找机架 token 后的下一个纯 U 数字
        for (var ti = 0; ti < tokens.length - 1; ti++) {
          if (/CIDC|GZHY|LF_|TZ_/i.test(tokens[ti]) && /^\d{1,2}$/.test(tokens[ti + 1])) {
            add(tokens[ti + 1], "after-rack");
          }
        }
      }
    })();

    if (!cands.length) return "";
    // 多个候选时：优先两位数 U（18），避免版本号里的 3、页码 1
    cands.sort(function (a, b) { return a - b; });
    // 去重
    var uniq = [];
    cands.forEach(function (n) {
      if (uniq.indexOf(n) < 0) uniq.push(n);
    });
    if (uniq.length === 1) return String(uniq[0]);
    // 优先 2 位数（10–48）
    var two = uniq.filter(function (n) { return n >= 10; });
    if (two.length) return String(two[two.length - 1]);
    // 否则取最大（18>3）
    return String(uniq[uniq.length - 1]);
  }

  function take(text, re) {
    var m = String(text || "").match(re);
    return m ? clean(m[1]) : "";
  }

  /** 全文正则 — CloudCMDB 最可靠 */
  function parseByRegex(text) {
    var r = emptyResult();
    var t = String(text || "");

    r.bmc =
      take(t, /BMC\s*IPv4\s*[:：]?\s*(\d{1,3}(?:\.\d{1,3}){3})/i) ||
      take(t, /BMC\s*IP(?!\s*v6)(?!\s*[:：]\s*生命周期)\s*[:：]?\s*(\d{1,3}(?:\.\d{1,3}){3})/i) ||
      take(t, /BMC\s*IPv4\s*[\r\n]+\s*(\d{1,3}(?:\.\d{1,3}){3})/i);

    r.mgmt =
      take(t, /管理\s*IPv4\s*[:：]?\s*(\d{1,3}(?:\.\d{1,3}){3})/i) ||
      take(t, /管理\s*IPv4\s*[\r\n]+\s*(\d{1,3}(?:\.\d{1,3}){3})/i) ||
      take(t, /管理\s*IP(?!\s*v6)\s*[:：]?\s*(\d{1,3}(?:\.\d{1,3}){3})/i);

    r.host =
      take(t, /主机名?\s*[:：]?\s*(cidcrp[A-Za-z0-9\-._]+)/i) ||
      take(t, /主机名?\s*[\r\n]+\s*(cidcrp[A-Za-z0-9\-._]+)/i) ||
      take(t, /\b(cidcrp[A-Za-z0-9\-._]+)\b/i);

    r.sn =
      take(t, /(?<!Agent)(?<!agent)\bSN\s*[:：]?\s*([0-9A-Za-z]{12,})/) ||
      take(t, /\bSN\s*[\r\n]+\s*([0-9A-Za-z]{12,})/) ||
      take(t, /物理机?SN\s*[:：]?\s*([0-9A-Za-z]{10,})/i) ||
      take(t, /serialNumberPM\s*[=:：]\s*([0-9A-Za-z]+)/i);

    // 无标签时的华为 SN 形态兜底
    if (!r.sn) {
      var snm = t.match(/\b(2106[0-9A-Za-z]{10,})\b/) || t.match(/\b([0-9]{6,}[A-Z]{2,}[0-9A-Za-z]{6,})\b/);
      if (snm && isSN(snm[1])) r.sn = snm[1];
    }
    // SN 排除 UUID
    if (r.sn && /^[0-9a-f]{8}-/i.test(r.sn)) r.sn = "";

    // 型号：5288 V6 / Atlas 900… / 主机类型后整段
    r.model = "";
    (function () {
      function cutModel(raw) {
        raw = clean(raw).replace(/[\u00a0\u3000]/g, " ").replace(/\s+/g, " ").trim();
        // 在中文区划/运维状态前截断
        raw = raw.split(
          /\s{2,}|生命周期|二级状态|纳管状态|Region|AZ\b|POD\b|OS类型|BIOS|集群|用途|数据创建|最后更新|描述|转维|可用区|华东|华南|华北|华中|西南|西北|东北|江苏|浙江|广东|北京|上海|山东|河北|四川|福建|湖北|湖南|河南|安徽|江西|重庆|天津|辽宁|吉林|黑龙江|陕西|山西|广西|云南|贵州|甘肃|海南|宁夏|青海|新疆|西藏|内蒙古/
        )[0].trim();
        // Atlas … Compute Node 为完整型号
        var am = raw.match(/^(Atlas\s*900(?:\s+RCK)?(?:\s+A\d)?(?:\s+Compute\s+Node)?)/i);
        if (am) return am[1].replace(/\s+/g, " ").trim();
        // 通用：型号遇到连续中文地名则停
        raw = raw.replace(/\s*[\u4e00-\u9fff].*$/, function (tail) {
          // 若整段都是中文（无英文型号）保留；否则去掉中文后缀
          return /[A-Za-z0-9]/.test(raw.slice(0, raw.length - tail.length + 1)) ? "" : tail;
        }).trim();
        return raw;
      }
      var mm =
        t.match(/主机类型\s*[:：]\s*([^\n\r]{2,80})/i) ||
        t.match(/主机类型\s*[:：]?\s+([^\n\r]{2,80})/i) ||
        t.match(/主机类型\s*[\r\n]+\s*([^\n\r]{2,80})/i) ||
        t.match(/服务器型号\s*[:：]?\s*([^\n\r]{2,80})/i);
      if (mm) {
        var raw = cutModel(mm[1]);
        // 华为数字型号
        var m2 = raw.match(
          /^((?:5288|2288|S920X?\d*|RS?\d{2,4}|R\d{3,4}G?\d*\w*|TaiShan[^,，]{0,40}|NW\d\w*|RH\d\w*|G\d{4}\w*|Atlas[^,，]{0,50}|Kunpeng[^,，]{0,40})(?:\s*V\d)?)/i
        );
        if (m2) r.model = m2[1].replace(/\s+/g, " ").trim();
        else if (raw && !isJunk(raw) && !isSN(raw) && raw.length >= 3 && raw.length <= 60) r.model = raw;
      }
      if (!r.model) {
        var m3 = t.match(
          /\b(5288\s*V6|2288\s*V[56]|S920X\w*|S920X00\w*|R521G\w*|RS221G\w*|Atlas\s*900[^,\n]{0,40})\b/i
        );
        if (m3) r.model = m3[1].replace(/\s+/g, " ").trim();
      }
      if (r.model) {
        r.model = cutModel(r.model);
        // 再清一次中文运维后缀
        r.model = r.model
          .replace(/\s*(华东|华南|华北|华中|西南|西北|东北)[\s\S]*$/u, "")
          .replace(/\s*(转维|可用区)[\s\S]*$/u, "")
          .replace(/\s+/g, " ")
          .trim();
      }
      if (r.model && (isJunk(r.model) || isSN(r.model) || /^(Region|AZ)/i.test(r.model))) r.model = "";
      if (r.model && r.model.length > 60) r.model = r.model.slice(0, 60);
    })();

    // 机房：CloudCMDB 数据中心+房间+机架+U / 完整码优选
    r.room = "";
    (function () {

      // FIDCA 位置码优先：2FIDCA-06_14 / 2FIDCA-06_14-2u
      var fidca = [];
      var rf = /\b(\d?FIDCA[-_][0-9A-Za-z]+(?:_[0-9A-Za-z]+)*)(?:\s*[-\s]\s*(\d{1,2}))?(?:u)?\b/gi;
      var mf;
      while ((mf = rf.exec(t))) {
        var base = mf[1];
        var u = mf[2] || "";
        if (u) fidca.push(base + "-" + u + "u");
        else if (/-\d{1,2}u$/i.test(base)) fidca.push(base);
        else fidca.push(base);
      }
      // 位置：2FIDCA-06_14-2u
      rf = /(?:位置|机房|机架)\s*[:：]?\s*(\d?FIDCA[^\s,，]{3,40})/gi;
      while ((mf = rf.exec(t))) fidca.push(mf[1].replace(/\s+/g, ""));
      if (fidca.length) {
        var slot0 = takeStartU(t);
        var bestF = "";
        fidca.forEach(function (c) {
          c = String(c).replace(/[,，].*$/, "").trim();
          if (slot0 && !/\d{1,2}u$/i.test(c)) c = c.replace(/-\d{1,2}u$/i, "") + "-" + slot0 + "u";
          // 保留下划线
          if (!bestF || c.length > bestF.length || (/\d{1,2}u$/i.test(c) && !/\d{1,2}u$/i.test(bestF))) bestF = c;
        });
        if (bestF) {
          r.room = bestF;
          return; // FIDCA 命中则不再拼 cidc-rp
        }
      }

      // JS-/TJ- 等长机架码优先：JS-CZ-YTYYDC-4-203-C-05（禁止只用数据中心名+U）
      var longJS = [];
      var rj, mj;
      // 完整已带 u
      rj = /\b((?:JS|TJ|QD|BJ|GD|QH|LF)-[A-Z0-9]+(?:-[A-Z0-9]+){2,10}-\d{1,2}u)\b/gi;
      while ((mj = rj.exec(t))) longJS.push(mj[1]);
      // 机架/位置标签后的长码
      rj = /(?:机架|位置|机房|rackCode|rackName)\s*[:：=]?\s*((?:JS|TJ|QD|BJ|GD|QH|LF)-[A-Z0-9]+(?:-[A-Z0-9_]+){2,12})/gi;
      while ((mj = rj.exec(t))) longJS.push(mj[1].replace(/\s+/g, ""));
      // 正文长码（至少 4 段：JS-CZ-YTYYDC-4-203-C-05）
      rj = /\b((?:JS|TJ|QD|BJ|GD|QH|LF)-[A-Z0-9]+(?:-[A-Z0-9]+){3,12})(?!-\d{1,2}u)\b/gi;
      while ((mj = rj.exec(t))) longJS.push(mj[1]);
      // 带 u 的长码再扫一遍宽松
      rj = /\b((?:JS|TJ|QD|BJ|GD|QH|LF)-[A-Za-z0-9]+(?:-[A-Za-z0-9]+){2,12}-\d{1,2}u)\b/gi;
      while ((mj = rj.exec(t))) longJS.push(mj[1]);

      if (longJS.length) {
        var slotJ = takeStartU(t);
        var bestJ = "";
        longJS.forEach(function (c) {
          c = String(c || "").replace(/[,，;；].*$/, "").trim();
          if (!c || c.split(/[-_]/).length < 4) return; // 拒绝 JS-CZ-YTYYDC 这种过短
          if (slotJ && !/\d{1,2}u$/i.test(c)) c = c.replace(/-\d{1,2}u$/i, "") + "-" + slotJ + "u";
          if (!bestJ || c.length > bestJ.length || (/\d{1,2}u$/i.test(c) && !/\d{1,2}u$/i.test(bestJ)))
            bestJ = c;
        });
        if (bestJ) {
          r.room = bestJ;
          return;
        }
      }

      function scoreRoom(s, host) {
        if (!s) return -1;
        var sc = s.length;
        // 与主机名资源池对齐：cidcrp12 → 优先含 12 / cidc-rp-12
        if (host) {
          var hm = host.match(/^cidcrp(\d+)/i);
          if (hm) {
            var num = hm[1];
            if (new RegExp("cidc[-_]?rp[-_]?" + num + "\\b", "i").test(s)) sc += 1000;
            else if (new RegExp("[-_]" + num + "[-_]", "i").test(s) || new RegExp("RP[-_]?" + num, "i").test(s)) sc += 500;
            else if (/^JS-|^TJ-|^QD-|^BJ-|^GD-|^QH-/i.test(s) && !new RegExp(num).test(s)) sc -= 300;
          }
        }
        if (/cidc[-_]?rp/i.test(s)) sc += 200;
        if (/IDC\d+/i.test(s)) sc += 80;
        if (/\d{1,2}u$/i.test(s)) sc += 50;
        if (/TKYDC|TKY02|ZLDC/i.test(s) && host && /^cidcrp12/i.test(host)) sc -= 100; // 易串台
        return sc;
      }

      // --- A. 结构化：数据中心 / 房间 / 机架 / 起始U位 ---
      var dc =
        take(t, /数据中心\s*[:：]?\s*((?:CIDC[-_]?RP[-_]?|cidc[-_]?rp[-_]?|JS-[A-Z0-9\-]+|TJ-[A-Z0-9\-]+)[A-Za-z0-9\-]*)/i) ||
        take(t, /数据中心\s*[\r\n]+\s*((?:CIDC[-_]?RP[-_]?|cidc[-_]?rp[-_]?|JS-[A-Z0-9\-]+)[A-Za-z0-9\-]*)/i) ||
        take(t, /\b((?:CIDC[-_]?RP[-_]?|cidc[-_]?rp[-_]?)?\d+[A-Za-z]?)\b/i) ||
        take(t, /\b(JS-[A-Z]{2,}-[A-Z0-9]+)\b/i);
      var roomCode =
        take(t, /房间\s*[:：]?\s*(IDC[A-Za-z0-9\-]+|\d{2,4}[A-Za-z]?|[A-Z0-9]+-\d{2,4}[A-Z0-9\-]*)/i) ||
        take(t, /房间\s*[\r\n]+\s*(IDC[A-Za-z0-9\-]+|\d{2,4}[A-Za-z]?)/i) ||
        take(t, /\b(IDC[A-Za-z0-9]{2,})\b/i);
      var rackOnly =
        take(t, /机架\s*[:：]?\s*([A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)/i) ||
        take(t, /机架\s*[\r\n]+\s*([A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)/i);
      // 机架若已是完整长码则不当作短柜号
      if (rackOnly && (/cidc|TKYDC|YTYYDC|ZLDC|FIDCA/i.test(rackOnly) || rackOnly.split('-').length >= 4) && rackOnly.length > 10) {
        // 完整机架码直接进候选
        longJS = longJS || [];
        try { longJS.push(rackOnly); } catch (e) {}
      } else if (rackOnly && rackOnly.length > 10 && /-/.test(rackOnly)) {
        try { if (typeof longJS !== 'undefined') longJS.push(rackOnly); } catch (e2) {}
      }
      var slot = takeStartU(t);

      // 短机架号：J08 / J-08 / 10-9 等（排除完整 cidc 码）
      var shortRack = "";
      if (rackOnly && !/cidc[-_]?rp/i.test(rackOnly) && rackOnly.length <= 12) {
        shortRack = rackOnly.replace(/\s+/g, "");
      }
      // 从正文再找柜号：常见 J08、B16
      if (!shortRack) {
        var sm = t.match(/\b机架\s*[:：]?\s*([A-Z]?\d{1,3}[A-Z]?(?:-[A-Z]?\d{1,3})?)\b/i);
        if (sm && !/cidc/i.test(sm[1])) shortRack = sm[1];
      }
      // 表格里 cidc-rp-12-IDC501-J08
      var composedFull = "";
      var mFull = t.match(
        /\b((?:cidc[-_]?rp|CIDC[-_]?RP)[-_]?\d+[A-Za-z]?(?:-IDC[A-Za-z0-9]+)?(?:-[A-Za-z0-9]+){0,6})(?:-(\d{1,2})u)?\b/i
      );
      // 更精确：cidc-rp-12-IDC501-J08-23u 或 无 u
      var allCidc = [];
      var reC = /\b((?:cidc[-_]?rp|CIDC[-_]?RP)[-_]?[A-Za-z0-9]+(?:-[A-Za-z0-9]+){1,8})(?:-(\d{1,2})u)?\b/gi;
      var mc;
      while ((mc = reC.exec(t))) {
        var base = mc[1];
        if (mc[2]) allCidc.push(base + "-" + mc[2] + "u");
        else if (/\d{1,2}u$/i.test(base)) allCidc.push(base);
        else allCidc.push(base);
      }
      // 也匹配整段已带 u
      reC = /\b((?:cidc[-_]?rp|CIDC[-_]?RP)[-_]?[A-Za-z0-9\-]+-\d{1,2}u)\b/gi;
      while ((mc = reC.exec(t))) allCidc.push(mc[1]);

      // 用 数据中心+房间+短机架+U 拼装（用户口径：cidc-rp-12-IDC501-J08-23u）
      if (dc || roomCode || shortRack) {
        var parts = [];
        if (dc) {
          var dcn = dc.replace(/_/g, "-");
          // 统一成 cidc-rp-12 风格（保留数字与可选字母后缀）
          var dm = dcn.match(/(?:cidc[-_]?rp|CIDC[-_]?RP)[-_]?(\d+[A-Za-z]?)/i);
          if (dm) parts.push("cidc-rp-" + dm[1]);
          else parts.push(dcn);
        }
        if (roomCode) parts.push(roomCode.replace(/^房间/, ""));
        if (shortRack) {
          // 避免 shortRack 已包含 IDC
          if (!/IDC/i.test(shortRack)) parts.push(shortRack);
          else if (!roomCode) parts.push(shortRack);
        }
        if (parts.length >= 2) {
          composedFull = parts.join("-");
          if (slot) composedFull = composedFull.replace(/-\d{1,2}u$/i, "") + "-" + slot + "u";
          allCidc.push(composedFull);
        }
      }

      // --- B. 其它完整候选（JS-WX-… 等）---
      var cands = allCidc.slice();
      var re, m;
      re = /(?:机房|位置|机架)\s*[:：]?\s*([A-Za-z0-9_\-][A-Za-z0-9_\-]{4,80})/gi;
      while ((m = re.exec(t))) cands.push(m[1].trim());
      re = /\b((?:GZHY|LF_|JS-|QD_|TJ_|BJ-|GD-|QH-|TZ_|\d?FIDCA)[A-Za-z0-9_\-]+(?:-\d{1,2}u)?)\b/gi;
      while ((m = re.exec(t))) cands.push(m[1]);
      // 2FIDCA-06_14 / 2FIDCA-06_14-2u
      re = /\b(\d?FIDCA[-_][A-Za-z0-9_\-]+(?:-\d{1,2}u)?)\b/gi;
      while ((m = re.exec(t))) cands.push(m[1]);
      re = /["'](?:rackCode|rackName|cabinetName|roomCode|dcCode)["']\s*:\s*["']([^"']+)["']/gi;
      while ((m = re.exec(t))) cands.push(m[1]);

      // 规范化候选：拼 U
      var host = r.host || "";
      var best = "";
      var bestScore = -1;
      cands.forEach(function (c) {
        c = String(c || "").replace(/[,，;；].*$/, "").replace(/\s+/g, "").trim();
        if (!c || c.length < 5) return;
        if (/^(Region|AZ|POD|操作)$/i.test(c)) return;
        // 若无 u 有 slot 则补 —— 短数据中心名（≤3 段）禁止直接 +U
        var segs = c.split(/[-_]/).filter(Boolean);
        if (slot && !/\d{1,2}u$/i.test(c) && !/^\d+$/.test(c)) {
          // JS-CZ-YTYYDC 只有 3 段，不能变成 JS-CZ-YTYYDC-35u
          // 完整机架至少 4 段：JS-CZ-YTYYDC-4-203-C-05
          if (segs.length >= 5 || (/cidc[-_]?rp/i.test(c) && segs.length >= 3) || /FIDCA/i.test(c)) {
            c = c.replace(/-\d{1,2}u$/i, "") + "-" + slot + "u";
            segs = c.split(/[-_]/).filter(Boolean);
          }
        }
        // 已是短码+U（如 JS-CZ-YTYYDC-35u，去 u 后 ≤3 段）直接丢弃
        var baseNoU = c.replace(/-\d{1,2}u$/i, "");
        var baseSegs = baseNoU.split(/[-_]/).filter(Boolean);
        if (/^(JS|TJ|QD|BJ|GD|QH)-/i.test(c) && baseSegs.length <= 3 && /\d{1,2}u$/i.test(c)) {
          return; // 垃圾短位置
        }
        var sc = scoreRoom(c, host);
        // 长 JS 机架加分
        if (/^(JS|TJ|QD|BJ|GD|QH)-/i.test(c) && baseSegs.length >= 5) sc += 600;
        if (/^(JS|TJ)-/i.test(c) && baseSegs.length >= 6 && /\d{1,2}u$/i.test(c)) sc += 300;
        // 拼装的 cidc-rp-12-IDC… 额外加分
        if (/^cidc-rp-\d+/i.test(c) && /IDC/i.test(c)) sc += 400;
        if (sc > bestScore) {
          bestScore = sc;
          best = c;
        }
      });

      if (best) r.room = best;
      else if (slot) {
        // 仅有 U
        var rk = "";
        m = t.match(/\b((?:cidc[-_]?rp|CIDC[-_]?RP)[-_]?[A-Za-z0-9\-]+)\b/i);
        if (m) rk = m[1];
        if (rk) r.room = joinRackSlot(rk, slot);
      }
    })();


    return r;
  }

  function parseExactTemplate(text) {
    var r = emptyResult();
    var hit = 0;
    var lines = String(text || "").split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line) continue;
      var m = line.match(/^(主机名?|物理机?SN|管理IP|BMC\s*IP|BMCIP|服务器型号|机型|机房|位置|故障描述|故障信息|故障)\s*[:：]\s*(.*)$/i);
      if (!m) continue;
      var lab = m[1].replace(/\s+/g, " ");
      var key = "fault";
      if (/^主机名?$/i.test(lab)) key = "host";
      else if (/SN/i.test(lab)) key = "sn";
      else if (/^管理IP$/i.test(lab)) key = "mgmt";
      else if (/BMC/i.test(lab)) key = "bmc";
      else if (/型号|机型/i.test(lab)) key = "model";
      else if (/机房|位置/i.test(lab)) key = "room";
      else key = "fault";
      var val = clean(m[2]);
      if (isJunk(val)) val = "";
      if (key === "mgmt" || key === "bmc") val = grabIPv4(val) || "";
      if (key === "host" && val) {
        var hm = val.match(/cidcrp[A-Za-z0-9\-._]+/i);
        val = hm ? hm[0] : isHostname(val) ? val : "";
      }
      if (key === "room" && val) val = normRoom(val);
      r[key] = val;
      hit++;
    }
    return hit >= 3 ? r : null;
  }

  function parseLinePairs(text) {
    var r = emptyResult();
    var lines = String(text || "")
      .replace(/\r/g, "\n")
      .split("\n")
      .map(function (l) {
        return l.replace(/\s+/g, " ").trim();
      })
      .filter(Boolean);

    var labelRe =
      /^(主机名?|SN|物理机?SN|管理IPv4|管理IP|BMC IPv4|BMC IP|主机类型|服务器型号|机型|机架|起始U位|位置|机房|故障描述|故障信息|故障)$/i;

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      // 忽略 Agent / 存储
      if (/^Agent|^存储IPv|^管理IPv6|^BMC IPv6/i.test(line)) continue;

      var m = line.match(/^(主机名?|SN|物理机?SN|管理IPv4|管理IP|BMC IPv4|BMC IP|主机类型|服务器型号|机架|起始U位|机房|故障)\s*[:：]\s*(.+)$/i);
      if (m) {
        assignPair(r, m[1], m[2]);
        continue;
      }
      m = line.match(/^(主机名|SN|管理IPv4|BMC IPv4|主机类型|机架|起始U位)\s+(\S.+)$/i);
      if (m) {
        assignPair(r, m[1], m[2].split(/\s{2,}/)[0]);
        continue;
      }
      var lab = line.replace(/[:：]\s*$/, "");
      if (!labelRe.test(lab)) continue;
      if (/^Agent|^存储/i.test(lab)) continue;
      var next = lines[i + 1];
      if (!next) continue;
      var nextLab = next.replace(/[:：]\s*$/, "");
      if (labelRe.test(nextLab)) continue;
      if (isJunk(next) || next === "--") continue;
      assignPair(r, lab, next);
    }

    // 机架+U
    if (!r.room) {
      var rack = "",
        slot = "";
      for (var j = 0; j < lines.length; j++) {
        if (/^机架$/i.test(lines[j].replace(/[:：]$/, "")) && lines[j + 1] && !labelRe.test(lines[j + 1]))
          rack = lines[j + 1];
        if (/^起始U位$/i.test(lines[j].replace(/[:：]$/, "")) && lines[j + 1]) slot = lines[j + 1].match(/\d+/)
          ? lines[j + 1].match(/\d+/)[0]
          : "";
        var rm = lines[j].match(/机架\s*[:：]?\s*(\S+)/i);
        if (rm) rack = rm[1];
        var sm = lines[j].match(/起始U位\s*[:：]?\s*(\d+)/i);
        if (sm) slot = sm[1];
      }
      if (rack && slot) r.room = normRoom(rack + "-" + slot);
      else if (rack) r.room = normRoom(rack);
    }
    return r;
  }

  function assignPair(r, lab, val) {
    lab = String(lab || "").replace(/[:：]\s*$/, "").trim();
    val = clean(val);
    if (isJunk(val) || val === "--") return;
    if (/^主机名$/i.test(lab)) {
      var hm = val.match(/cidcrp[A-Za-z0-9\-._]+/i);
      if (hm) r.host = hm[0];
    } else if (/^(SN|物理机SN)$/i.test(lab) && !/^Agent/i.test(lab)) {
      if (isSN(val)) r.sn = val;
    } else if (/管理IPv4|管理IP/i.test(lab) && !/v6/i.test(lab)) {
      var ip = grabIPv4(val);
      if (ip) r.mgmt = ip;
    } else if (/BMC\s*IPv4|BMC\s*IP/i.test(lab) && !/v6/i.test(lab)) {
      var ip2 = grabIPv4(val);
      if (ip2) r.bmc = ip2;
    } else if (/主机类型|服务器型号|机型|型号/i.test(lab)) {
      val = val.replace(/[\u00a0\u3000]/g, " ").replace(/\s+/g, " ").trim();
      val = val.split(/\s{2,}|生命周期|Region|纳管|OS类型/)[0].trim();
      if (val && !isJunk(val) && !/^(Region|AZ)/i.test(val) && (isModel(val) || (val.length >= 3 && val.length <= 60)))
        r.model = val;
    } else if (/机架|位置|机房/i.test(lab)) {
      r.room = val.replace(/[\u00a0\u3000]/g, " ").trim();
      if (!/\d{1,2}u$/i.test(r.room)) r.room = normRoom(r.room);
      else r.room = r.room.replace(/\s+/g, "");
    } else if (/起始U位/i.test(lab)) {
      var u = val.match(/^\s*(\d{1,2})\s*$/);
      if (u) {
        var n = parseInt(u[1], 10);
        if (n >= 1 && n <= 48) {
          if (r.room) r.room = joinRackSlot(r.room.replace(/-\d{1,2}u$/i, ""), String(n));
          else r._slot = String(n);
        }
      }
    } else if (/故障/i.test(lab)) {
      r.fault = val;
    }
  }

  function scrub(r) {
    var out = emptyResult();
    var k;
    for (k in out) {
      if (!Object.prototype.hasOwnProperty.call(out, k)) continue;
      var v = (r && r[k]) || "";
      if (isJunk(v)) v = "";
      if (k === "host" && v) {
        var hm = String(v).match(/cidcrp[A-Za-z0-9\-._]+/i);
        v = hm ? hm[0] : isHostname(v) ? v : "";
      }
      if ((k === "mgmt" || k === "bmc") && v) v = grabIPv4(v) || "";
      if (k === "sn" && v && !isSN(v)) v = "";
      if (k === "model" && v) {
        v = v.replace(/[\u00a0\u3000]/g, " ").replace(/\s+/g, " ").trim();
        var am = v.match(/^(Atlas\s*900(?:\s+RCK)?(?:\s+A\d)?(?:\s+Compute\s+Node)?)/i);
        if (am) v = am[1].replace(/\s+/g, " ").trim();
        else {
          // 去掉型号后的中文区划/状态
          var mi = v.search(/[\u4e00-\u9fff]/);
          if (mi > 3 && /[A-Za-z0-9]/.test(v.slice(0, mi))) v = v.slice(0, mi).trim();
        }
        v = v.replace(/\s*(转维|可用区|华东|华南|华北|华中)[\s\S]*$/u, "").trim();
      }
      if (k === "model" && v && isJunk(v)) v = "";
      out[k] = v;
    }
    return out;
  }

  function mergeLayers() {
    var out = emptyResult();
    for (var i = 0; i < arguments.length; i++) {
      var layer = arguments[i];
      if (!layer) continue;
      for (var k in out) {
        if (!out[k] && layer[k] && !isJunk(layer[k])) out[k] = layer[k];
      }
    }
    return out;
  }

  function parseText(text) {
    text = String(text || "").trim();
    if (!text) return emptyResult();

    var byRe = parseByRegex(text);
    var exact = parseExactTemplate(text);
    var pairs = parseLinePairs(text);

    // 优先级：regex（CloudCMDB 标签）> 行对 > 标准七行
    var r = mergeLayers(byRe, pairs, exact);

    // regex 的 IP/主机强制覆盖
    if (byRe.mgmt) r.mgmt = byRe.mgmt;
    if (byRe.bmc) r.bmc = byRe.bmc;
    if (byRe.host) r.host = byRe.host;
    if (byRe.sn) r.sn = byRe.sn;
    if (byRe.model) r.model = byRe.model;
    if (byRe.room) r.room = byRe.room;

    r = scrub(r);

    // 完整机房码候选：按主机名/cidc-rp 打分，禁止被更长的 JS-WX 串抢掉
    (function () {
      function scoreRoom(s, host) {
        if (!s) return -9999;
        var sc = Math.min(s.length, 40);
        if (host) {
          var hm = String(host).match(/^cidcrp(\d+)/i);
          if (hm) {
            var num = hm[1];
            if (new RegExp("cidc[-_]?rp[-_]?" + num + "\\b", "i").test(s)) sc += 2000;
            else if (new RegExp("(?:^|[-_])" + num + "(?:[-_]|$)", "i").test(s)) sc += 400;
            if (/^JS-|^TJ-|^QD-|^BJ-|^GD-|^QH-/i.test(s) && !new RegExp(num).test(s)) sc -= 800;
          }
        }
        if (/^cidc[-_]?rp/i.test(s)) sc += 500;
        if (/IDC\d+/i.test(s)) sc += 200;
        if (/\d{1,2}u$/i.test(s)) sc += 80;
        if (/TKYDC|TKY0|ZLDC|太科园/i.test(s)) sc -= 200;
        if (/FIDCA/i.test(s) && host && /cidcrp2006/i.test(host)) sc += 800;
        if (/FIDCA/i.test(s)) sc += 150;
        return sc;
      }
      var done = [];
      var re = /\b((?:cidc[-_]?rp|CIDC[-_]?RP|GZHY|LF_|JS-|QD_|TJ_|BJ-|GD-|QH-|TZ_|\d?FIDCA)[A-Za-z0-9_\-]*?-\d{1,2}u)\b/gi;
      var m;
      while ((m = re.exec(text))) done.push(m[1]);
      re = /(?:机房|位置)\s*[:：]?\s*([^\s,，]{6,80}?\d{1,2}u)/gi;
      while ((m = re.exec(text))) done.push(m[1].trim());
      // 当前 r.room 也参与竞选
      if (r.room) done.push(r.room);
      if (!done.length) return;
      var host = r.host || "";
      var best = "";
      var bestSc = -99999;
      done.forEach(function (c) {
        c = String(c || "").trim();
        if (!c) return;
        if (isHostname(c) || /^cidcrp/i.test(c)) return;
        if (c === host) return;
        var baseNoU = c.replace(/-\d{1,2}u$/i, "");
        var segs = baseNoU.split(/[-_]/).filter(Boolean);
        // 丢弃 JS-CZ-YTYYDC-35u 这类（去 u 后段数 ≤3）
        if (/^(JS|TJ|QD|BJ|GD|QH)-/i.test(c) && segs.length <= 3) return;
        var sc = scoreRoom(c, host);
        if (/FIDCA/i.test(c)) sc += 900;
        if (/^(JS|TJ)-/i.test(c) && segs.length >= 5) sc += 700;
        if (sc > bestSc) {
          bestSc = sc;
          best = c;
        }
      });
      if (best) r.room = best;
      else if (r.room && isHostname(r.room)) r.room = "";
    })();

    // 机房补 U：有机架码但无 -Nu 时，再取一次起始U位
    (function () {
      var slot = takeStartU(text);
      if (!slot) return;
      var room = r.room || "";
      if (room && /u$/i.test(room)) return;
      if (room) {
        r.room = joinRackSlot(room.replace(/-\d{1,2}u$/i, ""), slot);
        return;
      }
      var rk = "";
      var m = text.match(
        /\b((?:CIDC[-_]?RP[-_]|GZHY|LF_|JS-|QD_|TJ_|BJ-|GD-|QH-|TZ_)[A-Za-z0-9_\-]+)\b/i
      );
      if (m) rk = m[1];
      if (rk) r.room = joinRackSlot(rk, slot);
    })();

    // 裸 IP 归属（绝不把唯一 BMC 填进管理）
    (function () {
      var ips = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || [];
      var uniq = [];
      ips.forEach(function (ip) {
        if (uniq.indexOf(ip) < 0) uniq.push(ip);
      });
      if (!uniq.length) return;

      var hasBmcLabel = /BMC\s*IPv4|BMC\s*IP\s*[:：]/i.test(text);
      var hasMgmtLabel = /管理\s*IPv4\s*[:：]|管理\s*IP\s*[:：]/i.test(text);
      var mgmtEmpty =
        /管理\s*IPv4\s*[:：]?\s*(--|—|无|N\/A)?\s*($|[\r\n])/im.test(text) ||
        /管理\s*IP\s*[:：]\s*($|[\r\n])/im.test(text) ||
        !/管理\s*IPv4?\s*[:：]?\s*\d{1,3}\./i.test(text);

      // 已有 BMC、管理为空/-- → 保持管理空
      if (r.bmc && (!r.mgmt || r.mgmt === r.bmc) && (mgmtEmpty || hasBmcLabel)) {
        if (r.mgmt === r.bmc) r.mgmt = "";
        return;
      }

      if (!r.bmc && !r.mgmt) {
        if (uniq.length === 1) {
          if (hasBmcLabel || mgmtEmpty || /^172\./.test(uniq[0])) r.bmc = uniq[0];
          else r.mgmt = uniq[0];
        } else {
          r.mgmt = uniq[0];
          r.bmc = uniq[1];
          // 172 更像 BMC：对调
          if (/^172\./.test(uniq[0]) && /^10\./.test(uniq[1])) {
            r.bmc = uniq[0];
            r.mgmt = uniq[1];
          }
        }
      } else if (!r.bmc && r.mgmt) {
        for (var i = 0; i < uniq.length; i++) {
          if (uniq[i] !== r.mgmt) {
            r.bmc = uniq[i];
            break;
          }
        }
      } else if (r.bmc && !r.mgmt && !mgmtEmpty && hasMgmtLabel && uniq.length >= 2) {
        for (var j = 0; j < uniq.length; j++) {
          if (uniq[j] !== r.bmc) {
            r.mgmt = uniq[j];
            break;
          }
        }
      }

      if (r.mgmt && r.bmc && r.mgmt === r.bmc) r.mgmt = "";
    })();

    // 只有 BMC IPv4、完全没有管理IP/管理IPv4 时，才把唯一 IP 归 BMC
    if (/BMC\s*IPv4/i.test(text) && !/管理\s*IPv4/i.test(text) && !/管理\s*IP\s*[:：]/i.test(text)) {
      if (r.mgmt && !r.bmc) {
        r.bmc = r.mgmt;
        r.mgmt = "";
      }
    }
    var region = extractRegion(text);
    if (region) r.region = region;
    return r;
  }

  /** 区域：优先「华东-无锡Server业务」，其次正文里的大区-城市 / 省-市 */
  function extractRegion(text) {
    text = String(text || "").replace(/[－—–]/g, "-");
    if (!text) return "";

    function trimCity(city) {
      return String(city || "").replace(/(数据中心|数据|机房|可用区|资源池|服务器|业务|节点|园区).*$/, "");
    }

    var zones = "华东|华南|华北|华中|西南|西北|东北";
    var re = new RegExp("(" + zones + ")-([\\u4e00-\\u9fff]{2,8})", "g");
    var best = "";
    var bestScore = -1;
    var m;
    while ((m = re.exec(text))) {
      var city = trimCity(m[2]);
      if (city.length < 2 || city.length > 6) continue;
      var region = m[1] + "-" + city;
      var end = m.index + m[1].length + 1 + city.length;
      var after = text.slice(end, end + 16);
      var before = text.slice(Math.max(0, m.index - 10), m.index);
      var score = 10;
      if (/^Server业务/.test(after)) score += 200;
      if (/^_/.test(after) || /^Fusion/.test(after)) score += 40;
      if (/资源池|可用区|区域|大区|机房/.test(before)) score += 30;
      if (score > bestScore) {
        bestScore = score;
        best = region;
      }
    }
    if (best) return best;

    var provZone = {
      江苏: "华东", 浙江: "华东", 安徽: "华东", 上海: "华东", 福建: "华东", 江西: "华东", 山东: "华东",
      广东: "华南", 广西: "华南", 海南: "华南",
      北京: "华北", 天津: "华北", 河北: "华北", 山西: "华北", 内蒙古: "华北",
      河南: "华中", 湖北: "华中", 湖南: "华中",
      四川: "西南", 重庆: "西南", 云南: "西南", 贵州: "西南", 西藏: "西南",
      陕西: "西北", 甘肃: "西北", 宁夏: "西北", 青海: "西北", 新疆: "西北",
      辽宁: "东北", 吉林: "东北", 黑龙江: "东北",
    };
    var re2 = new RegExp("(" + Object.keys(provZone).join("|") + ")-([\\u4e00-\\u9fff]{2,4})", "g");
    var m2;
    var fb = "";
    var fbScore = -1;
    while ((m2 = re2.exec(text))) {
      var city2 = trimCity(m2[2]);
      if (city2.length < 2) continue;
      var score2 = 5;
      if (/数据中心|机房|园区/.test(text.slice(m2.index, m2.index + m2[0].length + 8))) score2 += 20;
      if (score2 > fbScore) {
        fbScore = score2;
        fb = provZone[m2[1]] + "-" + city2;
      }
    }
    if (fb) return fb;

    var cityZone = {
      无锡: "华东", 苏州: "华东", 南京: "华东", 杭州: "华东", 宁波: "华东", 合肥: "华东",
      济南: "华东", 青岛: "华东", 福州: "华东", 厦门: "华东", 南昌: "华东", 上海: "华东",
      广州: "华南", 深圳: "华南", 东莞: "华南", 佛山: "华南", 南宁: "华南", 海口: "华南",
      北京: "华北", 天津: "华北", 石家庄: "华北", 廊坊: "华北", 呼和浩特: "华北", 太原: "华北",
      郑州: "华中", 武汉: "华中", 长沙: "华中",
      成都: "西南", 重庆: "西南", 贵阳: "西南", 昆明: "西南",
      西安: "西北", 咸阳: "西北", 兰州: "西北", 西宁: "西北", 银川: "西北", 乌鲁木齐: "西北",
      沈阳: "东北", 大连: "东北", 长春: "东北", 哈尔滨: "东北",
    };
    var cities = Object.keys(cityZone).sort(function (a, b) {
      return b.length - a.length;
    });
    var m3 = text.match(new RegExp("(" + cities.join("|") + ")(?=数据中心|资源池|可用区)"));
    if (m3) return cityZone[m3[1]] + "-" + m3[1];
    return "";
  }

  function pushKV(chunks, k, v) {
    k = clean(String(k || "").replace(/[:：]\s*$/, ""));
    v = clean(String(v || "").replace(/\s+/g, " "));
    if (!k || !v || isJunk(k) || isJunk(v)) return;
    if (k.length > 40 || v.length > 400) return;
    if (k === v) return;
    chunks.push(k + "：" + v);
  }

  function extractPageText(doc) {
    doc = doc || document;
    var chunks = [];
    var seen = {};
    function add(line) {
      line = String(line || "").trim();
      if (!line || line.length < 2 || seen[line]) return;
      seen[line] = 1;
      chunks.push(line);
    }
    // 读取单元格，处理省略号截断（读 title / data-value / 内部 [title]）
    function readCell(el) {
      if (!el) return "";
      var v = (el.innerText || el.textContent || "").replace(/\s+/g, " ").trim();
      if (/\.\.\.$|…$/.test(v) || v.length < 6) {
        var attrs = ["title", "data-value", "data-text", "aria-label"];
        for (var ai = 0; ai < attrs.length; ai++) {
          var a = el.getAttribute && el.getAttribute(attrs[ai]);
          if (a && a.trim().length > v.length) { v = a.replace(/\s+/g, " ").trim(); break; }
        }
        if (/\.\.\.$|…$/.test(v) && el.querySelector) {
          var inner = el.querySelector("[title],[data-value]");
          if (inner) {
            var t = inner.getAttribute("title") || inner.getAttribute("data-value");
            if (t && t.trim().length > v.length) v = t.replace(/\s+/g, " ").trim();
          }
        }
      }
      return v;
    }
    // 选中
    try {
      var sel = (doc.getSelection && doc.getSelection().toString()) || "";
      if (sel && sel.trim().length > 8) add(sel.trim());
    } catch (e) {}

    // 正文 — 最重要
    var bodyText = "";
    try {
      bodyText = (doc.body && doc.body.innerText) || "";
    } catch (e) {}
    if (bodyText) add(bodyText.replace(/\n{3,}/g, "\n\n").slice(0, 50000));

    // 列表：表头 + 数据行（不把表头互配）
     // 列表：表头 + 数据行（不把表头互配）
    try {
      var tables = doc.querySelectorAll("table");
      for (var ti = 0; ti < tables.length; ti++) {
        var table = tables[ti];
        var headers = [];
        var ths = table.querySelectorAll(
          "thead th, thead td, .ant-table-thead th, .ant-table-thead td"
        );
        if (!ths.length) {
          var fr = table.querySelector("tr");
          if (fr) ths = fr.querySelectorAll("th, .ant-table-cell");
        }
        for (var hi = 0; hi < ths.length; hi++)
          headers.push((ths[hi].innerText || "").replace(/\s+/g, " ").trim());
        if (!headers.length) continue;
        var rows = table.querySelectorAll("tbody tr");
        if (!rows.length) rows = table.querySelectorAll("tr");
        for (var ri = 0; ri < rows.length; ri++) {
          var tr = rows[ri];
          if (tr.querySelector("th") && !tr.querySelector("td")) continue;
          var cells = tr.querySelectorAll("td");
          if (!cells.length) continue;

          var uIdx = -1, rackIdx = -1;
          for (var hi2 = 0; hi2 < headers.length; hi2++) {
            if (/起始\s*U\s*位|^U位$/i.test(headers[hi2])) uIdx = hi2;
            if (/^机架$|机架位置|rack|cabinet/i.test(headers[hi2])) rackIdx = hi2;
          }

          // ★ 机架+起始U位 同时命中 → 直接拼成完整"机房"
          if (uIdx >= 0 && rackIdx >= 0 && uIdx < cells.length && rackIdx < cells.length) {
            var rv = readCell(cells[rackIdx]);
            var uv = readCell(cells[uIdx]);
            var um = uv.match(/^\s*(\d{1,2})\s*u?\s*$/i);
            if (rv && um && rv !== "--") {
              var uNum = um[1];
              if (/cidc|FIDCA|IDC|JS-|TJ-|QD-|BJ-|GD-|QH-/i.test(rv)) {
                var merged = /-\d{1,2}u$/i.test(rv)
                  ? rv
                  : rv.replace(/-\d{1,2}u$/i, "") + "-" + uNum + "u";
                pushKV(chunks, "机房", merged);
              }
              pushKV(chunks, "机架", rv);
              pushKV(chunks, "起始U位", uNum);
            }
          } else {
            if (uIdx >= 0 && uIdx < cells.length) {
              var uv2 = readCell(cells[uIdx]);
              var um2 = uv2.match(/^(\d{1,2})(?:\s*u)?$/i);
              if (um2) pushKV(chunks, "起始U位", um2[1]);
            }
            if (rackIdx >= 0 && rackIdx < cells.length) {
              var rv2 = readCell(cells[rackIdx]);
              if (rv2 && rv2 !== "--") pushKV(chunks, "机架", rv2);
            }
          }

          for (var ci = 0; ci < cells.length && ci < headers.length; ci++) {
            var h = headers[ci];
            var c = readCell(cells[ci]);
            if (!h || !c || isJunk(c)) continue;
            if (/SN|主机名|管理|BMC|类型|机架|U位|位置|数据中心|房间/i.test(h))
              pushKV(chunks, h, c);
          }
        }
      }
    } catch (e) {}

    // 详情两列 th+td
    try {
      var trs = doc.querySelectorAll("tr");
      for (var i = 0; i < trs.length; i++) {
        var row = trs[i];
        var th = row.querySelector("th");
        var tds = row.querySelectorAll("td");
        if (th && tds.length === 1) pushKV(chunks, th.innerText, tds[0].innerText);
        else if (!th && tds.length === 2) {
          var k = (tds[0].innerText || "").trim();
          if (k.length <= 16 && /主机名|SN|管理|BMC|类型|机架|U位|IP/i.test(k))
            pushKV(chunks, k, tds[1].innerText);
        }
      }
    } catch (e) {}

    // 短标签节点
    try {
      var known = /^(主机名|SN|物理机SN|管理IPv4|管理IP|BMC IPv4|BMC IP|主机类型|机架|起始U位|机房|数据中心|房间|位置)$/i;
      var nodes = doc.querySelectorAll("span, div, label, p");
      for (var ni = 0; ni < nodes.length; ni++) {
        var el = nodes[ni];
        if (el.children && el.children.length > 2) continue;
        var raw = (el.textContent || "").replace(/\s+/g, " ").trim();
        if (!raw || raw.length > 20) continue;
        var lab = raw.replace(/[:：]\s*$/, "");
        if (!known.test(lab)) continue;
        var val = "";
        if (el.nextElementSibling) val = (el.nextElementSibling.innerText || "").replace(/\s+/g, " ").trim();
        if (!val && el.parentElement) {
          var kids = el.parentElement.children;
          for (var ki = 0; ki < kids.length; ki++) {
            if (kids[ki] === el && kids[ki + 1]) {
              val = (kids[ki + 1].innerText || "").replace(/\s+/g, " ").trim();
              break;
            }
          }
        }
        if (val && !isJunk(val) && val !== lab) pushKV(chunks, lab, val);
      }
    } catch (e) {}

    // input 只要真实 value
    try {
      var inputs = doc.querySelectorAll("input:not([type=password]):not([type=hidden]), textarea");
      for (var ii = 0; ii < inputs.length; ii++) {
        var inp = inputs[ii];
        var val = String(inp.value || "").trim();
        var ph = String(inp.placeholder || "").trim();
        if (!val || val === ph || isJunk(val)) continue;
        var name = (inp.getAttribute("aria-label") || inp.name || inp.id || "").trim();
        if (name && !isJunk(name)) pushKV(chunks, name, val);
      }
    } catch (e) {}

    // HTML 直抽
    try {
      var html = ((doc.documentElement && doc.documentElement.innerHTML) || "").slice(0, 500000);
      var mg = html.match(/管理IPv4[^0-9]{0,80}(\d{1,3}(?:\.\d{1,3}){3})/);
      if (mg) pushKV(chunks, "管理IPv4", mg[1]);
      var bm = html.match(/BMC\s*IPv4[^0-9]{0,80}(\d{1,3}(?:\.\d{1,3}){3})/i);
      if (bm) pushKV(chunks, "BMC IPv4", bm[1]);
      var hn = html.match(/cidcrp[a-z0-9\-._]+/i);
      if (hn) pushKV(chunks, "主机名", hn[0]);
      var sn = html.match(/2106[0-9A-Za-z]{10,}/);
      if (sn) pushKV(chunks, "SN", sn[0]);
      var md = html.match(/主机类型[^S5288R]{0,40}((?:5288|2288|S920|RS?\d{2,4})[\s\u00a0]*V?\d*)/i);
      if (md) pushKV(chunks, "主机类型", md[1]);
      var md2 = html.match(/\b(5288[\s\u00a0]*V6|2288[\s\u00a0]*V[56]|S920X[A-Z0-9]*)\b/i);
      if (md2) pushKV(chunks, "主机类型", md2[1]);
      // 机架：取最长 CIDC-RP-...
      var rackBest = "";
      var rr = html.match(/CIDC[-_]?RP[-_][A-Za-z0-9]+(?:-[A-Za-z0-9]+)*/gi) || [];
      for (var ri = 0; ri < rr.length; ri++) {
        if (rr[ri].length > rackBest.length) rackBest = rr[ri];
      }
      if (rackBest) pushKV(chunks, "机架", rackBest);
      var uk = html.match(/起始\s*U\s*位\s*[:：]?\s*(\d{1,2})(?!\d)/i);
      if (uk) pushKV(chunks, "起始U位", uk[1]);
      // JSON 字段
      var jk = [
        ["rackCode", "机架"],
        ["rackName", "机架"],
        ["cabinetName", "机架"],
        ["startU", "起始U位"],
        ["uPosition", "起始U位"],
        ["hostType", "主机类型"],
        ["serverModel", "主机类型"],
        ["model", "主机类型"],
      ];
      for (var ji = 0; ji < jk.length; ji++) {
        var key = jk[ji][0], lab = jk[ji][1];
        var re = new RegExp('["\']' + key + '["\']\s*:\s*["\']([^"\']+)["\']', "i");
        var jm = html.match(re);
        if (jm && jm[1] && jm[1] !== "null" && jm[1] !== "--") pushKV(chunks, lab, jm[1]);
      }
    } catch (e) {}

    return chunks.join("\n");
  }

  function scoreData(r) {
    if (!r) return 0;
    var s = 0;
    if (r.host) s += 3;
    if (r.sn) s += 3;
    if (r.bmc) s += 2;
    if (r.mgmt) s += 2;
    if (r.model) s += 1;
    if (r.room) s += 2;
    if (r.fault) s += 1;
    return s;
  }

  function formatTemplate(r) {
    r = r || emptyResult();
    return FIELDS.map(function (f) {
      return f.label + (r[f.key] || "");
    }).join("\n");
  }

  function formatTitle(r) {
    r = r || emptyResult();
    var region = String(r.region || "").replace(/\s+/g, "");
    var host = String(r.host || "").trim();
    return "【合营云】" + region + "Server业务" + host + "硬件故障";
  }

  function formatBundle(r) {
    return formatTitle(r) + "\n\n" + formatTemplate(r);
  }

  function extractAndParse(doc) {
    doc = doc || document;
    var text = extractPageText(doc);
    var body = text;
    try {
      body = ((doc.body && doc.body.innerText) || "") + "\n" + text;
    } catch (e) {}
    var data = parseText(body);
    return {
      text: text.slice(0, 30000),
      data: data,
      formatted: formatTemplate(data),
      titleLine: formatTitle(data),
      bundle: formatBundle(data),
      score: scoreData(data),
      href: typeof location !== "undefined" ? location.href : "",
      title: typeof document !== "undefined" ? document.title : "",
    };
  }

  root.ServerInfoParse = {
    FIELDS: FIELDS,
    emptyResult: emptyResult,
    parseText: parseText,
    extractPageText: extractPageText,
    extractAndParse: extractAndParse,
    scoreData: scoreData,
    formatTemplate: formatTemplate,
    formatTitle: formatTitle,
    formatBundle: formatBundle,
    extractRegion: extractRegion,
    grabIPv4: grabIPv4,
    normRoom: normRoom,
  };
})(typeof window !== "undefined" ? window : globalThis);
