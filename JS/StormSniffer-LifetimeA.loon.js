/* Storm Sniffer 2.2.1 — Loon response script
 *
 * 匹配: ^https:\/\/api\.x-storm\.com\/app\/user-profile\/?(?:\?|$)
 * 类型: http-response, 需要响应体
 *
 * 从请求头 uid 派生设备密钥，解密会员资料，改写会员字段与功能权限数组
 * 后用同一密钥重新加密。纯 JS 实现 MD5 / Base64 / XXTEA，无远程依赖。
 *
 * Loon API: $request / $response / $done
 *   与 Shadowrocket 的差异：Loon 的 $response.body 可能是字符串或对象，
 *   且 $done 接收 {body: ...} 时不再携带 status/headers（保持原样）。
 */
var STMembership = (function () {
  'use strict';
  var TABLE = [
    'faac7a39c9c7229eecd16006fc62aac7', 'f399eafeac62027f8f53610fb5c203cd',
    'd2a2c4c21739e5019d813126ddecd334', '7a521eb7a0866e77cd888d657d83c81d',
    '1de4141bada32b7cbd05a71999ff178b', '9a77418c9e76ee08979de28949e35c50',
    '05bee540c570cd0009eca833e3a3b80d', 'f40498e595de7de0294eb2c38a540030',
    'fcb27275f3c252bdf02b74cd584bf82d', '1b8432f7fdd07811df057da374db25d9',
    '7148f83492231c07c85cfa8d9853c1ba', '0031693f7be88ca8c1f68044c31e41ae',
    'd9bd867f90a3d2a3e32c09b449aeb2c7', '271b91346fca60accfa76b8f43ede04d',
    'f06851ff186c8d054206849352e9bca1', '70c84564bcbcc0b95ed2b00ad6fec3b1'
  ];
  var B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  var DELTA = 0x9e3779b9;

  /* ---------- 字节与编码 ---------- */

  function utf8(s) {
    var esc = encodeURIComponent(s), out = [];
    for (var i = 0; i < esc.length; i++) {
      if (esc.charAt(i) === '%') {
        out.push(parseInt(esc.substr(i + 1, 2), 16));
        i += 2;
      } else {
        out.push(esc.charCodeAt(i));
      }
    }
    return out;
  }

  function text(bytes) {
    var parts = [];
    for (var i = 0; i < bytes.length; i++) {
      parts.push('%' + ('0' + (bytes[i] & 255).toString(16)).slice(-2));
    }
    return decodeURIComponent(parts.join(''));
  }

  function hex(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += ('0' + bytes[i].toString(16)).slice(-2);
    return s;
  }

  function unhex(s) {
    var out = [];
    for (var i = 0; i < s.length; i += 2) out.push(parseInt(s.substr(i, 2), 16));
    return out;
  }

  function words(bytes) {
    var out = [];
    for (var i = 0; i < bytes.length; i++) {
      out[i >>> 2] = ((out[i >>> 2] || 0) | (bytes[i] << ((i & 3) * 8))) >>> 0;
    }
    return out;
  }

  function bytes(v) {
    var out = [];
    for (var i = 0; i < v.length * 4; i++) out.push((v[i >>> 2] >>> ((i & 3) * 8)) & 255);
    return out;
  }

  /* ---------- MD5 ---------- */

  var MD5_SHIFTS = [7,12,17,22,5,9,14,20,4,11,16,23,6,10,15,21];
  var MD5_K = null;

  function md5K() {
    if (MD5_K) return MD5_K;
    MD5_K = [];
    for (var i = 0; i < 64; i++) MD5_K.push(Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296));
    return MD5_K;
  }

  function md5(s) {
    var b = utf8(s), bitLen = b.length * 8;
    b.push(128);
    while ((b.length & 63) !== 56) b.push(0);
    for (var j = 0; j < 8; j++) b.push(Math.floor(bitLen / Math.pow(256, j)) & 255);

    var v = words(b), K = md5K();
    var a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

    for (var off = 0; off < v.length; off += 16) {
      var a = a0, bb = b0, c = c0, d = d0;
      for (var i = 0; i < 64; i++) {
        var f, g;
        if (i < 16)      { f = (bb & c) | (~bb & d);      g = i; }
        else if (i < 32) { f = (d & bb) | (~d & c);       g = (5 * i + 1) & 15; }
        else if (i < 48) { f = bb ^ c ^ d;                g = (3 * i + 5) & 15; }
        else             { f = c ^ (bb | ~d);             g = (7 * i) & 15; }

        var x = (a + f + K[i] + v[off + g]) >>> 0;
        var sh = MD5_SHIFTS[(i >>> 4) * 4 + (i & 3)];
        a = d; d = c; c = bb;
        bb = (bb + ((x << sh) | (x >>> (32 - sh)))) >>> 0;
      }
      a0 = (a0 + a) >>> 0;
      b0 = (b0 + bb) >>> 0;
      c0 = (c0 + c) >>> 0;
      d0 = (d0 + d) >>> 0;
    }
    return hex(bytes([a0, b0, c0, d0]));
  }

  /* ---------- 密钥派生（对应主程序 0x1000e64c0） ---------- */

  function deriveKey(identity) {
    if (!identity) throw new Error('请求头缺少 uid');
    var h = md5(identity + identity.charAt(0));
    var sel = parseInt(h.slice(0, 2), 16) ^ parseInt(h.slice(-2), 16);
    if (!sel) sel = (parseInt(h.charAt(h.length - 3), 16) << 4) | 1;
    var q = sel >>> 4;
    var mid = q ? h.slice(q, h.length - q) : h;
    var mixed = h.slice(0, q) + (q ? h.slice(-q) : '') + mid.split('').reverse().join('');
    var x = unhex(mixed), t = unhex(TABLE[sel & 15]);
    return hex(x.map(function (ch, i) { return ch ^ t[i]; })) + '==';
  }

  /* ---------- Base64 ---------- */

  function b64decode(s) {
    s = String(s).replace(/\s+/g, '');
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s)) {
      throw new Error('Base64 格式非法');
    }
    var out = [];
    for (var i = 0; i < s.length; i += 4) {
      var x = (B64.indexOf(s.charAt(i)) << 18) |
              (B64.indexOf(s.charAt(i + 1)) << 12) |
              ((B64.indexOf(s.charAt(i + 2)) & 63) << 6) |
              (B64.indexOf(s.charAt(i + 3)) & 63);
      out.push((x >>> 16) & 255);
      if (s.charAt(i + 2) !== '=') out.push((x >>> 8) & 255);
      if (s.charAt(i + 3) !== '=') out.push(x & 255);
    }
    return out;
  }

  function b64encode(b) {
    var s = '';
    for (var i = 0; i < b.length; i += 3) {
      var x = (b[i] << 16) | ((b[i + 1] || 0) << 8) | (b[i + 2] || 0);
      s += B64.charAt((x >>> 18) & 63) + B64.charAt((x >>> 12) & 63);
      s += i + 1 < b.length ? B64.charAt((x >>> 6) & 63) : '=';
      s += i + 2 < b.length ? B64.charAt(x & 63) : '=';
    }
    return s;
  }

  /* ---------- XXTEA ---------- */

  function mix(z, y, sum, k, p, e) {
    return ((((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z))) >>> 0;
  }

  function keyWords(key) {
    var b = utf8(String(key)).slice(0, 16);
    while (b.length < 16) b.push(0);
    return words(b);
  }

  function xxteaDecryptBytes(b, key) {
    if (b.length < 8 || (b.length & 3)) throw new Error('密文长度非法');
    var v = words(b), k = keyWords(key);
    var n = v.length - 1, y = v[0], z;
    var sum = (Math.floor(6 + 52 / v.length) * DELTA) >>> 0;
    while (sum) {
      var e = (sum >>> 2) & 3;
      for (var p = n; p > 0; p--) {
        z = v[p - 1];
        y = v[p] = (v[p] - mix(z, y, sum, k, p, e)) >>> 0;
      }
      z = v[n];
      y = v[0] = (v[0] - mix(z, y, sum, k, 0, e)) >>> 0;
      sum = (sum - DELTA) >>> 0;
    }
    var len = v[n], cap = n * 4;
    if (len < cap - 3 || len > cap) throw new Error('密钥不匹配（长度校验失败）');
    return bytes(v).slice(0, len);
  }

  function xxteaEncryptBytes(b, key) {
    var v = words(b), k = keyWords(key);
    v.push(b.length);
    var n = v.length - 1, z = v[n], sum = 0;
    var rounds = Math.floor(6 + 52 / v.length);
    for (var r = 0; r < rounds; r++) {
      sum = (sum + DELTA) >>> 0;
      var e = (sum >>> 2) & 3;
      for (var p = 0; p < n; p++) {
        var y = v[p + 1];
        z = v[p] = (v[p] + mix(z, y, sum, k, p, e)) >>> 0;
      }
      y = v[0];
      z = v[n] = (v[n] + mix(z, y, sum, k, n, e)) >>> 0;
    }
    return bytes(v);
  }

  function decrypt(cipher, key) {
    return text(xxteaDecryptBytes(b64decode(cipher), key));
  }

  function encrypt(plain, key) {
    return b64encode(xxteaEncryptBytes(utf8(plain), key));
  }

  /* ---------- 请求辅助 ---------- */

  function header(headers, name) {
    if (!headers) return '';
    var keys = Object.keys(headers);
    for (var i = 0; i < keys.length; i++) {
      if (keys[i].toLowerCase() === name) return String(headers[keys[i]]);
    }
    return '';
  }

  function identities(uid) {
    var list = [uid, uid.toUpperCase()];
    var compact = uid.replace(/-/g, '');
    if (/^[a-f0-9]{32}$/i.test(compact)) {
      var dashed = compact.replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
      list.push(compact.toLowerCase(), compact.toUpperCase(),
                dashed.toLowerCase(), dashed.toUpperCase());
    }
    var out = [];
    for (var i = 0; i < list.length; i++) {
      if (list[i] && out.indexOf(list[i]) === -1) out.push(list[i]);
    }
    return out;
  }

  /* ---------- 目标会员档位 ---------- */

  // 商品列表解密结果：member_type 2 = 终身版 A (ST.Sniffer.FullUnlock.101)
  var TARGET = {
    isVip: 1,
    member_type: 2,
    member_title: '终身版 A',
    expire_on: '永久有效'
  };
  // 客户端入口检查：脚本 4，重放 5。合并而非覆盖，保留原有及未知编号。
  var REQUIRED_FUNCTIONS = [1, 2, 3, 4, 5];

  function applyMembership(profile) {
    for (var k in TARGET) {
      if (Object.prototype.hasOwnProperty.call(TARGET, k)) profile[k] = TARGET[k];
    }
    var perms = Array.isArray(profile.function_list) ? profile.function_list.slice() : [];
    for (var i = 0; i < REQUIRED_FUNCTIONS.length; i++) {
      if (perms.indexOf(REQUIRED_FUNCTIONS[i]) === -1) perms.push(REQUIRED_FUNCTIONS[i]);
    }
    profile.function_list = perms;
    return profile;
  }

  /* ---------- 主体 ---------- */

  var URL_RE = /^https:\/\/api\.x-storm\.com\/app\/user-profile\/?(?:\?|$)/i;

  function rewrite(request, responseBody) {
    if (!URL_RE.test((request && request.url) || '')) return null;

    var raw = responseBody;
    if (raw && typeof raw === 'object') raw = JSON.stringify(raw);
    if (typeof raw !== 'string' || !raw) return null;

    var envelope = JSON.parse(raw);
    if (!envelope || Number(envelope.code) !== 200) return null;
    if (typeof envelope.data !== 'string') return null;

    var candidates = identities(header(request.headers, 'uid'));
    var key = null, profile = null;

    for (var i = 0; i < candidates.length; i++) {
      try {
        var attempt = deriveKey(candidates[i]);
        var parsed = JSON.parse(decrypt(envelope.data, attempt));
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) continue;
        if (!Object.prototype.hasOwnProperty.call(parsed, 'member_type')) continue;
        profile = parsed;
        key = attempt;
        break;
      } catch (e) { /* 换一种 uid 形式重试 */ }
    }
    if (!profile) throw new Error('uid 的任何形式都无法解出会员资料');

    applyMembership(profile);
    envelope.data = encrypt(JSON.stringify(profile), key);
    return JSON.stringify(envelope);
  }

  return {
    rewrite: rewrite,
    md5: md5,
    deriveKey: deriveKey,
    decrypt: decrypt,
    encrypt: encrypt,
    applyMembership: applyMembership,
    target: TARGET,
    requiredFunctions: REQUIRED_FUNCTIONS
  };
}());

/* ---------- Loon 入口 ---------- */

(function () {
  var tag = '[StormSniffer]';
  try {
    if (typeof $request === 'undefined' || typeof $response === 'undefined') {
      throw new Error('缺少 $request / $response，请确认插件类型为 http-response');
    }
    var body = $response.body;
    var changed = STMembership.rewrite($request, body);
    if (!changed) {
      console.log(tag + ' 未匹配目标接口或响应无需改写，保持原样');
      $done({});
      return;
    }
    console.log(tag + ' 已改写会员资料：终身版 A；功能权限已补齐 1,2,3,4,5');
    $done({ body: changed });
  } catch (e) {
    console.log(tag + ' 保留原响应：' + (e && e.message ? e.message : e));
    $done({});
  }
}());
