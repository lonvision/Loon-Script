/* NB Pro 3.9.1 — Loon response script
 * Match: ^https?:\/\/nbtool8\.com(?::9527)?\/nb\/app\/?(?:\?|$)
 * Requires response body. 纯 JS 实现 AES-128-CBC / PKCS#7，无远程依赖。
 * 只改配置响应的三个字段：adVIPForever / adFree / adFreeTime。
 * 修改的是本机收到的响应，不改变服务器账户权益。
 *
 * 与 Shadowrocket 版的差异（仅适配层，算法未改）：
 *   1. $response.body 可能是 String / Uint8Array / Object，统一归一化后再处理
 *   2. headers 为空时不再返回 headers:{}（Loon 里空对象会清空响应头）
 */
(function () {
  'use strict';
  var TAG = '[NB VIP local] ';
  var URL_PATTERN = /^https?:\/\/nbtool8\.com(?::9527)?\/nb\/app\/?(?:\?|$)/i;
  var KEY = ascii('5cd8b43a5f01927b');
  var IV = ascii('063ad3f8efc1658d');
  var B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  var S = [], IS = [];
  var expanded;

  function ascii(s) {
    var a = [], i;
    for (i = 0; i < s.length; i++) a.push(s.charCodeAt(i));
    return a;
  }
  function mul(a, b) {
    var r = 0;
    while (b) {
      if (b & 1) r ^= a;
      a = ((a << 1) ^ ((a & 128) ? 283 : 0)) & 255;
      b >>>= 1;
    }
    return r;
  }
  function pow(a, n) {
    var r = 1;
    while (n) {
      if (n & 1) r = mul(r, a);
      a = mul(a, a); n >>>= 1;
    }
    return r;
  }
  function rot(x, n) { return ((x << n) | (x >>> (8 - n))) & 255; }
  function initAES() {
    var i, x, y, k = KEY.slice(), t, rcon = 1;
    for (i = 0; i < 256; i++) {
      x = i ? pow(i, 254) : 0;
      y = x ^ rot(x, 1) ^ rot(x, 2) ^ rot(x, 3) ^ rot(x, 4) ^ 99;
      S[i] = y; IS[y] = i;
    }
    for (i = 16; i < 176; i += 4) {
      t = k.slice(i - 4, i);
      if (i % 16 === 0) {
        t = [S[t[1]] ^ rcon, S[t[2]], S[t[3]], S[t[0]]];
        rcon = mul(rcon, 2);
      }
      k.push(k[i - 16] ^ t[0], k[i - 15] ^ t[1], k[i - 14] ^ t[2], k[i - 13] ^ t[3]);
    }
    expanded = k;
  }
  function addKey(s, round) {
    for (var i = 0; i < 16; i++) s[i] ^= expanded[round * 16 + i];
  }
  function sub(s, inverse) {
    var box = inverse ? IS : S;
    for (var i = 0; i < 16; i++) s[i] = box[s[i]];
  }
  function shift(s, inverse) {
    var copy = s.slice(), r, c;
    for (r = 0; r < 4; r++) for (c = 0; c < 4; c++) {
      s[4 * c + r] = copy[4 * ((c + (inverse ? 4 - r : r)) % 4) + r];
    }
  }
  function mix(s, inverse) {
    var matrix = inverse ? [14, 11, 13, 9] : [2, 3, 1, 1];
    var c, r, j, col, v;
    for (c = 0; c < 4; c++) {
      col = s.slice(c * 4, c * 4 + 4);
      for (r = 0; r < 4; r++) {
        v = 0;
        for (j = 0; j < 4; j++) v ^= mul(col[j], matrix[(j - r + 4) % 4]);
        s[c * 4 + r] = v;
      }
    }
  }
  function block(input, inverse) {
    var s = input.slice(), round;
    if (inverse) {
      addKey(s, 10);
      for (round = 9; round > 0; round--) {
        shift(s, true); sub(s, true); addKey(s, round); mix(s, true);
      }
      shift(s, true); sub(s, true); addKey(s, 0);
    } else {
      addKey(s, 0);
      for (round = 1; round < 10; round++) {
        sub(s, false); shift(s, false); mix(s, false); addKey(s, round);
      }
      sub(s, false); shift(s, false); addKey(s, 10);
    }
    return s;
  }
  function decodeBase64(text) {
    var s = text.replace(/\s/g, ''), out = [], i, a, b, c, d;
    if (!s.length || s.length % 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s)) {
      throw new Error('Invalid Base64 body');
    }
    for (i = 0; i < s.length; i += 4) {
      a = B64.indexOf(s.charAt(i)); b = B64.indexOf(s.charAt(i + 1));
      c = B64.indexOf(s.charAt(i + 2)); d = B64.indexOf(s.charAt(i + 3));
      out.push((a << 2) | (b >>> 4));
      if (c >= 0) out.push(((b & 15) << 4) | (c >>> 2));
      if (d >= 0) out.push(((c & 3) << 6) | d);
    }
    return out;
  }
  function encodeBase64(bytes) {
    var out = '', i, a, b, c;
    for (i = 0; i < bytes.length; i += 3) {
      a = bytes[i]; b = bytes[i + 1]; c = bytes[i + 2];
      out += B64.charAt(a >>> 2) + B64.charAt(((a & 3) << 4) | ((b || 0) >>> 4));
      out += i + 1 < bytes.length ? B64.charAt(((b & 15) << 2) | ((c || 0) >>> 6)) : '=';
      out += i + 2 < bytes.length ? B64.charAt(c & 63) : '=';
    }
    return out;
  }
  function utf8Decode(bytes) {
    var s = '', i;
    for (i = 0; i < bytes.length; i++) s += '%' + ('0' + bytes[i].toString(16)).slice(-2);
    return decodeURIComponent(s);
  }
  function utf8Encode(text) {
    var s = encodeURIComponent(text), out = [], i;
    for (i = 0; i < s.length; i++) {
      if (s.charAt(i) === '%') { out.push(parseInt(s.substr(i + 1, 2), 16)); i += 2; }
      else out.push(s.charCodeAt(i));
    }
    return out;
  }
  function decrypt(text) {
    var data = decodeBase64(text), prev = IV.slice(), out = [], chunk, p, i, j, n;
    if (data.length % 16) throw new Error('Ciphertext length is not a multiple of 16');
    for (i = 0; i < data.length; i += 16) {
      chunk = data.slice(i, i + 16); p = block(chunk, true);
      for (j = 0; j < 16; j++) out.push(p[j] ^ prev[j]);
      prev = chunk;
    }
    n = out[out.length - 1];
    if (n < 1 || n > 16) throw new Error('Invalid PKCS7 padding');
    for (i = out.length - n; i < out.length; i++) if (out[i] !== n) throw new Error('Invalid PKCS7 padding');
    return utf8Decode(out.slice(0, out.length - n));
  }
  function encrypt(text) {
    var data = utf8Encode(text), n = 16 - data.length % 16;
    var out = [], prev = IV.slice(), chunk, i, j;
    for (i = 0; i < n; i++) data.push(n);
    for (i = 0; i < data.length; i += 16) {
      chunk = data.slice(i, i + 16);
      for (j = 0; j < 16; j++) chunk[j] ^= prev[j];
      prev = block(chunk, false); out = out.concat(prev);
    }
    return encodeBase64(out);
  }
  function log(s) { if (typeof console !== 'undefined' && console.log) console.log(TAG + s); }

  /* 把 Loon 可能给出的各种 body 类型统一成字符串。
   * String   -> 原样
   * Uint8Array / byte array -> 按字节转 ASCII（Base64 正文本身就是 ASCII）
   * 其它     -> 空串，让上层走"保持原响应"分支
   */
  function toText(body) {
    if (typeof body === 'string') return body;
    if (!body) return '';
    if (typeof body.length === 'number') {
      var out = '', i;
      for (i = 0; i < body.length; i++) out += String.fromCharCode(body[i] & 255);
      return out;
    }
    return '';
  }

  var result = {};
  try {
    if (typeof $request !== 'undefined' && typeof $response !== 'undefined' && URL_PATTERN.test($request.url || '')) {
      var statusValue = $response.statusCode || $response.status || 200;
      var statusMatch = String(statusValue).match(/^(?:HTTP\/\S+\s+)?(\d{3})(?:\s|$)/i);
      var status = statusMatch ? Number(statusMatch[1]) : 0;
      var rawBody = toText($response.body);
      if (status >= 200 && status < 300 && rawBody.length) {
        if (rawBody.length > 2 * 1024 * 1024) throw new Error('Body exceeds 2 MiB limit');
        initAES();
        var plain = decrypt(rawBody);
        var obj = JSON.parse(plain), data = obj && obj.data;
        if (obj.code === 0 && data && !Array.isArray(data) &&
            Object.prototype.hasOwnProperty.call(data, 'adFree') &&
            Object.prototype.hasOwnProperty.call(data, 'adVIPForever') &&
            Object.prototype.hasOwnProperty.call(data, 'adFreeTime')) {
          data.adVIPForever = true;
          data.adFree = true;
          data.adFreeTime = '永久会员';
          var body = encrypt(JSON.stringify(obj)), headers = {}, name;
          for (name in ($response.headers || {})) {
            if (Object.prototype.hasOwnProperty.call($response.headers, name) &&
                !/^(content-length|content-encoding|transfer-encoding|etag|content-md5)$/i.test(name)) {
              headers[name] = $response.headers[name];
            }
          }
          /* Loon 中 headers:{} 会清空响应头，为空时整个字段都不返回 */
          result = Object.keys(headers).length ? { body: body, headers: headers } : { body: body };
          log('配置已改写：adVIPForever=true, adFree=true, adFreeTime=永久会员');
        } else {
          log('非会员配置响应，保持原样');
        }
      }
    }
  } catch (error) {
    log('保持原响应：' + (error && error.message ? error.message : String(error)));
    result = {};
  }
  $done(result);
})();
