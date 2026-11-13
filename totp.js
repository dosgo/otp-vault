/**
 * totp.js — TOTP / HOTP 核心算法（RFC 4226 + RFC 6238）
 * 纯 ESM 模块，不依赖 DOM，可在浏览器与 Node.js 中直接运行。
 * 所有密码学运算使用 Web Crypto API (crypto.subtle)。
 */

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const HASH_NAMES = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

/** 归一化 Base32 密钥：大写、去空格/连字符/填充 */
export function normalizeSecret(secret) {
  return String(secret ?? '')
    .toUpperCase()
    .replace(/[\s=\-_]/g, '')
    .replace(/0/g, 'O')   // 常见手抄误认
    .replace(/1/g, 'I');
}

/** Base32 解码为字节数组 */
export function base32Decode(input) {
  const s = normalizeSecret(input);
  if (!s) throw new Error('密钥不能为空');
  let buffer = 0;
  let bitsLeft = 0;
  const out = [];
  for (const ch of s) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx === -1) {
      throw new Error(`密钥包含非法字符「${ch}」，请确认复制完整（只应含 A-Z 与 2-7）`);
    }
    buffer = (buffer << 5) | idx;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      bitsLeft -= 8;
      out.push((buffer >>> bitsLeft) & 0xff);
      buffer &= (1 << bitsLeft) - 1;
    }
  }
  if (out.length === 0) throw new Error('密钥太短，无法解析');
  return new Uint8Array(out);
}

/** 64 位大端计数器字节（8 bytes） */
function counterToBytes(counter) {
  const bytes = new Uint8Array(8);
  let v = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}

/** HMAC 签名 */
async function hmacSign(algorithm, keyBytes, message) {
  const hash = HASH_NAMES[algorithm];
  if (!hash) throw new Error(`不支持的算法：${algorithm}`);
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, message);
  return new Uint8Array(sig);
}

/** 动态截断 (dynamic truncation) */
function dynamicTruncation(hmac, digits) {
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(binary % 10 ** digits).padStart(digits, '0');
}

/**
 * 生成 TOTP 验证码
 * @param {object} opts
 * @param {string} opts.secret    Base32 密钥
 * @param {string} [opts.algorithm] SHA1 | SHA256 | SHA512
 * @param {number} [opts.digits]  验证码位数，默认 6
 * @param {number} [opts.period]  周期（秒），默认 30
 * @param {number} [opts.timestamp] 时间戳（毫秒），默认当前时间
 * @returns {Promise<{code:string, counter:number, remaining:number, progress:number, validFrom:number, validUntil:number}>}
 */
export async function generateTOTP({
  secret,
  algorithm = 'SHA1',
  digits = 6,
  period = 30,
  timestamp = Date.now(),
} = {}) {
  algorithm = String(algorithm).toUpperCase();
  digits = Number(digits) || 6;
  period = Number(period) || 30;
  if (digits < 4 || digits > 9) throw new Error('验证码位数需在 4-9 之间');
  if (period < 1 || period > 3600) throw new Error('周期需在 1-3600 秒之间');

  const keyBytes = base32Decode(secret);
  const seconds = Math.floor(timestamp / 1000);
  const counter = Math.floor(seconds / period);
  const elapsed = seconds - counter * period;
  const remaining = period - elapsed;

  const hmac = await hmacSign(algorithm, keyBytes, counterToBytes(counter));
  return {
    code: dynamicTruncation(hmac, digits),
    counter,
    remaining,
    progress: elapsed / period,
    validFrom: counter * period * 1000,
    validUntil: (counter + 1) * period * 1000,
  };
}

/** 生成下一个周期的验证码（用于提前查看） */
export async function generateNextTOTP(entry, timestamp = Date.now()) {
  const period = Number(entry.period) || 30;
  return generateTOTP({ ...entry, timestamp: timestamp + period * 1000 });
}

/** 6 位 → "123 456"，8 位 → "1234 5678" */
export function formatCode(code) {
  const mid = Math.ceil(code.length / 2);
  return `${code.slice(0, mid)} ${code.slice(mid)}`;
}

/** 解析 otpauth://totp/... 链接 */
export function parseOtpauthURI(uri) {
  const raw = String(uri ?? '').trim();
  if (!/^otpauth:\/\//i.test(raw)) {
    throw new Error('请以 otpauth:// 开头的二维码内容或链接');
  }
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('链接格式无法解析，请检查内容是否完整');
  }
  if (url.host.toLowerCase() !== 'totp') {
    throw new Error('目前仅支持 TOTP 类型（HOTP 暂不支持）');
  }
  const p = url.searchParams;
  const secret = normalizeSecret(p.get('secret'));
  if (!secret) throw new Error('二维码中缺少 secret 密钥');
  base32Decode(secret); // 提前校验合法性

  const label = decodeURIComponent(url.pathname.replace(/^\//, '')).trim();
  let issuer = (p.get('issuer') || '').trim();
  let account = label;
  if (label.includes(':')) {
    const [labelIssuer, ...rest] = label.split(':');
    if (!issuer) issuer = labelIssuer.trim();
    account = rest.join(':').trim() || labelIssuer.trim();
    if (issuer === labelIssuer.trim()) account = rest.join(':').trim() || '';
  }

  const algorithm = (p.get('algorithm') || 'SHA1').toUpperCase();
  if (!HASH_NAMES[algorithm]) throw new Error(`不支持的算法：${algorithm}`);
  const digits = Number(p.get('digits') || 6);
  const period = Number(p.get('period') || 30);
  if (![6, 7, 8, 9].includes(digits)) throw new Error(`不支持的验证码位数：${digits}`);
  if (!Number.isFinite(period) || period < 1 || period > 3600) {
    throw new Error(`不支持的周期：${period}`);
  }

  return {
    issuer: issuer || '未命名',
    account: account || '',
    secret,
    algorithm,
    digits,
    period,
  };
}

/** 由账号信息反生成 otpauth:// 链接（用于备份 / 迁移） */
export function buildOtpauthURI(entry) {
  const label = entry.issuer
    ? `${entry.issuer}:${entry.account || ''}`
    : (entry.account || 'Account');
  const q = new URLSearchParams({
    secret: normalizeSecret(entry.secret),
    issuer: entry.issuer || '',
    algorithm: entry.algorithm || 'SHA1',
    digits: String(entry.digits || 6),
    period: String(entry.period || 30),
  });
  return `otpauth://totp/${encodeURIComponent(label)}?${q.toString()}`;
}

/** 校验一份手工输入的配置是否可用 */
export function validateEntry(entry) {
  const e = {
    issuer: String(entry.issuer ?? '').trim() || '未命名',
    account: String(entry.account ?? '').trim(),
    secret: normalizeSecret(entry.secret),
    algorithm: String(entry.algorithm || 'SHA1').toUpperCase(),
    digits: Number(entry.digits || 6),
    period: Number(entry.period || 30),
  };
  if (!e.secret) throw new Error('请填写密钥');
  base32Decode(e.secret);
  if (!HASH_NAMES[e.algorithm]) throw new Error(`不支持的算法：${e.algorithm}`);
  if (![6, 7, 8, 9].includes(e.digits)) throw new Error('验证码位数只支持 6/7/8/9');
  if (!Number.isFinite(e.period) || e.period < 1 || e.period > 3600) {
    throw new Error('周期需在 1-3600 秒之间');
  }
  return e;
}
