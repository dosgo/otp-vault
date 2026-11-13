/**
 * migration.js — 解析 Google Authenticator「转移账号 / 导出账号」二维码
 *
 * 二维码内容形如：
 *   otpauth-migration://offline?data=<Base64(protobuf MigrationPayload)>
 *
 * Protobuf 结构（Google 导出格式，2020 年起稳定）：
 *   message MigrationPayload {
 *     repeated OtpParameters otp_parameters = 1;  // 每条是一个账号
 *     int32 version      = 2;
 *     int32 batch_size   = 3;  // 本次导出共几张二维码
 *     int32 batch_index  = 4;  // 当前是第几张（从 0 开始）
 *     int32 batch_id     = 5;  // 同一批二维码的标识
 *   }
 *   message OtpParameters {
 *     bytes  secret    = 1;  // 原始密钥字节，需转成 Base32
 *     string name      = 2;  // 账号名，有时带 "Issuer:" 前缀
 *     string issuer    = 3;  // 服务名
 *     Algorithm algorithm = 4;  // 0/1 SHA1, 2 SHA256, 3 SHA512, 4 MD5
 *     DigitCount digits   = 5;  // 0/1 六位, 2 八位, 3 七位
 *     OtpType type        = 6;  // 0/2 TOTP, 1 HOTP
 *     int64  counter      = 7;  // 仅 HOTP 使用
 *     string unique_id    = 8;  // 新版字段，忽略
 *   }
 *
 * 纯 ESM、无 DOM 依赖，可直接在浏览器与 Node.js 中运行。
 * 不引入任何第三方 protobuf 库，只实现本项目需要的 wire type。
 */

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const ALGORITHMS = { 0: 'SHA1', 1: 'SHA1', 2: 'SHA256', 3: 'SHA512' };
const DIGIT_COUNTS = { 0: 6, 1: 6, 2: 8, 3: 7 };
const OTP_TYPES = { 0: 'TOTP', 1: 'HOTP', 2: 'TOTP' };

const utf8 = new TextDecoder('utf-8');

/** 原始密钥字节 → Base32（无填充） */
export function base32Encode(bytes) {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | (byte & 0xff);
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32_ALPHABET[(buffer >>> bits) & 31];
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32_ALPHABET[(buffer << (5 - bits)) & 31];
  return out;
}

/** Base64 解码，兼容标准/URL-safe、URL 编码、缺少填充的情况 */
function base64Decode(input) {
  let s = String(input ?? '').trim();
  // 二维码里的 data 参数常被 URL 编码（+ → %2B，/ → %2F，= → %3D）
  if (s.includes('%')) {
    try { s = decodeURIComponent(s); } catch { /* 保留原样 */ }
  }
  s = s.replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  if (!s) throw new Error('迁移数据为空');
  if (!/^[A-Za-z0-9+/]+$/.test(s)) throw new Error('迁移数据不是合法的 Base64');

  const out = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of s) {
    const idx = B64_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error('迁移数据含非法字符');
    buffer = (buffer << 6) | idx;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >>> bits) & 0xff);
      buffer &= (1 << bits) - 1;
    }
  }
  return Uint8Array.from(out);
}

/** 最小 protobuf 读取器：varint / length-delimited / fixed32 / fixed64 */
class ProtoReader {
  constructor(bytes) { this.b = bytes; this.p = 0; }
  get left() { return this.b.length - this.p; }

  varint() {
    let value = 0n;
    for (let i = 0; i < 10; i++) {
      if (this.p >= this.b.length) throw new Error('迁移数据被截断');
      const byte = this.b[this.p++];
      value |= BigInt(byte & 0x7f) << BigInt(7 * i);
      if ((byte & 0x80) === 0) return value;
    }
    throw new Error('迁移数据中的整数编码异常');
  }

  lengthDelimited() {
    const lenBig = this.varint();
    const len = Number(lenBig);
    if (!Number.isSafeInteger(len) || len < 0 || len > this.left) {
      throw new Error('迁移数据被截断');
    }
    const slice = this.b.subarray(this.p, this.p + len);
    this.p += len;
    return slice;
  }

  skip(wire) {
    if (wire === 0) { this.varint(); return; }
    if (wire === 2) { this.lengthDelimited(); return; }
    if (wire === 1 || wire === 5) {
      const n = wire === 1 ? 8 : 4;
      if (this.left < n) throw new Error('迁移数据被截断');
      this.p += n;
      return;
    }
    throw new Error(`无法识别的 protobuf 字段类型：${wire}`);
  }

  tag() {
    const raw = this.varint();
    if (raw > 0xffffffffn) throw new Error('迁移数据字段编号异常');
    const n = Number(raw);
    const field = n >>> 3;
    if (field === 0) throw new Error('迁移数据字段编号异常');
    return { field, wire: n & 7 };
  }
}

/** 判断一段文本是否像谷歌迁移数据（也接受裸 Base64） */
export function isMigrationText(text) {
  const s = String(text ?? '').trim();
  if (/^otpauth-migration:\/\//i.test(s)) return true;
  if (/^data=/i.test(s)) return true;
  // 裸 Base64：必须含小写字母或 + / = _ % - 之一，避免把纯大写 Base32 密钥误判
  return s.length >= 16
    && !/\s/.test(s)
    && !s.includes('://')
    && /^[A-Za-z0-9+/_%=-]+$/.test(s)
    && /[a-z+\/=_%-]/.test(s);
}

function extractData(text) {
  const s = String(text ?? '').trim();
  const m = s.match(/[?&]data=([^&#\s]*)/i);
  if (m) return m[1];
  if (/^otpauth-migration:\/\//i.test(s)) throw new Error('链接里缺少 data 参数');
  if (/^data=/i.test(s)) return s.slice(5);
  return s;
}

/** 把一个 OtpParameters 转成本应用的账号格式 */
function toAccount(p) {
  const reasons = [];
  if (!p.secret || p.secret.length === 0) reasons.push('缺少密钥');

  const algorithm = ALGORITHMS[p.algorithm] || 'SHA1';
  if (p.algorithm === 4) reasons.push('MD5 算法不受支持');
  else if (ALGORITHMS[p.algorithm] === undefined) reasons.push(`未知算法 ${p.algorithm}`);

  const digits = DIGIT_COUNTS[p.digits] ?? 6;
  if (DIGIT_COUNTS[p.digits] === undefined) reasons.push(`未知位数 ${p.digits}`);

  const type = OTP_TYPES[p.type] || 'TOTP';
  if (p.type === 1) reasons.push('HOTP 计数器型（本应用仅支持 TOTP）');
  else if (OTP_TYPES[p.type] === undefined) reasons.push(`未知类型 ${p.type}`);

  let account = String(p.name || '').trim();
  let issuer = String(p.issuer || '').trim();
  if (account.includes(':')) {
    const idx = account.indexOf(':');
    const prefix = account.slice(0, idx).trim();
    const rest = account.slice(idx + 1).trim();
    if (!issuer) { issuer = prefix; account = rest; }
    else if (prefix.toLowerCase() === issuer.toLowerCase()) account = rest;
  }

  return {
    issuer: issuer || '未命名',
    account,
    secret: p.secret ? base32Encode(p.secret) : '',
    algorithm,
    digits,
    period: 30,              // 谷歌验证器固定 30 秒
    type,
    counter: p.counter,
    skipReason: reasons.length ? reasons.join('；') : null,
  };
}

function parseOtpParameters(bytes) {
  const r = new ProtoReader(bytes);
  const p = { secret: null, name: '', issuer: '', algorithm: 0, digits: 0, type: 0, counter: 0 };
  while (r.left > 0) {
    const { field, wire } = r.tag();
    if (wire === 0) {
      const v = Number(r.varint());
      if (field === 4) p.algorithm = v;
      else if (field === 5) p.digits = v;
      else if (field === 6) p.type = v;
      else if (field === 7) p.counter = v;
      continue;
    }
    if (wire === 2) {
      const raw = r.lengthDelimited();
      if (field === 1) p.secret = raw;
      else if (field === 2) p.name = utf8.decode(raw);
      else if (field === 3) p.issuer = utf8.decode(raw);
      // field 8 = unique_id，忽略
      continue;
    }
    r.skip(wire);
  }
  return p;
}

/**
 * 解析单张谷歌导出二维码（或裸 Base64）
 * @returns {{version:number,batchSize:number,batchIndex:number,batchId:number,accounts:object[]}}
 */
export function parseMigrationPayload(text) {
  const bytes = base64Decode(extractData(text));
  if (!bytes.length) throw new Error('迁移数据为空');

  const r = new ProtoReader(bytes);
  let version = 0; let batchSize = 0; let batchIndex = 0; let batchId = 0;
  const rawAccounts = [];
  while (r.left > 0) {
    const { field, wire } = r.tag();
    if (field === 1 && wire === 2) {
      rawAccounts.push(parseOtpParameters(r.lengthDelimited()));
      continue;
    }
    if (wire === 0) {
      const v = Number(r.varint());
      if (field === 2) version = v;
      else if (field === 3) batchSize = v;
      else if (field === 4) batchIndex = v;
      else if (field === 5) batchId = v;
      continue;
    }
    r.skip(wire);
  }
  if (!rawAccounts.length && !version && !batchSize) {
    throw new Error('没有解析到账号数据，请确认这是谷歌验证器的「导出账号」二维码');
  }
  return { version, batchSize, batchIndex, batchId, accounts: rawAccounts.map(toAccount) };
}

/**
 * 分批二维码收集器。
 * 账号多时谷歌会把一次导出拆成 N 张二维码，需要按 batchId 逐张扫完再合并。
 * 多份独立的单张导出也可以连续添加，账号会累加。
 */
export class MigrationSession {
  constructor() { this.reset(); }

  reset() {
    this.mode = 'idle';      // idle | single | batch
    this.batchId = 0;
    this.batchSize = 0;
    this.parts = new Map();
    this.singleCount = 0;
  }

  add(text) {
    const payload = parseMigrationPayload(text);
    const size = Math.max(1, payload.batchSize || 1);
    const hadParts = this.parts.size > 0;

    // 单张导出：各自独立，累加到本次会话
    if (size <= 1) {
      if (this.mode === 'batch') this.reset();
      this.mode = 'single';
      this.parts.set(`s${this.singleCount++}`, payload);
      return { status: 'complete', payload, restart: false, ...this.progress() };
    }

    // 多张导出：同一批必须 batchId 与 batchSize 一致
    let restart = false;
    if (this.mode !== 'batch' || this.batchId !== payload.batchId || this.batchSize !== size) {
      this.reset();
      this.mode = 'batch';
      this.batchId = payload.batchId;
      this.batchSize = size;
      restart = hadParts;
    }

    const idx = Math.min(Math.max(0, payload.batchIndex || 0), size - 1);
    if (this.parts.has(idx)) {
      return { status: 'duplicate', payload, restart: false, ...this.progress() };
    }
    this.parts.set(idx, payload);
    const pr = this.progress();
    return {
      status: pr.complete ? 'complete' : 'partial',
      payload, restart, ...pr,
    };
  }

  progress() {
    if (this.mode === 'single') {
      return {
        mode: 'single', total: this.parts.size, size: this.parts.size,
        got: this.parts.size, missing: [], complete: this.parts.size > 0,
      };
    }
    if (this.mode !== 'batch') {
      return { mode: 'idle', total: 0, size: 0, got: 0, missing: [], complete: false };
    }
    const missing = [];
    for (let i = 0; i < this.batchSize; i++) if (!this.parts.has(i)) missing.push(i);
    return {
      mode: 'batch', total: this.parts.size, size: this.batchSize,
      got: this.parts.size, missing, complete: missing.length === 0,
    };
  }

  /** 按二维码顺序汇总账号，并按密钥+名称去重 */
  accounts() {
    const keys = [...this.parts.keys()].sort((a, b) =>
      (typeof a === 'number' && typeof b === 'number')
        ? a - b
        : String(a).localeCompare(String(b)));
    const out = [];
    const seen = new Set();
    for (const key of keys) {
      for (const a of this.parts.get(key).accounts) {
        const ident = `${a.secret}|${a.issuer}|${a.account}`;
        if (seen.has(ident)) continue;
        seen.add(ident);
        out.push(a);
      }
    }
    return out;
  }
}
