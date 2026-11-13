/**
 * migration.test.mjs — 谷歌验证器导出二维码解析测试
 * 运行：node test/migration.test.mjs
 */
import assert from 'node:assert/strict';
import {
  base32Encode, isMigrationText, parseMigrationPayload, MigrationSession,
} from '../migration.js';
import { validateEntry, base32Decode, generateTOTP } from '../totp.js';

let passed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log(`  ✓ ${name}`); }
  catch (err) { console.error(`  ✗ ${name}\n    ${err.message}`); process.exitCode = 1; }
}
async function atest(name, fn) {
  try { await fn(); passed++; console.log(`  ✓ ${name}`); }
  catch (err) { console.error(`  ✗ ${name}\n    ${err.message}`); process.exitCode = 1; }
}

/* ---- 构造真实的 protobuf 字节（不依赖第三方库） ---- */
const te = new TextEncoder();
const vi = (n) => {
  let v = BigInt(n); const out = [];
  while (v > 127n) { out.push(Number(v & 127n) | 0x80); v >>= 7n; }
  out.push(Number(v));
  return out;
};
const tag = (field, wire) => vi(field * 8 + wire);
const bytesF = (field, b) => [...tag(field, 2), ...vi(b.length), ...b];
const varF = (field, n) => [...tag(field, 0), ...vi(n)];
const str = (s) => [...te.encode(s)];

function otpParams({ secret, name, issuer = '', algorithm = 1, digits = 1, type = 2, counter = 0, uniqueId = '' }) {
  return [
    ...bytesF(1, secret),
    ...bytesF(2, str(name)),
    ...(issuer ? bytesF(3, str(issuer)) : []),
    ...varF(4, algorithm),
    ...varF(5, digits),
    ...varF(6, type),
    ...(counter ? varF(7, counter) : []),
    ...(uniqueId ? bytesF(8, str(uniqueId)) : []),
  ];
}
function payload(accounts, { version = 1, batchSize = 1, batchIndex = 0, batchId = 12345, trailing = false } = {}) {
  const b = [];
  for (const a of accounts) b.push(...bytesF(1, otpParams(a)));
  b.push(...varF(2, version), ...varF(3, batchSize), ...varF(4, batchIndex), ...varF(5, batchId));
  if (trailing) b.push(...bytesF(9, str('unknown-field'))); // 未知字段应被安全跳过
  return b;
}
const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const uri = (bytes, encode = true) =>
  'otpauth-migration://offline?data=' + (encode ? encodeURIComponent(b64(bytes)) : b64(bytes));

console.log('\n=== Base32 编码 ===');
test('原始字节 → Base32（与 RFC 测试密钥一致）', () => {
  assert.equal(base32Encode([72, 101, 108, 108, 111, 33, 222, 173, 190, 239]), 'JBSWY3DPEHPK3PXP');
});
test('Base32 编码可被本应用解码还原', () => {
  const raw = Uint8Array.from([1, 2, 3, 250, 17, 88, 200, 7, 240]);
  assert.deepEqual([...base32Decode(base32Encode(raw))], [...raw]);
});

console.log('\n=== 官方公开样例 ===');
// 公开文档广泛引用的样例：secret = Hello!\xDE\xAD\xBE\xEF，name = Test:alice@google.com，issuer = Example
// （按 protobuf 规范重新编码，网上流传的摘录字符串长度字节有误，解析器会正确拒绝）
test('公开样例向量解析出 Example / JBSWY3DPEHPK3PXP', () => {
  const v = 'otpauth-migration://offline?data=CjIKCkhlbGxvId6tvu8SFVRlc3Q6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZSABKAEwAhABGAEgACgA';
  const p = parseMigrationPayload(v);
  assert.equal(p.accounts.length, 1);
  const a = p.accounts[0];
  assert.equal(p.version, 1);
  assert.equal(p.batchSize, 1);
  assert.equal(a.issuer, 'Example');
  assert.equal(a.account, 'Test:alice@google.com');
  assert.equal(a.secret, 'JBSWY3DPEHPK3PXP');
  assert.equal(a.algorithm, 'SHA1');
  assert.equal(a.digits, 6);
  assert.equal(a.type, 'TOTP');
  assert.equal(a.skipReason, null);
  validateEntry(a);
});

console.log('\n=== 单张导出：多账号 / 枚举 / 中文 / 前缀 ===');
const S1 = [72, 101, 108, 108, 111, 33, 222, 173, 190, 239]; // Hello!\xDE\xAD\xBE\xEF
const S2 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
const S3 = [200, 100, 50, 25, 12, 6, 3];
const S4 = [9, 9, 9, 9];
const S5 = [7, 7, 7, 7];
const single = payload([
  { secret: S1, name: 'alice@example.com', issuer: 'GitHub' },
  { secret: S2, name: 'seller@shop.com', issuer: 'Amazon', algorithm: 2, digits: 2 },   // SHA256 / 8 位
  { secret: S3, name: 'bob@outlook.com', issuer: 'Microsoft', algorithm: 3, digits: 3 },  // SHA512 / 7 位
  { secret: S4, name: 'Legacy:token', issuer: '' },                                       // name 带 issuer 前缀
  { secret: S5, name: '腾讯科技:zhangsan', issuer: '腾讯科技' },                              // UTF-8 服务名
  { secret: [1, 2], name: 'hotp@example.com', issuer: 'HOTP Demo', type: 1, counter: 42 },
  { secret: [3, 4], name: 'md5@example.com', issuer: 'MD5 Demo', algorithm: 4 },
], { trailing: true });

test('URL 编码与裸 Base64 两种形式结果一致', () => {
  assert.deepEqual(parseMigrationPayload(uri(single, true)).accounts,
    parseMigrationPayload(uri(single, false)).accounts);
});
test('裸 Base64 也能直接解析', () => {
  assert.equal(parseMigrationPayload(b64(single)).accounts.length, 7);
});
test('账号数量与名称解析正确（含中文服务名）', () => {
  const a = parseMigrationPayload(uri(single)).accounts;
  assert.equal(a.length, 7);
  assert.deepEqual(a.slice(0, 5).map((x) => [x.issuer, x.account]), [
    ['GitHub', 'alice@example.com'],
    ['Amazon', 'seller@shop.com'],
    ['Microsoft', 'bob@outlook.com'],
    ['Legacy', 'token'],
    ['腾讯科技', 'zhangsan'],
  ]);
});
test('算法 / 位数枚举映射正确', () => {
  const a = parseMigrationPayload(uri(single)).accounts;
  assert.deepEqual(a.slice(0, 3).map((x) => [x.algorithm, x.digits, x.period]), [
    ['SHA1', 6, 30], ['SHA256', 8, 30], ['SHA512', 7, 30],
  ]);
});
test('HOTP 与 MD5 被标记为不支持', () => {
  const a = parseMigrationPayload(uri(single)).accounts;
  assert.match(a[5].skipReason, /HOTP/);
  assert.match(a[6].skipReason, /MD5/);
});
test('解析出的账号全部能通过本应用校验', () => {
  for (const a of parseMigrationPayload(uri(single)).accounts) {
    if (!a.secret) continue;
    assert.equal(validateEntry(a).secret, a.secret);
  }
});
test('data 参数单独粘贴（data=...）也能解析', () => {
  assert.equal(parseMigrationPayload('data=' + encodeURIComponent(b64(single))).accounts.length, 7);
});
await atest('解析出的密钥能算出 RFC 6238 官方验证码', async () => {
  // RFC 6238 SHA1 密钥原文 12345678901234567890，T=59 时应为 94287082（8 位）/ 287082（6 位）
  const rfc = payload([{ secret: [...str('12345678901234567890')], name: 'rfc', issuer: 'RFC' }]);
  const a = parseMigrationPayload(uri(rfc)).accounts[0];
  assert.equal(a.secret, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  const r = await generateTOTP({ ...a, timestamp: 59000 });
  assert.equal(r.code, '287082');
});

console.log('\n=== 多张二维码分批合并 ===');
const batchOpts = (idx) => ({ version: 1, batchSize: 3, batchIndex: idx, batchId: 777 });
const b0 = payload([{ secret: S1, name: 'a@x.com', issuer: 'A' }], batchOpts(0));
const b1 = payload([{ secret: S2, name: 'b@x.com', issuer: 'B' },
                    { secret: S3, name: 'c@x.com', issuer: 'C' }], batchOpts(1));
const b2 = payload([{ secret: S4, name: 'd@x.com', issuer: 'D' }], batchOpts(2));

test('乱序扫描仍按 batchIndex 顺序汇总，且检测重复张', () => {
  const s = new MigrationSession();
  assert.equal(s.add(uri(b2)).status, 'partial');
  assert.equal(s.progress().missing.join(','), '0,1');
  assert.equal(s.add(uri(b2)).status, 'duplicate');
  let r = s.add(uri(b0));
  assert.equal(r.status, 'partial');
  assert.deepEqual(r.missing, [1]);
  r = s.add(uri(b1));
  assert.equal(r.status, 'complete');
  assert.equal(r.complete, true);
  assert.deepEqual(s.accounts().map((a) => a.issuer), ['A', 'B', 'C', 'D']);
});
test('批次信息齐全时 progress 正确', () => {
  const s = new MigrationSession();
  s.add(uri(b0));
  assert.deepEqual(s.progress().missing, [1, 2]);
  assert.equal(s.progress().size, 3);
  assert.equal(s.progress().complete, false);
});
test('batchId 不同会重新开始一批，旧数据不混入', () => {
  const s = new MigrationSession();
  s.add(uri(b0));
  const other = payload([{ secret: S5, name: 'z@x.com', issuer: 'Z' }],
    { version: 1, batchSize: 3, batchIndex: 0, batchId: 999 });
  const r = s.add(uri(other));
  assert.equal(r.restart, true);
  assert.equal(s.parts.size, 1);
  assert.equal(s.accounts()[0].issuer, 'Z');
});
test('多份独立的单张导出可以连续累加', () => {
  const s = new MigrationSession();
  const one = payload([{ secret: S1, name: 'one@x.com', issuer: 'One' }], { batchSize: 1, batchIndex: 0 });
  const two = payload([{ secret: S2, name: 'two@x.com', issuer: 'Two' }], { batchSize: 1, batchIndex: 0 });
  s.add(uri(one)); s.add(uri(two));
  assert.equal(s.progress().mode, 'single');
  assert.equal(s.progress().complete, true);
  assert.deepEqual(s.accounts().map((a) => a.issuer), ['One', 'Two']);
});
test('相同密钥+名称的账号会被去重', () => {
  const s = new MigrationSession();
  const one = payload([{ secret: S1, name: 'dup@x.com', issuer: 'Dup' }], { batchSize: 1 });
  s.add(uri(one)); s.add(uri(one));
  assert.equal(s.accounts().length, 1);
});
test('reset 后重新收集', () => {
  const s = new MigrationSession();
  s.add(uri(b0)); s.reset();
  assert.equal(s.accounts().length, 0);
  assert.equal(s.progress().mode, 'idle');
});

console.log('\n=== 识别判断与异常输入 ===');
test('isMigrationText 正确区分各类文本', () => {
  assert.equal(isMigrationText(uri(single)), true);
  assert.equal(isMigrationText(b64(single)), true);
  assert.equal(isMigrationText('otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP'), false);
  assert.equal(isMigrationText('JBSWY3DPEHPK3PXP'), false);              // 纯 Base32 密钥不能误判
  assert.equal(isMigrationText('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'), false);
  assert.equal(isMigrationText('hello world'), false);
});
test('缺少 data 参数、非法 Base64、非 protobuf 数据都会报错', () => {
  assert.throws(() => parseMigrationPayload('otpauth-migration://offline'), /缺少 data/);
  assert.throws(() => parseMigrationPayload('otpauth-migration://offline?data=@@@'), /Base64/);
  assert.throws(() => parseMigrationPayload('otpauth-migration://offline?data=' +
    encodeURIComponent(b64([0xff, 0xff, 0xff, 0xff, 0x0f]))), /proto|截断|账号|异常/i);
});
test('被截断的 protobuf 不会静默产出错误账号', () => {
  const full = single;
  assert.throws(() => parseMigrationPayload(b64(full.slice(0, Math.floor(full.length / 2)))), /截断|异常|账号/i);
});

console.log(`\n${process.exitCode ? '❌ 存在失败' : '✅ 全部通过'}：${passed} 项\n`);
