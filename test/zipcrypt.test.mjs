/* zipcrypt.js 单元测试：node test/zipcrypt.test.mjs */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createEncryptedZip, readZip, inspectZip, isZipBytes, __internal,
} from '../zipcrypt.js';

const OUT = path.join(path.dirname(fileURLToPath(import.meta.url)), 'out');
fs.mkdirSync(OUT, { recursive: true });

let pass = 0;
const test = (name, fn) => {
  try { fn(); console.log(`  ✓ ${name}`); pass++; }
  catch (e) { console.error(`  ✗ ${name}\n    ${e.stack}`); process.exitCode = 1; }
};
const atest = async (name, fn) => {
  try { await fn(); console.log(`  ✓ ${name}`); pass++; }
  catch (e) { console.error(`  ✗ ${name}\n    ${e.stack}`); process.exitCode = 1; }
};

const CONTENT = JSON.stringify({
  app: 'otp-vault', version: 1, exportedAt: '2026-11-12T00:00:00.000Z',
  entries: [
    { issuer: 'GitHub', account: 'alice', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 },
    { issuer: '亚马逊卖家', account: 'seller@example.com', secret: 'GEZDGNBVGY3TQOJQ', algorithm: 'SHA256', digits: 8, period: 30 },
  ],
}, null, 2);
const PASSWORD = 'Str0ng-P@ssw0rd-2026';

console.log('— AES 分组加密 —');
test('S-box 前两项符合 FIPS-197', () => {
  assert.equal(__internal.SBOX[0], 0x63);
  assert.equal(__internal.SBOX[1], 0x7c);
  assert.equal(__internal.SBOX[0x53], 0xed);
});
test('AES-256 FIPS-197 官方向量', () => {
  const key = Uint8Array.from({ length: 32 }, (_, i) => i);
  const pt = new Uint8Array([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
  const ct = new __internal.AES256(key).encryptBlock(pt);
  assert.equal(Buffer.from(ct).toString('hex'), '8ea2b7ca516745bfeafc49904b496089');
});
test('CTR 加解密互逆且计数器小端进位', () => {
  const key = Uint8Array.from({ length: 32 }, (_, i) => (i * 7) & 0xff);
  const data = new Uint8Array(64 * 16 + 7); // 跨越多组，触发进位
  for (let i = 0; i < data.length; i++) data[i] = (i * 31) & 0xff;
  const c = __internal.aesCtr(data, key);
  assert.notDeepEqual(Buffer.from(c).toString('hex'), Buffer.from(data).toString('hex'));
  assert.deepEqual(__internal.aesCtr(c, key), data);
});
test('CRC-32 标准向量 "123456789" = 0xCBF43926', () => {
  assert.equal(__internal.crc32(new TextEncoder().encode('123456789')), 0xcbf43926);
});

console.log('— 生成 / 读取加密 ZIP —');
for (const mode of ['aes', 'zipcrypto']) {
  await atest(`${mode}: 生成、识别、正确密码解密`, async () => {
    const zip = await createEncryptedZip({ content: CONTENT, password: PASSWORD, mode });
    assert.equal(isZipBytes(zip), true);
    const info = inspectZip(zip);
    assert.equal(info.mode, mode);
    assert.equal(info.encrypted, true);
    assert.equal(info.name, 'otp-backup.json');
    const r = await readZip(zip, PASSWORD);
    assert.equal(r.text, CONTENT);
    assert.equal(r.mode, mode);
    fs.writeFileSync(path.join(OUT, `generated-${mode}.zip`), zip);
  });
  await atest(`${mode}: 错误密码明确报错`, async () => {
    const zip = await createEncryptedZip({ content: CONTENT, password: PASSWORD, mode });
    await assert.rejects(() => readZip(zip, 'wrong-password'), /密码不正确/);
  });
  await atest(`${mode}: 不输密码不能解出内容`, async () => {
    const zip = await createEncryptedZip({ content: CONTENT, password: PASSWORD, mode });
    await assert.rejects(() => readZip(zip, ''), /需要备份密码/);
  });
  await atest(`${mode}: 每次导出密文不同（随机盐 / 随机头）`, async () => {
    const a = await createEncryptedZip({ content: CONTENT, password: PASSWORD, mode });
    const b = await createEncryptedZip({ content: CONTENT, password: PASSWORD, mode });
    assert.notEqual(Buffer.from(a).toString('hex'), Buffer.from(b).toString('hex'));
  });
}

console.log('— 外部工具生成的 ZIP —');
// pyzipper 生成的 AES-256 (AE-2) ZIP，密码 hello123
const REF_AES_B64 = 'UEsDBBQAAQBjAKySbF0AAAAAPAAAACAAAAAPAAsAb3RwLWJhY2t1cC5qc29uAZkHAAIAQUUDAADElKKdhLAJwh+/vRBcc0VY5OdlnsIZBRmeal5R/+wKEwV1kpB/gHLvSUpmfl4zYSwC8kYmgGYXR4F05hZQSwECFAAUAAEAYwCskmxdAAAAADwAAAAgAAAADwALAAAAAAAAAAAAgAEAAAAAb3RwLWJhY2t1cC5qc29uAZkHAAIAQUUDAABQSwUGAAAAAAEAAQBIAAAAdAAAAAAA';
await atest('能解开 pyzipper 生成的 AES-256 ZIP', async () => {
  const b = Buffer.from(REF_AES_B64, 'base64');
  const info = inspectZip(b);
  assert.equal(info.mode, 'aes');
  assert.equal((await readZip(b, 'hello123')).text, '{"app":"otp-vault","entries":[]}');
  await assert.rejects(() => readZip(b, 'bad'), /密码不正确/);
});
// Python zipfile 生成的未加密 STORE ZIP
const REF_PLAIN_B64 = 'UEsDBBQAAAAAAKySbF0bhm9bIAAAACAAAAAPAAAAb3RwLWJhY2t1cC5qc29ueyJhcHAiOiJvdHAtdmF1bHQiLCJlbnRyaWVzIjpbXX1QSwECFAAUAAAAAACskmxdG4ZvWyAAAAAgAAAADwAAAAAAAAAAAAAAgAEAAAAAb3RwLWJhY2t1cC5qc29uUEsFBgAAAAABAAEAPQAAAE0AAAAAAA==';
await atest('能读取普通未加密 ZIP', async () => {
  const b = Buffer.from(REF_PLAIN_B64, 'base64');
  assert.equal(inspectZip(b).encrypted, false);
  assert.equal((await readZip(b)).text, '{"app":"otp-vault","entries":[]}');
});

console.log('— 异常输入 —');
await atest('非 ZIP 内容给出清晰错误', async () => {
  await assert.rejects(() => readZip(new TextEncoder().encode('{"a":1}'), 'x'), /不是有效的 ZIP/);
});
await atest('空密码拒绝导出', async () => {
  await assert.rejects(() => createEncryptedZip({ content: 'x', password: '' }), /请先设置备份密码/);
});
await atest('篡改密文会被 HMAC / CRC 检出', async () => {
  const zip = await createEncryptedZip({ content: CONTENT, password: PASSWORD, mode: 'aes' });
  const broken = Uint8Array.from(zip);
  broken[60] ^= 0x01;
  await assert.rejects(() => readZip(broken, PASSWORD), /密码不正确|校验失败/);
});

console.log(`\n通过 ${pass} 项`);
if (process.exitCode) process.exit(1);
