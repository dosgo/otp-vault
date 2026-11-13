/** RFC 6238 官方测试向量校验： node test/totp.test.mjs */
import assert from 'node:assert/strict';
import { generateTOTP, parseOtpauthURI, buildOtpauthURI, normalizeSecret } from '../totp.js';

const SHA1 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const SHA256 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA';
const SHA512 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA';

const vectors = [
  [SHA1, 'SHA1'],
  [SHA256, 'SHA256'],
  [SHA512, 'SHA512'],
];
const times = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000];
const expected = {
  SHA1: ['94287082', '07081804', '14050471', '89005924', '69279037', '65353130'],
  SHA256: ['46119246', '68084774', '67062674', '91819424', '90698825', '77737706'],
  SHA512: ['90693936', '25091201', '99943326', '93441116', '38618901', '47863826'],
};

let passed = 0;
for (const [secret, algorithm] of vectors) {
  for (let i = 0; i < times.length; i++) {
    const r = await generateTOTP({
      secret, algorithm, digits: 8, period: 30, timestamp: times[i] * 1000,
    });
    assert.equal(r.code, expected[algorithm][i], `${algorithm} @ ${times[i]}`);
    passed++;
  }
}

// RFC 4226 HOTP counter=0 等价校验（6 位）
const hotp0 = await generateTOTP({ secret: SHA1, digits: 6, timestamp: 0 });
assert.equal(hotp0.code, '755224');
assert.equal(hotp0.remaining, 30);
passed++;

// 密钥归一化：小写、空格、连字符
assert.equal(
  (await generateTOTP({ secret: 'gezdgnbvgy3tqojqgezdgnbvgy3tqojq ', digits: 6, timestamp: 0 })).code,
  '755224'
);
passed++;

// URI 解析与回写
const uri = 'otpauth://totp/GitHub:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60';
const parsed = parseOtpauthURI(uri);
assert.equal(parsed.issuer, 'GitHub');
assert.equal(parsed.account, 'alice@example.com');
assert.equal(parsed.algorithm, 'SHA256');
assert.equal(parsed.digits, 8);
assert.equal(parsed.period, 60);
assert.equal(normalizeSecret(parsed.secret), 'JBSWY3DPEHPK3PXP');
assert.equal(parseOtpauthURI(buildOtpauthURI(parsed)).secret, parsed.secret);
passed++;

console.log(`✅ TOTP 全部测试通过：${passed} 项（含 RFC 6238 SHA1/SHA256/SHA512 共 18 个向量）`);
