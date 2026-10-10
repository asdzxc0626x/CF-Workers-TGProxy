#!/usr/bin/env node
/**
 * 混淆产物校验
 *
 *   1. 语法：混淆产物必须是合法 ES module（Workers 模块语法）；
 *   2. 行为：把 telegram_webproxy.js 与 telegram_webproxy.obfuscated.js
 *      同时当模块加载，对同一组请求断言响应一致；
 *   3. 混淆度：断言产物里不再残留源文件的可读字符串。
 *
 * 用法：npm run check
 *
 * 之所以要把两个文件复制成 .mjs 再加载：package.json 里 type 是 commonjs，
 * Node 会把 .js 按 CJS 解析，而这两个文件都是 ES module 语法。
 */
import { webcrypto } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SOURCE = path.join(root, 'telegram_webproxy.js');
const OUTPUT = path.join(root, 'telegram_webproxy.obfuscated.js');

const SECRET = 'dd0123456789abcdef0123456789abcdef';
const BOOT = 'verify-boot-token-0123456789abcdef';
const HOST = 'worker.example.com';
const env = { SECRET, BOOT };

let failures = 0;
const ok = (name, extra = '') => console.log(`  PASS  ${name}${extra ? `  ${extra}` : ''}`);
const bad = (name, detail) => {
  failures++;
  console.log(`  FAIL  ${name}\n        ${detail}`);
};

// ---- 复制成 .mjs 后加载 ------------------------------------------------

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tgproxy-verify-'));
const asModule = (src, name) => {
  const dest = path.join(tmp, name);
  fs.copyFileSync(src, dest);
  return dest;
};

const plainPath = asModule(SOURCE, 'plain.mjs');
const obfPath = asModule(OUTPUT, 'obf.mjs');

// 语法检查：node --check 按 .mjs 解析，不执行
try {
  execFileSync(process.execPath, ['--check', obfPath], { stdio: 'pipe' });
  ok('混淆产物语法合法（ES module）');
} catch (err) {
  bad('混淆产物语法非法', String(err.stderr || err.message).trim().split('\n').slice(0, 4).join('\n        '));
  process.exit(1);
}

const plain = (await import(`file://${plainPath}`)).default;
const obf = (await import(`file://${obfPath}`)).default;

for (const [label, mod] of [['明文', plain], ['混淆', obf]]) {
  if (typeof mod?.fetch !== 'function') bad(`${label}版导出 fetch`, `实际拿到 ${typeof mod?.fetch}`);
}
if (failures) process.exit(1);

// ---- 构造一个合法 bridge 签名（复刻 mkCap） ----------------------------

const txt = new TextEncoder();
const hexBytes = s => Uint8Array.from(s.match(/..?/g).map(h => parseInt(h.padEnd(2, '0'), 16)));
const b64 = b => Buffer.from(b).toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');

async function mkCap(secret, host) {
  const raw = secret.trim().toLowerCase();
  const material = hexBytes(raw.length === 34 && raw.startsWith('dd') ? raw : raw.slice(-32));
  const key = await webcrypto.subtle.importKey('raw', material, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await webcrypto.subtle.sign('HMAC', key, txt.encode(`tdesktop-web-proxy-bridge-v1\n${host}`));
  return b64(new Uint8Array(sig));
}

const cap = await mkCap(SECRET, HOST);

// ---- 请求用例 ----------------------------------------------------------

const CASES = [
  ['GET /health 有 env', new Request('https://x/health'), env],
  ['GET /health 无 env', new Request('https://x/health'), {}],
  ['GET /?bridge= 合法', new Request(`https://${HOST}/?bridge=${cap}`), env],
  ['HEAD /?bridge= 合法', new Request(`https://${HOST}/?bridge=${cap}`, { method: 'HEAD' }), env],
  ['GET / 无 bridge', new Request('https://x/'), env],
  ['GET /?bridge= 伪造', new Request(`https://${HOST}/?bridge=${'A'.repeat(43)}`), env],
  ['POST /api/v1/session 无鉴权', new Request('https://x/api/v1/session', { method: 'POST' }), env],
  ['DELETE /api/v1/session 无鉴权', new Request('https://x/api/v1/session', { method: 'DELETE' }), env],
  ['GET /api/v1/ws 无 Upgrade', new Request('https://x/api/v1/ws'), env],
  ['GET /nope', new Request('https://x/nope'), env],
];

// 页面里有随机 nonce / bootstrap，比对前把长 token 归一化
const normalize = s => s.replace(/[A-Za-z0-9_-]{20,}/g, '<TOKEN>');

const run = async (mod, [name, req, e]) => {
  const res = await mod.fetch(req.clone(), e);
  return {
    status: res.status,
    headers: [...res.headers]
      .filter(([k]) => k !== 'date')
      .map(([k, v]) => [k, normalize(v)]) // CSP 里的 nonce 每次随机，同样要归一化
      .sort(([a], [b]) => a.localeCompare(b)),
    body: normalize(await res.text()),
  };
};

for (const c of CASES) {
  const [name] = c;
  let a, b;
  try {
    a = await run(plain, c);
  } catch (err) {
    bad(name, `明文版抛错：${err.message}`);
    continue;
  }
  try {
    b = await run(obf, c);
  } catch (err) {
    bad(name, `混淆版抛错：${err.message}`);
    continue;
  }
  if (a.status !== b.status) bad(name, `status 不一致：明文 ${a.status} vs 混淆 ${b.status}`);
  else if (JSON.stringify(a.headers) !== JSON.stringify(b.headers)) {
    bad(name, `header 不一致：明文 ${JSON.stringify(a.headers)} vs 混淆 ${JSON.stringify(b.headers)}`);
  } else if (a.body !== b.body) {
    bad(name, `body 不一致：明文 ${a.body.length}B vs 混淆 ${b.body.length}B`);
  } else {
    ok(name, `status ${a.status}, ${a.body.length}B`);
  }
}

// 合法 bridge 页面必须真的下发成功，避免「两边都 404」这种假通过
const pageRes = await plain.fetch(new Request(`https://${HOST}/?bridge=${cap}`), env);
const pageBody = await pageRes.text();
const csp = pageRes.headers.get('Content-Security-Policy') ?? '';
if (pageRes.status === 200 && csp.includes('frame-ancestors http://127.0.0.1:*') && pageBody.includes('tproxy-init')) {
  ok('明文版 bridge 页面可作为基线');
} else {
  bad('明文版 bridge 页面基线异常', `status ${pageRes.status}, csp=${csp.slice(0, 80)}`);
}

// ---- 混淆度 ------------------------------------------------------------

const obfCode = fs.readFileSync(OUTPUT, 'utf8');
const LEAKS = [
  'tproxy-lane-v1',
  'web.telegram.org',
  'Sec-WebSocket-Protocol',
  'frame-ancestors',
  'apiws',
  'X-Session-Token',
  'websocket-lanes',
];
const leaked = LEAKS.filter(s => obfCode.includes(s));
if (leaked.length) bad('产物残留明文串', leaked.join(', '));
else ok('产物无可读业务串', `${LEAKS.length} 个哨兵字符串均已被字符串数组吞掉`);

if (!/export\s*\{/.test(obfCode) && !/export default/.test(obfCode)) {
  bad('产物丢失 export', 'Cloudflare Workers 模块语法要求 export default');
} else {
  ok('产物保留 export default');
}

// ---- 收尾 --------------------------------------------------------------

fs.rmSync(tmp, { recursive: true, force: true });

console.log(
  failures === 0
    ? `\n全部通过：${CASES.length} 个对拍用例 + 语法 + 混淆度检查`
    : `\n${failures} 项失败`,
);
process.exit(failures === 0 ? 0 : 1);
