#!/usr/bin/env node
/**
 * CF-Workers-TGProxy 混淆构建
 *
 *   telegram_webproxy.js  ->  telegram_webproxy.obfuscated.js
 *
 * 用法：
 *   npm run obfuscate
 *
 * 对照参考实现（cfnew 的 .github/workflows/obfuscate.yml）保持同一套
 * javascript-obfuscator 选项，只做两处必要调整：
 *
 *   1. 源/产物文件名换成本项目里的实际文件；
 *   2. 产物写回仓库根目录，方便直接复制进 Cloudflare Workers 面板。
 *
 * 注意：selfDefending / debugProtection 必须保持 false。
 * 这两个选项会在运行时自校验 / 自断点，而 Cloudflare Workers 上传后
 * 会重新压缩与改写脚本，自校验会直接把 Worker 打挂。
 */
const JavaScriptObfuscator = require('javascript-obfuscator');
const fs = require('fs');
const path = require('path');

const SOURCE_FILE = 'telegram_webproxy.js';
const OUTPUT_FILE = 'telegram_webproxy.obfuscated.js';

const sourcePath = path.join(__dirname, SOURCE_FILE);
const outputPath = path.join(__dirname, OUTPUT_FILE);

if (!fs.existsSync(sourcePath)) {
  console.error(`错误：未找到源文件 ${sourcePath}`);
  process.exit(1);
}

const originalCode = fs.readFileSync(sourcePath, 'utf8');
if (!originalCode.trim()) {
  console.error(`错误：源文件 ${SOURCE_FILE} 为空。`);
  process.exit(1);
}

const obfuscationOptions = {
  compact: true,
  controlFlowFlattening: false,
  controlFlowFlatteningThreshold: 0,
  deadCodeInjection: false,
  stringArray: true,
  stringArrayEncoding: ['base64'],
  stringArrayThreshold: 1.0,
  stringArrayRotate: true,
  stringArrayShuffle: true,
  stringArrayWrappersCount: 2,
  stringArrayWrappersChainedCalls: false,
  stringArrayWrappersParametersMaxCount: 3,
  renameGlobals: true,
  identifierNamesGenerator: 'mangled-shuffled',
  identifierNamesCache: null,
  identifiersPrefix: '',
  renameProperties: false,
  renamePropertiesMode: 'safe',
  ignoreImports: false,
  target: 'browser',
  numbersToExpressions: false,
  simplify: false,
  splitStrings: true,
  splitStringsChunkLength: 1,
  transformObjectKeys: false,
  unicodeEscapeSequence: true,
  selfDefending: false,
  debugProtection: false,
  debugProtectionInterval: 0,
  disableConsoleOutput: false,
  domainLock: [],
};

const t0 = Date.now();
const obfuscatedCode = JavaScriptObfuscator.obfuscate(
  originalCode,
  obfuscationOptions,
).getObfuscatedCode();

fs.writeFileSync(outputPath, obfuscatedCode, 'utf8');

const kb = n => `${(n / 1024).toFixed(1)} KB`;
console.log(`源文件   ${SOURCE_FILE}  ${kb(Buffer.byteLength(originalCode))}`);
console.log(`混淆产物 ${OUTPUT_FILE}  ${kb(Buffer.byteLength(obfuscatedCode))}`);
console.log(
  `膨胀     ${(Buffer.byteLength(obfuscatedCode) / Buffer.byteLength(originalCode)).toFixed(1)}x   耗时 ${Date.now() - t0} ms`,
);
