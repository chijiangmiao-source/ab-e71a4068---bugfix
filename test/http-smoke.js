'use strict';
// 对运行中的 web 服务执行端到端 HTTP 冒烟：
//   健康端点 / 静态入口页 / 示例快照 / 有效授权 / 篡改子节点引用 / 非规范 RLP / 前缀标识（短标识值槽 vs 子标识叶）
// 用法：BASE_URL=http://web:8080 node test/http-smoke.js
// 任一检查失败即以非零退出码结束。
const BASE = process.env.BASE_URL || 'http://127.0.0.1:8080';

let failures = 0;
function check(name, cond, detail) {
  if (cond) {
    console.log(`  ok - ${name}`);
  } else {
    failures += 1;
    console.log(`  FAIL - ${name}${detail ? '：' + detail : ''}`);
  }
}

async function postJson(path, body) {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: await res.json() };
}

function hexToBytes(hex) {
  return Uint8Array.from(Buffer.from(hex.startsWith('0x') ? hex.slice(2) : hex, 'hex'));
}

// 手工构造含非规范内嵌叶（c4 20 8101）的根分支 RLP。
function nonCanonicalNode() {
  const parts = [];
  for (let i = 0; i < 17; i++) parts.push(Buffer.from(i === 2 ? 'c4208101' : '80', 'hex'));
  const payload = Buffer.concat(parts);
  let prefix;
  if (payload.length < 56) prefix = Buffer.from([0xc0 + payload.length]);
  else {
    const lenBytes = [];
    let x = payload.length;
    while (x > 0) { lenBytes.push(x & 0xff); x = Math.floor(x / 256); }
    lenBytes.reverse();
    prefix = Buffer.from([0xf7 + lenBytes.length, ...lenBytes]);
  }
  return Buffer.concat([prefix, payload]);
}

function keccak256Local(bytes) {
  // 复用项目内实现，避免在冒烟脚本里依赖外部库。
  return require('../src/keccak').keccak256(bytes);
}
const { toHex } = require('../src/hexutil');
const { buildSnapshots } = require('../src/sample-snapshot');

async function main() {
  console.log(`HTTP 冒烟目标：${BASE}`);

  const health = await fetch(BASE + '/healthz');
  check('GET /healthz 返回 200', health.status === 200);
  const healthBody = await health.json();
  check('健康体 status=ok', healthBody.status === 'ok', JSON.stringify(healthBody));

  const home = await fetch(BASE + '/');
  check('GET / 返回 200 HTML', home.status === 200 && /text\/html/.test(home.headers.get('content-type') || ''));
  const homeHtml = await home.text();
  check('入口页含三要素表单与静态入口标题',
    homeHtml.includes('name="rootHash"') && homeHtml.includes('name="keyHex"') &&
    homeHtml.includes('name="proofNodes"') && homeHtml.includes('离线指令授权快照复核'));

  const sampleRes = await fetch(BASE + '/api/sample');
  check('GET /api/sample 返回 200', sampleRes.status === 200);
  const sample = await sampleRes.json();
  check('示例含 32 字节根哈希', /^[0-9a-f]{64}$/.test(sample.rootHash));
  check('示例含已授权/未授权两套用例', !!sample.cases.authorized && !!sample.cases.unauthorized);

  // 场景一：有效授权
  const ok = await postJson('/api/verify', sample.cases.authorized);
  check('有效授权：HTTP 200', ok.status === 200);
  check('有效授权：status=authorized 且叶值 01',
    ok.json.result && ok.json.result.status === 'authorized' && ok.json.result.value === '01',
    JSON.stringify(ok.json.result && ok.json.result.status));
  check('结果页显示“已授权”并逐层回放',
    typeof ok.json.page === 'string' && ok.json.page.includes('已授权') &&
    ok.json.page.includes('累计已消费路径') && ok.json.page.includes('节点摘要'));

  // 场景二：篡改子节点引用（翻转第 2 个证明节点末尾一字节）
  const tampered = JSON.parse(JSON.stringify(sample.cases.authorized));
  const nodes = tampered.proofNodes.map(hexToBytes);
  nodes[1][nodes[1].length - 1] ^= 0x01;
  tampered.proofNodes = nodes.map((b) => toHex(b));
  const bad = await postJson('/api/verify', tampered);
  check('篡改引用：status=invalid / REF_MISMATCH / 第 2 层',
    bad.json.result && bad.json.result.status === 'invalid' &&
    bad.json.result.code === 'REF_MISMATCH' && bad.json.result.firstFailedLayer === 2,
    JSON.stringify(bad.json.result && bad.json.result.code));
  check('篡改页标明首个失败层且无“已授权”横幅',
    bad.json.page.includes('证明无效') && bad.json.page.includes('第 2 层') &&
    !bad.json.page.includes('banner-title">已授权'));

  // 场景三：非规范 RLP
  const ncNode = nonCanonicalNode();
  const nc = await postJson('/api/verify', {
    rootHash: toHex(keccak256Local(ncNode)),
    keyHex: '02',
    proofNodes: toHex(ncNode),
  });
  check('非规范 RLP：status=invalid / RLP_NONCANONICAL / 第 1 层',
    nc.json.result && nc.json.result.status === 'invalid' &&
    nc.json.result.code === 'RLP_NONCANONICAL' && nc.json.result.firstFailedLayer === 1,
    JSON.stringify(nc.json.result && nc.json.result.code));
  check('非规范页不含旧成功结论', nc.json.page.includes('证明无效') && !nc.json.page.includes('banner-title">已授权'));

  // 未授权：完整抵达叶但值 00
  const no = await postJson('/api/verify', sample.cases.unauthorized);
  check('未授权：status=unauthorized 且保留路径证据',
    no.json.result && no.json.result.status === 'unauthorized' &&
    no.json.result.value === '00' && no.json.result.layers.length > 0);
  check('未授权页明确显示“未授权”', no.json.page.includes('未授权'));

  // 前缀场景：同一快照中短标识（值槽 00）是子标识（叶 01）的前缀。
  // 本地按同一构造器重放快照，根哈希须与服务端示例一致。
  const local = buildSnapshots();
  check('本地重放缓照与示例根哈希一致', local.rootHashHex === sample.rootHash);
  const mkProof = (keyHex) => ({
    rootHash: local.rootHashHex,
    keyHex,
    proofNodes: local.proofFor(keyHex).map((p) => toHex(p)),
  });
  const short = await postJson('/api/verify', mkProof(local.keys.prefixShort));
  check('前缀短标识：status=unauthorized 且值槽值 00、路径恰好为短标识',
    short.json.result && short.json.result.status === 'unauthorized' &&
    short.json.result.value === '00' && short.json.result.consumedPath === local.keys.prefixShort &&
    short.json.result.layers[short.json.result.layers.length - 1].kind === 'branch-value',
    JSON.stringify(short.json.result && short.json.result.status));
  check('前缀短标识页显示“未授权”且含值槽终止证据、无“已授权”横幅',
    short.json.page.includes('未授权') && short.json.page.includes('分支节点（值槽）') &&
    !short.json.page.includes('banner-title">已授权'));
  const child = await postJson('/api/verify', mkProof(local.keys.prefixChild));
  check('子标识：status=authorized 且叶值 01、路径为短标识 + 一个半字节',
    child.json.result && child.json.result.status === 'authorized' &&
    child.json.result.value === '01' && child.json.result.consumedPath === local.keys.prefixChild,
    JSON.stringify(child.json.result && child.json.result.status));
  check('子标识页显示“已授权”', child.json.page.includes('已授权'));

  console.log(`\nHTTP 冒烟：${failures === 0 ? '全部通过 ✅' : failures + ' 项失败'}`);
  process.exitCode = failures === 0 ? 0 : 1;
}

main().catch((e) => {
  console.error('HTTP 冒烟运行器异常（目标可能未就绪）：', e.message);
  process.exit(2);
});
