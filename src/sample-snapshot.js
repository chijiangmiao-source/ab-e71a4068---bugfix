'use strict';
// 内置离线示例快照：构造一棵覆盖 扩展/分支/叶、内嵌节点与 32 字节散列引用的 MPT。
// 供入口页“一键载入示例”与验收冒烟使用；真实使用时审查员导入自己的离线快照。
const { Trie } = require('./trie');
const { toHex, keyHexToNibbles } = require('./hexutil');

function buildSnapshots() {
  const trie = new Trie();
  // keyHexToNibbles 支持奇数长度标识（如子标识 b50），Buffer.from(hex) 会静默截断奇数半字节。
  const put = (keyHex, ...value) => trie.put(keyHexToNibbles(keyHex), Uint8Array.of(...value));

  // 深前缀族：迫使上层出现扩展节点与散列引用
  put('0123456789abcdef0123', 0x01); // 有效授权目标
  put('0123456789abcdef0124', 0x00); // 同构兄弟键：叶值 00 -> 未授权
  put('0123456789abcdef0abc', 0x01);
  put('0123456789abdddddddd', 0x02);
  // 另一前缀族
  put('fedcba9876543210abcd', 0x01);
  put('fedcba9876543210abce', 0x01);
  // 短键：迫使分支槽下出现 < 32 字节的内嵌叶节点
  put('a1', 0x00);
  put('a2', 0x01);
  // 前缀族：较短标识 b5 是子标识 b50 的前缀——短标识承诺 00 落于分支值槽（槽 16），
  // 子标识承诺 01 落于分支槽 0 的内嵌叶；长尾兄弟键迫使该分支以 32 字节散列引用。
  put('b5', 0x00);
  put('b50', 0x01);
  put('b5f0123456789abcdef0123456789abcd', 0x01);

  const rootHash = trie.commit();

  const proofFor = (keyHex) => trie.proveKey(keyHexToNibbles(keyHex));

  return {
    trie,
    rootHash,
    rootHashHex: toHex(rootHash),
    keys: {
      authorized: '0123456789abcdef0123',
      unauthorized: '0123456789abcdef0124',
      otherAuthorized: 'a2',
      shortUnauthorized: 'a1',
      prefixShort: 'b5',
      prefixChild: 'b50',
    },
    proofFor,
  };
}

module.exports = { buildSnapshots };
