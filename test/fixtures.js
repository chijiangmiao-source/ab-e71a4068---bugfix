'use strict';
// 测试夹具：复用生产侧快照构造器与 MPT 构建器。
const { buildSnapshots } = require('../src/sample-snapshot');
const { Trie } = require('../src/trie');
const { toHex, keyHexToNibbles } = require('../src/hexutil');

// 前缀关系快照：较短指令标识是另一指令标识的前缀，短标识的承诺值落在分支值槽（16）。
//   短标识 5c   -> 00（未授权承诺）
//   子标识 5c0  -> 01（短标识追加半字节 0；启用承诺在子树叶节点）
//   短标识 7a   -> 01（反向场景：短标识自身即启用承诺）
//   子标识 7a0  -> 00
// 结构：根分支 -> 内嵌扩展 -> 内嵌分支（值槽 + 槽 0 内嵌叶）。
// 注意子标识为奇数长度 hex（追加单个半字节），须用 keyHexToNibbles 定位。
function buildPrefixSnapshots() {
  const trie = new Trie();
  const put = (keyHex, ...value) => trie.put(keyHexToNibbles(keyHex), Uint8Array.of(...value));

  put('5c', 0x00);
  put('5c0', 0x01);
  put('7a', 0x01);
  put('7a0', 0x00);

  const rootHash = trie.commit();

  return {
    trie,
    rootHash,
    rootHashHex: toHex(rootHash),
    keys: {
      prefixShort: '5c',
      prefixChild: '5c0',
      reverseShort: '7a',
      reverseChild: '7a0',
    },
    proofFor: (keyHex) => trie.proveKey(keyHexToNibbles(keyHex)),
  };
}

module.exports = { buildSnapshots, buildPrefixSnapshots };
