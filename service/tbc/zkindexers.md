## Raw

global hvm state root is a merkle over: utxo, txid, block hash, block height

at any height we end up with the merkle of the 4 pieces described above

block height -> block hash
        roll up sha256(height+hash)

block hash -> block info
        roll up tbcd.BlockHeader

txid_height_hash -> rolling tx spend
        roll up vout index + spend info (spending txin:vidx)

sha256(spendscript)_height_hash_txid_vin/vout_vin/voutindex -> cumulative balance
        fear that this structure will baloon and we may have to keep "just the latest"

After generating the merkle we must record the state transition to this block
which is the merkle root of the parent + merkle rooto of self.

Store this also in the db as
        "statetrans"_height_hash -> sha256(parent_merkle_root + self_merkle_root) + self_merkle_tree

## ZK indexers

There are various indexers in `tbc` to handle zero knowledge proofs (zkps). The
indexers exist to quickly gather data required to handle a zkp.

### Blockheader indexer

This index encodes block headers including emergent height and cumulative
difficulty. It consists of two indexes in the same table.

Block Height Hash indexer has no payload and the index key is encoded as
follows:
```
 0 1          4 5       37
+-+------------+----------+
|h|block height|block hash|
+-+------------+----------+
```

Block header is encoded as follows:
```
 0       31      0    3 4   83 84
+----------+    +------+------+----------+
|block hash| -> |height|header|difficulty|
+----------+    +------+------+----------+
```
XXX Note that we reuse the encoding from height/hash that encodes height as
uint64 so these values are off. This needs to be corrected.

