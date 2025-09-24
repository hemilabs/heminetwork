## Current state

Every block wind/unwind goes goes thorugh the following process:

### In

UTxO index
```
PkScript, Value = cache[PrevOut]                        // OutpointScriptValue
Balance = cache[sha256(PkScript)]                       // ScriptHash
cache[sha256(PkScript)] -= Value                        // ScriptHash
cache[sha256(PkScript) + height + hash + txid + PrevOut + txInIndex] = nil  // SpentOutput
```

Tx index
```
cache[PrevOut.Hash, height, hash, PrevOut.Index] = txid + txInIndex // SpendingOutpoint
```

### Out

UTxO index
```
cache[sha256(PkScript) + height + hash + txid + txOutIndex] = nil    // SpendableOutput
cache[Out] = TxOut                                      // OutpointScriptValue
cache[sha256(PkScript)] += Value                        // ScriptHash
```

Tx index
```
cache[txid + height + hash + txOutIndex] = nil          // SpendingOutpoint
```

### Unwinding

Cache values are mixed updates and inserts thus, on unwind there must be
updates and deletes. An example of an update are the `ScriptHash` to balance
rows. Those will either add or subtract an amount from the stored total and
will be updated in place. An example of an insert is a `SpentOutput` row, these
will be inserted at wind time and must be deleted at unwind time.

Practically speaking it seems like updates must always occur prior to deletes.
This does however not happen inside the database transaction but shouldn't
matter because it is an atomically committed batch.

### In

```
PkScript, Value = cache[PrevOut]                        // Lookup
Balance = cache[sha256(PkScript)]                       // Lookup
cache[sha256(PkScript)] += Value                        // Update balance
cache[sha256(PkScript) + height + hash + txid + PrevOut + txInIndex] = nil  // Delete
cache[PrevOut.Hash, height, hash, PrevOut.Index] = txid + txInIndex // Delete
```

### Out

```
Balance = cache[sha256(PkScript)]                                   // Lookup
cache[sha256(PkScript)] -= Value                                    // Update balance
cache[sha256(PkScript) + height + hash + txid + txOutIndex] = nil   // Delete
cache[Out] = TxOut                                                  // Delete
cache[txid + height + hash + txOutIndex] = nil                      // Delete
```

Thoughts
1. If we keep track of the balance in SpendableOutput we can get rid of
   OutpointScriptValue however that makes cache lookups O(N), disk is O log(N).
2. OutpointScriptValue is prunable.
3. With this format we must flip balance += and -= depending on direction.
4. I don't see the point of SpendableOutput. It isn't pruned and if spent, it
   is not marked as such. Cross referencing it with SpentOutput is O(N). It is
   not used as a cache input either. We probably should add the txid (or even
   SpendableOutput) to TxOut structure if we need a quick lookup of PrevOut to
   tx mapping.
5. When combining utxo+tx index it feels that we are overlapping
   spending/unspent data. It looks that this can be easily reconstructed from
   utxo SpentOutput, which may be another reason to prune some values.



## Raw thoughts and other junk

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

