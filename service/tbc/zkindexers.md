# ZK & Hemi sitting in a tree

tl;dr We want to be able to quickly and succinctly prove "bitcoin state".

## Why are we doing this?

The reason for this is create pre-compiles in evm that can be "easily" and
"quickly" verified to enable complex functionality such as tunneling funds to
and from bitcoin. In order to do these complex functions we need primitives
that prove positives and negatives.

Examples:

* Does this utxo exist?
* Has this utxo been spent? When? Whereto?
* What is the balance of this address?

## How are we doing this?

We are compressing bitcoin state in a way that can be quickly and easily
accessed (zkindexers).

On top of that data we "compress" the overall state of various bitcoin stateless
properties and positional data to get to a succinct representation of bitcoin
state.

The big challenge is how do we compress delta state to positonal verifiable
state so that we do not feed "many" inputs into the zk prover. For example, if
a utxo came into existence in block 1000, how do we verify it's inclusion and
non-spending status at block 9897 without traversing 7897 blocks and
"accumulated state"? We have been referring to this as "the merkleization of
state".

## Why ZK?

While we are really only after succinctly proving data and not zero-knowledge
there exist no better system than ZK which happens to include all the things we
need. Our problem can be narrowed down to "compressing bitcoin state" and use
the various ZK algorithms do the hard math.

## What is ZK?

A zero-knowledge proof is a cryptographic protocol that can improve data
privacy. It allows one party, known as the prover, to assure another party, the
verifier, that a statement is true without revealing any extra information. For
example, the prover can convince the verifier that they know a specific number
without actually revealing it.

## ZK indexers

Every block wind/unwind goes through the following process:

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
cache[PrevOut.Hash, height, hash, PrevOut.Index] = txid + txInIndex // SpendingOutpointKey = SpendingOutpointValue
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

### Overall state

We need to roll-up the entire state of a block too as we process the indexer.
The state will be rolled-up in a merkle tree and will contain the following
information:

```
sha256(be_uint32(height) + blockhash)                             // Positional proof
sha256(blockheader + FillBytes(cumdiff))                          // Header and cumdiff
for range block.ins { sha256(SpentOutput+SpendingOutpointValue) } // Spent ouput by where
for range block.outs { sha256(SpendableOutput) }                  // Spendables outputs
utxo delta state root = merkle(ins, outs)
utxo state root = trie root
```

After rolling up a block it needs to recorded as the transition from the
parent. This works just like blockheaders do. It is stacked on top of a parent
with a cumulative state change.

```
db[sha256(be_uint32(height) + blockhash)] = merkle(utxo state root, utxo delta state root, parent.state.merkleroot, state.merkleroot) + state.merkletree
```

This stores the state transition at blockhash+blockheight which is witnessed
inside the state.merkletree and witness the stacking on top of a parent.

Thoughts:

1. There are a few corners hiding in there and maybe we should roll up the
   state change merkle into the overall block merkle we are generating.
2. Consensus enforces parent before child Tx's in the blockheader merkle root.
   This practically means we can handle Tx's in order of appearance (reverse on
   unwind).
3. This can in theory proof the entire chain "positionally" but you do have to
   show up with a whole lot of inputs.

### Trie

//Range over ins
//    create a delete map of
//        key = sha256(PkScript)
//        value = []PrevOutpoint
//
//Range over utxos
//    key = sha256(PkScript)
//    value = []Outpoint{txid + txOutIndex}
//
//Roll up the ins and utxos as a single key to update on disk
//
//for this height tell me if thuis utxo was spent

every block we want to record the new state of the utxo set.

new trie
Range over ins
    create a delete map of
        address trie
            key = sha256(PkScript) // address fake keccak of sha256(pkscript)
            value -= value
        storage trie
            key = sha256(PkScript)
            value =
                key = sha256(outpoint) // fixed 32 bytes so sha
                value = nil

Range over utxos
        address trie
            key = sha256(PkScript) // address fake keccak of sha256(pkscript)
            value += value
        storage trie
            key = sha256(PkScript)
            value =
                key = sha256(outpoint) // fixed 32 bytes so sha
                value = pkscript+value

commit above

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
        fear that this structure will balloon and we may have to keep "just the latest"

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
