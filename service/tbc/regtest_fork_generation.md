# Creating and saving a forked chain on regtest for testing TBC fork resolution

Steps to create a simple fork using a single Bitcoin regtest mode and save the block data so the fork can be re-experienced for testing.
Macro steps:
- Generate Chain A: 3 blocks starting from genesis
- Save the raw blocks so we can replay later
- Invalidate Chain A's 2nd block (index 1), which will be Chain B's forking point
- Generate Chain B: 3 blocks starting from the first block in Chain A (index 1)
- Save the raw blocks so we can replay later
- Restart Regtest from genesis
- Submit all Chain A blocks in order, daemon should end at Chain A tip
- Submit all Chain B blocks in order, daemon should end at Chain B tip which builds on Chain A's 2nd block (index 1)

# Requirements:
- Single VM with bitcoind installed/compiled

## Steps to create forked chain

### Start regtest
`> bitcoind -regtest --fallbackfee=1.0 --maxtxfee=1.1`

### Generate wallet to mine to
`> bitcoin-cli -regtest -named createwallet wallet_name="test_wallet" descriptors=true`

### Generate chain A
```
> bitcoin-cli -regtest -generate 3
{
  "address": "bcrt1qgu3wjqajjzehcdy3em30dltfge6r9aafwww44t",
  "blocks": [
    "7d50f33faeb76c9fd3494bfadbe7de6d4d51ba23926b522dcbeb16ba6b0771ff",
    "2c1148b90d4b28d51914ae5e17ff30731c14260f3c985372adb7ff49ceed3575",
    "2e4b4d599d5a6b1b9ecc1875ef7b1bf2341dc7fc8a4f31d6fbfa03263470ccda"
  ]
}
```

### Check that daemon is now on Chain B
`> bitcoin-cli -regtest getblockchaininfo`

You should see the last block from the generate command as `bestblockhash`.

### Get the hex Chain A blocks for future use (replace hashes with block hashes from "generate" output above)
```
> bitcoin-cli -regtest getblock 7d50f33faeb76c9fd3494bfadbe7de6d4d51ba23926b522dcbeb16ba6b0771ff 0
> bitcoin-cli -regtest getblock 2c1148b90d4b28d51914ae5e17ff30731c14260f3c985372adb7ff49ceed3575 0
> bitcoin-cli -regtest getblock 2e4b4d599d5a6b1b9ecc1875ef7b1bf2341dc7fc8a4f31d6fbfa03263470ccda 0
```
Save the returned hex for each block - this is the raw block data you will feed into the daemon later to re-create the fork.


### Invalidate a block in Chain A
`> bitcoin-cli -regtest invalidateblock 2c1148b90d4b28d51914ae5e17ff30731c14260f3c985372adb7ff49ceed3575`

In this example we invalidated the middle block, so the first block from Chain A will still be canonical.

### Mine another chain forking from the first block of Chain A (recall we invalidated 2nd block of Chain A)
```
> bitcoin-cli -regtest -generate 3
{
  "address": "bcrt1q9cj5pvsgxz72qcg9xy8ag7zjcm5hhdwy3pzrls",
  "blocks": [
    "1996a73ccba693a3b4ec648b8c26510b5465f16d29ce9f7aa6bdfe3c9b675029",
    "49765415defecbfcca1accc860fef42a9f2e6e83f0e00ffc9b5e48ea989c69f8",
    "5f7f1a37c28183dde53d0bd5f0e47d38e18f0160f9d2e29d3e467cc8037d3abe"
  ]
}
```

### Get the hex Chain B blocks for future use
```
> bitcoin-cli -regtest getblock 1996a73ccba693a3b4ec648b8c26510b5465f16d29ce9f7aa6bdfe3c9b675029 0
> bitcoin-cli -regtest getblock 49765415defecbfcca1accc860fef42a9f2e6e83f0e00ffc9b5e48ea989c69f8 0
> bitcoin-cli -regtest getblock 5f7f1a37c28183dde53d0bd5f0e47d38e18f0160f9d2e29d3e467cc8037d3abe 0
```
Save the returned hex for each block - this is the raw block data you will feed into the daemon later to re-create the fork.

### Check that daemon is now on Chain B (tip 5f7f1a37c28183dde53d0bd5f0e47d38e18f0160f9d2e29d3e467cc8037d3abe in our example)
`> bitcoin-cli -regtest getblockchaininfo`

You should see the last block from the most recent generate command as `bestblockhash`.

### Stop regtest and delete data dir
```
> bitcoin-cli -regtest stop
> rm -rf ~/.bitcoin
```

### Start regtest again
`> bitcoind -regtest --fallbackfee=1.0 --maxtxfee=1.1`

### Check we are back on genesis
`> bitcoin-cli -regtest getblockchaininfo`

You should see `blocks` set to 0, and `bestblockhash` set to 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206

### Add chain A
`> bitcoin-cli regtest submitblock <chainABlock1Hex>`

[Repeat command for each hex block saved from Chain A...]

# Check that chain A is tip
`> bitcoin-cli -regtest getblockchaininfo`

You should see the last Chain A block as `bestblockhash`

# Add chain B
`> bitcoin-cli regtest submitblock <chainBBlock2Hex>`

[Repeat command for each hex block saved from Chain B...]

# Check that chain B is tip
`> bitcoin-cli -regtest getblockchaininfo`

You should see the last Chain B block as `bestblockhash`, which indicates that the node correctly reorged to the longer Chain B.
