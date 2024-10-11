# Example: Read Balances

*Warning: This example is NOT production ready; it is merely to demonstrate
localnet development and btc <-> eth interoperability.*

A short example to read a BTC balance from Hemi L2 and send that value to a 
contract on Eth L1.  We then read that value from a smart contract and print it.


## Requirements

* Localnet running
    * see `heminetwork` README on how to run localnet
* node installed
    * I have used and tested with `v21.1.0`


## For the impatient

install deps

```
npm install
```

run example

```
npm run example
```

## Step by step explaination

### Write the contracts

We will need two contracts to achieve our goal: a contract on L2 that has access
to hVM precompiles that reads a bitcoin address balance and a contract on L1
that receives this data and stores it, allowing it to be read.

You can find the L1 contract [here](L1ReadBalances.sol)

You can find the L2 contract [here](L2ReadBalances.sol)

We will be calling `L2ReadBalances.sendBitcoinAddressBalanceToL1` to read the 
bitcoin balance of an address then send that balance via the 
`CrossDomainMessenger` to L1.

`L1ReadBalances` will store this in a `mapping`, then we will be able to read 
that mapping value.

### Bridge some Eth to Hemi Eth

We will need to deploy our L2 contract, and thus will need Hemi Eth.  We can 
do this by using the `L1StandardBridgeProxy`.

We bridge Eth from the dev account (we run the L1 in dev mode, this is the
account that receives the funds) to our dev account on L2.

```javascript
l1.eth.sendTransaction({
    from: devAccount,
    to: l1StandardBridgeProxyAddress,
    value: 1000000000000000000000000000000000,
    maxFeePerGas: feeData.maxFeePerGas,
    maxPriorityFeePerGas: feeData.maxPriorityFeePerGas,
    gas: 1000000,
});
```

Now that we have bridged Hemi Eth, we can deploy our L2 contract.  There is a
bit too much to paste here, please view the use of the `deployContract` function
in [index.js](index.js).


### Call our L2 contract

We call our L2 contract to read the bitcoin balance of the regtest miner's 
address.  This can be done like so (where `deployedContract` is the L2 contract)

```javascript
const result = await deployedContract.methods
.sendBitcoinAddressBalanceToL1(
    l1DeployedContract.options.address,
    btcAddress,
)
.send({
    from: devAccount,
});
```

### Prove and relay the transaction

Using the `result` from above, we need to prove the transaction, then finalize
(relay) it to L1.

Again, view [index.js](index.js) for more details.

```javascript
console.log("waiting for message status READY_TO_PROVE");

  await waitForStatus(
    messenger,
    result.transactionHash,
    optimism.MessageStatus.READY_TO_PROVE,
    5 * 1000,
  );

  await messenger.proveMessage(result.transactionHash);

  console.log("waiting for message status READY_FOR_RELAY");

  await waitForStatus(
    messenger,
    result.transactionHash,
    optimism.MessageStatus.READY_FOR_RELAY,
    5 * 1000,
  );

  await messenger.finalizeMessage(result.transactionHash);

  console.log("waiting for message status RELAYED");

  await waitForStatus(
    messenger,
    result.transactionHash,
    optimism.MessageStatus.RELAYED,
    5 * 1000,
  );
```

### Read the balances

We can read the L1 and L2 btc balances.

*Note: L2 may be higher than L1, since that btc address has been mining bitcoin
while our script has been running.*

```javascript
const bitcoinBalance = await deployedContract.methods
    .getBitcoinAddressBalance(btcAddress)
    .call();

  console.log(
    `bitcoin balance according to the l2 precompile is ${bitcoinBalance}`,
  );

  const l1BtcBalance = await l1DeployedContract.methods
    .getBitcoinAddressBalance(btcAddress)
    .call();

  console.log(
    `l1 btc balance is ${l1BtcBalance} (should be <= than l2 ${bitcoinBalance})`,
  );
```