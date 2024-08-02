const web3 = require("web3");
const solc = require("solc");
const fs = require("fs");
const optimism = require("@eth-optimism/sdk");
const ethers = require("ethers");

const solcVersion = "v0.8.23+commit.f704f362";

main()
  .then(() => {
    console.log("done");
  })
  .catch((e) => {
    throw e;
  });

async function main() {
  const l1RpcUrl = `http://localhost:8545`;
  const l2RpcUrl = `http://localhost:8546`;

  const btcAddress = "mw47rj9rG25J67G6W8bbjRayRQjWN5ZSEG";
  const l1StandardBridgeProxyAddress = `0x654fe8bC4F8Bf51f0CeC4567399aD7067E145C3F`;

  const l1 = new web3.Web3(new web3.HttpProvider(l1RpcUrl));
  const l2 = new web3.Web3(new web3.HttpProvider(l2RpcUrl));

  const l1Provider = new ethers.providers.StaticJsonRpcProvider(l1RpcUrl);
  const l2Provider = new ethers.providers.StaticJsonRpcProvider(l2RpcUrl);
  const messenger = new optimism.CrossChainMessenger({
    l1SignerOrProvider: l1Provider.getSigner(),
    l2SignerOrProvider: l2Provider,
    l1ChainId: 901,
    l2ChainId: 1337,
    bedrock: true,
    contracts: {
      l1: {
        AddressManager: "0x6a977Ade8B7908D159B0068cF74C55F292b9B4fe",
        L1CrossDomainMessenger: "0xe50ea86676B29448a4e586511d8920105cEd1159",
        L1StandardBridge: l1StandardBridgeProxyAddress,
        OptimismPortal: "0x4859725d8f2f49aE689512eE5F150FdcB76cd72c",
        L2OutputOracle: "0xe67575204500AA637a013Db8fF9610940CACf9E6",
        // Need to be set to zero for this version of the SDK.
        StateCommitmentChain: ethers.constants.AddressZero,
        CanonicalTransactionChain: ethers.constants.AddressZero,
        BondManager: ethers.constants.AddressZero,
      },
    },
    l1BlockTimeSeconds: 3,
  });

  const devAccount = (await l1.eth.getAccounts())[0];

  console.log(`dev account is ${devAccount}`);

  const feeData = await l1.eth.calculateFeeData();

  const tx = {
    from: devAccount,
    to: l1StandardBridgeProxyAddress,
    value: 1000000000000000000000000000000000,
    maxFeePerGas: feeData.maxFeePerGas,
    maxPriorityFeePerGas: feeData.maxPriorityFeePerGas,
  };

  const gasEstimate = await l1.eth.estimateGas(tx);

  console.log(`bridging eth -> hemi eth with gas estimate ${gasEstimate}`);

  const sentTransaction = await l1.eth.sendTransaction(
    Object.assign(
      {
        gas: gasEstimate,
      },
      tx,
    ),
  );

  console.log(`done with bridging, gas used ${sentTransaction.gasUsed}`);

  await l2.eth.personal.unlockAccount(devAccount, "blahblahblah", 30 * 1000);

  const deployedContract = await deployContract(
    l2,
    devAccount,
    "L2ReadBalances.sol",
    "L2ReadBalances",
  );

  const l1DeployedContract = await deployContract(
    l1,
    devAccount,
    "L1ReadBalances.sol",
    "L1ReadBalances",
  );

  const result = await deployedContract.methods
    .sendBitcoinAddressBalanceToL1(
      l1DeployedContract.options.address,
      btcAddress,
    )
    .send({
      from: devAccount,
    });

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

  const bitcoinBalance = await deployedContract.methods
    .getBitcoinAddressBalance(btcAddress)
    .call();

  console.log(
    `bitcoin balance according to the l2 precompile is ${bitcoinBalance}`,
  );

  const addressBalanceResult = await l1DeployedContract.methods
    .getBitcoinAddressBalance(btcAddress)
    .call();

  const l1BtcBalance = addressBalanceResult[0];
  const blockHeight = addressBalanceResult[1];

  console.log(`l1 btc balance is ${l1BtcBalance} @ l2 height ${blockHeight}`);
}

async function deployContract(layer, devAccount, filename, contractname) {
  const fc = fs.readFileSync(filename).toString();

  const input = {
    language: "Solidity",
    sources: {
      [filename]: {
        content: fc,
      },
    },
    settings: {
      outputSelection: {
        "*": {
          "*": ["*"],
        },
      },
    },
  };

  const output = await new Promise((resolve, reject) => {
    solc.loadRemoteVersion(solcVersion, (err, snapshot) => {
      if (err) {
        reject(err);
        return;
      }

      const compiled = JSON.parse(snapshot.compile(JSON.stringify(input)));

      if (compiled.errors && compiled.errors.length > 0) {
        reject(JSON.stringify(compiled.errors));
        return;
      }

      resolve(compiled);
    });
  });

  const bytecode = output.contracts[filename][contractname].evm.bytecode.object;
  const abi = output.contracts[filename][contractname].abi;

  const contract = new layer.eth.Contract(abi);

  console.log(`deploying contract ${contractname}`);

  const deployedContract = await contract
    .deploy({
      data: bytecode,
    })
    .send({
      from: devAccount,
    });

  console.log(`deployed contract to ${deployedContract.options.address}`);

  return deployedContract;
}

// I was having issues debugging optimism's waitForStatus, this one provides
// logging on polls
async function waitForStatus(messenger, hash, status, pollInterval) {
  while (true) {
    const currentStatus = await messenger.getMessageStatus(hash);
    console.log(`waiting for status ${status}, received ${currentStatus}`);
    if (currentStatus === status) {
      break;
    }

    await new Promise((resolve) => setTimeout(resolve, pollInterval));
  }
}
