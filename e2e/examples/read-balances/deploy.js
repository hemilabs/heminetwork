const web3 = require('web3');
const solc = require('solc')
const fs = require('fs')
const optimism = require('@eth-optimism/sdk'); 
const ethers = require('ethers')

const deployContract = async (l, devAccount, filename, contractname) => {
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

    const output = (await new Promise((resolve, reject) => {
      solc.loadRemoteVersion("v0.8.23+commit.f704f362", (err, snapshot) => {
        if (err) {
          reject(err);
          return;
        }

        const compiled = JSON.parse(snapshot.compile(JSON.stringify(input)))

        if (compiled.errors && compiled.errors.length > 0) {
          reject(JSON.stringify(compiled.errors))
          return;
        }

        resolve(compiled);
      });
    }));


    const bytecode = output.contracts[filename][contractname].evm.bytecode.object;
    const abi = output.contracts[filename][contractname].abi;

    const contract = new l.eth.Contract(abi);

    const deployedContract = await contract
      .deploy({
        data: bytecode,
      })
      .send({
        from: devAccount,
        gas: "1853080",
      });

      console.log(`deployed contract to ${deployedContract.options.address}}`)

    return deployedContract;
} 

const main = async () => {
    const l1RpcUrl = `http://localhost:8545`;
    const l2RpcUrl = `http://localhost:8546`;
    const btcAddress = 'mw47rj9rG25J67G6W8bbjRayRQjWN5ZSEG'
    const l1StandardBridgeProxyAddress = `0x654fe8bC4F8Bf51f0CeC4567399aD7067E145C3F`
    const l1CrossDomainMessengerProxyAddress = '0xe50ea86676B29448a4e586511d8920105cEd1159'

    const l1Provider = new ethers.providers.StaticJsonRpcProvider(l1RpcUrl)
    const l2Provider = new ethers.providers.StaticJsonRpcProvider(l2RpcUrl)
    const messenger = new optimism.CrossChainMessenger({
      l1SignerOrProvider: l1Provider.getSigner(),
      l2SignerOrProvider: l2Provider,
      l1ChainId: 901,
      l2ChainId: 1337,
      bedrock: true, 
      contracts: {
        l1: {
          AddressManager: '0x6a977Ade8B7908D159B0068cF74C55F292b9B4fe',
          L1CrossDomainMessenger: '0xe50ea86676B29448a4e586511d8920105cEd1159',
          L1StandardBridge: "0x654fe8bC4F8Bf51f0CeC4567399aD7067E145C3F",
          OptimismPortal: '0x4859725d8f2f49aE689512eE5F150FdcB76cd72c',
          L2OutputOracle: '0xe67575204500AA637a013Db8fF9610940CACf9E6',
          // Need to be set to zero for this version of the SDK.
          StateCommitmentChain: ethers.constants.AddressZero,
          CanonicalTransactionChain: ethers.constants.AddressZero,
          BondManager: ethers.constants.AddressZero,
        }
      },
      l1BlockTimeSeconds: 3
    })

    const l1 = new web3.Web3(new web3.HttpProvider(l1RpcUrl));
    const l2 = new web3.Web3(new web3.HttpProvider(l2RpcUrl));

    const devAccount = (await l1.eth.getAccounts())[0];

    console.log(`dev account is ${devAccount}`);

    const feeData = await l1.eth.calculateFeeData();
    
    console.log(`balances before -- l1: ${await l1.eth.getBalance(devAccount)}, l2: ${await l2.eth.getBalance(devAccount)}`)
    const promiseEvent = l1.eth.sendTransaction({
        from: devAccount,
        to: l1StandardBridgeProxyAddress,
        value: 1000000000000000000000000000000000,
        maxFeePerGas: feeData.maxFeePerGas,
        maxPriorityFeePerGas: feeData.maxPriorityFeePerGas,
        gas: 1000000,
      });

      await new Promise((resolve, reject) => {
        promiseEvent.once("receipt", (r) => {
            console.log(`received receipt ${r.transactionHash}`)
            resolve();
        })
        promiseEvent.on("error", (e) => reject(e));
    });
    
    console.log(`balances after -- l1: ${await l1.eth.getBalance(devAccount)}, l2: ${await l2.eth.getBalance(devAccount)}`)
    
    await l2.eth.personal.unlockAccount(
        devAccount,
        "blahblahblah",
        30 * 1000
      );

      const deployedContract = await deployContract(l2, devAccount, 'ReadBalances.sol', 'ReadBalances');

      const otherDeployedContract = await deployContract(l1, devAccount, 'L1ReadBalances.sol', 'L1ReadBalances');


      const result = await deployedContract.methods.sendBitcoinAddressBalanceToL1(otherDeployedContract.options.address, btcAddress).send({
        from: devAccount
      });

      console.log(result)

      console.log('waiting for message status READY_TO_PROVE')

      await messenger.waitForMessageStatus(result.transactionHash, optimism.MessageStatus.READY_TO_PROVE);

      await messenger.proveMessage(result.transactionHash);

      console.log('waiting for message status READY_FOR_RELAY')

      await messenger.waitForMessageStatus(result.transactionHash, optimism.MessageStatus.READY_FOR_RELAY)

      await messenger.finalizeMessage(result.transactionHash)

      console.log('waiting for message status RELAYED')


      while (true) {
        const status = await messenger.getMessageStatus(result.transactionHash)
        console.log(`message status ${status}`)

        if (status === optimism.MessageStatus.RELAYED) {
          break;
        }

        await new Promise((resolve) => setTimeout(resolve, 5 * 1000))
      }

      await messenger.waitForMessageStatus(result.transactionHash, optimism.MessageStatus.RELAYED);

    const bitcoinBalance = await deployedContract.methods.getBitcoinAddressBalance(btcAddress).call()


    console.log(`bitcoin balance according to the l2 precompile is ${bitcoinBalance}`)
      
    while (true) {
      await new Promise((resolve) => setTimeout(resolve, 5 * 1000));

      const l1BtcBalance = await otherDeployedContract.methods.getBitcoinAddressBalance(btcAddress).call();
      console.log(`l1 btc balance is ${l1BtcBalance}`)
    }

} 

main()
.catch((e) => {
    throw e;
})