const web3 = require('web3');
const solc = require('solc')
const fs = require('fs')

const main = async () => {
    const l1RpcUrl = `http://localhost:8545`;
    const l2RpcUrl = `http://localhost:8546`;
    const l1StandardBridgeProxyAddress = `0x654fe8bC4F8Bf51f0CeC4567399aD7067E145C3F`
    const l1CrossDomainMessengerProxyAddress = '0xe50ea86676B29448a4e586511d8920105cEd1159'

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

      const ReadBalancesFileContents = fs.readFileSync("./ReadBalances.sol").toString();

    const input = {
      language: "Solidity",
      sources: {
        "ReadBalances.sol": {
          content: ReadBalancesFileContents,
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

        resolve(JSON.parse(snapshot.compile(JSON.stringify(input))));
      });
    }));

    await l2.eth.personal.unlockAccount(
        devAccount,
        "blahblahblah",
        30 * 1000
      );

    const bytecode = output.contracts["ReadBalances.sol"]["ReadBalances"].evm.bytecode.object;
    const abi = output.contracts["ReadBalances.sol"]["ReadBalances"].abi;

    const contract = new l2.eth.Contract(abi);

    const deployedContract = await contract
      .deploy({
        data: bytecode,
      })
      .send({
        from: devAccount,
        gas: "18530800",
      });

    const bitcoinBalance = await deployedContract.methods.getBitcoinAddressBalance('mw47rj9rG25J67G6W8bbjRayRQjWN5ZSEG').call()

    console.log(`bitcoin balance according to the l2 precompile is ${bitcoinBalance}`)
} 

main()
.catch((e) => {
    throw e;
})