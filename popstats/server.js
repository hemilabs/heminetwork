import { createClient } from "redis";
import { createPublicClient, erc20Abi, http, zeroAddress } from "viem";
import { hemi, hemiSepolia } from "hemi-viem";
import beforeExit from "before-exit";

// Constants

const governanceTokenAddress = "0x4200000000000000000000000000000000000042";
const popPayoutSender = "0x8888888888888888888888888888888888888888";

// Configuration params

const startBlock = 626000n; // Defined by the points program.
const delayBlocks = BigInt((2 * 60 * 60) / 12); // 2 hours worth of Hemi blocks.

const blocksChunkSize = 1000n;
const delayOnEndMs = 15 * 60 * 1000; // Wait 15 minutes
const delayOnErrorMs = 60 * 1000; // Wait 1 minute
const isTestnet = true;

// EVM helpers

const chain = isTestnet ? hemiSepolia : hemi;
const evmClient = createPublicClient({ chain, transport: http() });

function getLastBlockNumber() {
  return evmClient.getBlockNumber();
}

function getAllGovernanceTokenTransfers({ fromBlock, toBlock }) {
  if (fromBlock > toBlock) {
    return Promise.resolve([]);
  }
  return evmClient.getContractEvents({
    address: governanceTokenAddress,
    abi: erc20Abi,
    eventName: "Transfer",
    args: { from: zeroAddress },
    fromBlock,
    toBlock,
  });
}

function getTxFromEvent(event) {
  return evmClient.getTransaction({ hash: event.transactionHash });
}

// Database helpers

const keyPrefix = isTestnet ? "ht" : "hn";
const bestBlockKey = `${keyPrefix}:bestBlock`;
const lastPayoutsKey = `${keyPrefix}:lastPayouts`;

const redisClientPromise = createClient()
  .on("error", function (err) {
    console.error("Redis error:", err.message);
    process.exit(1);
  })
  .connect();

function disconnectFromRedis() {
  return redisClientPromise.then((redisClient) => redisClient.disconnect);
}

function getBestBlockNumber() {
  return redisClientPromise.then(function (redisClient) {
    return redisClient.get(bestBlockKey).then(function (bestBlock) {
      return BigInt(bestBlock || startBlock);
    });
  });
}

function updateBestBlock(bestBlock) {
  return redisClientPromise.then(function (redisClient) {
    return redisClient.set(bestBlockKey, bestBlock.toString());
  });
}

function updateLastPayouts(events) {
  if (!events.length) {
    return;
  }
  return redisClientPromise.then(function (redisClient) {
    return redisClient.hSet(
      lastPayoutsKey,
      events.map(function (event) {
        return [event.args.to, event.blockNumber.toString()];
      })
    );
  });
}

function getLastPayouts() {
  return redisClientPromise.then(function (redisClient) {
    return redisClient.hGetAll(lastPayoutsKey);
  });
}

// Core helpers

function getBlocksRange([fromBlock, blockNumber]) {
  const endBlock = blockNumber - delayBlocks;
  const chunkEndBlock = fromBlock + blocksChunkSize;
  const toBlock = chunkEndBlock < endBlock ? chunkEndBlock : endBlock;
  return { fromBlock, toBlock };
}

function mapEventToTxAndEvent(event) {
  return getTxFromEvent(event).then(function (transaction) {
    return { event, transaction };
  });
}

function eventComesFromPayoutSender({ event, transaction }) {
  return transaction.from === popPayoutSender;
}

function getEvent({ event }) {
  return event;
}

function sortEventsByBlockNumber(eventA, eventB) {
  return Number(eventA.blockNumber - eventB.blockNumber);
}

function getOnlyValidEvents(eventsAndTxs) {
  return eventsAndTxs
    .filter(eventComesFromPayoutSender)
    .map(getEvent)
    .sort(sortEventsByBlockNumber);
}

// Core processing

function processBlocks() {
  return Promise.all([getBestBlockNumber(), getLastBlockNumber()]).then(
    function ([bestBlock, blockNumber]) {
      const { fromBlock, toBlock } = getBlocksRange([bestBlock, blockNumber]);
      return (
        getAllGovernanceTokenTransfers({ fromBlock, toBlock })
          .then(function (events) {
            return Promise.all(events.map(mapEventToTxAndEvent));
          })
          .then(function (eventsAndTxs) {
            return updateLastPayouts(getOnlyValidEvents(eventsAndTxs));
          })
          .then(function () {
            return updateBestBlock(toBlock);
          })
          // TODO Report last payouts to Absinthe here
          .then(function () {
            return Number(toBlock - fromBlock) + 1;
          })
      );
    }
  );
}

// Initialization code

function loop() {
  processBlocks()
    .then(async function (processedBlocks) {
      console.log("");

      if (processedBlocks <= 0) {
        console.log("No more blocks to process");
        setTimeout(loop, delayOnEndMs);
        return;
      }

      console.log("Best block:", await getBestBlockNumber());
      console.log("Last payouts:", await getLastPayouts());
      setTimeout(loop, 0);
    })
    .catch(function (err) {
      console.warn("Unexpected error:", err.message);
      setTimeout(loop, delayOnErrorMs);
    });
}

loop();

// Cleanup code

beforeExit.do(function () {
  return disconnectFromRedis();
});
