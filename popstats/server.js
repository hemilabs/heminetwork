/**
 * Copyright (c) 2024 Hemi Labs, Inc.
 * Use of this source code is governed by the MIT License,
 * which can be found in the LICENSE file.
 */

import { createClient } from "redis";
import { createPublicClient, erc20Abi, http, zeroAddress } from "viem";
import { hemi, hemiSepolia } from "hemi-viem";
import beforeExit from "before-exit";
import groupBy from "lodash/groupBy.js";
import pFilter from "p-filter";
import pLimit from "p-limit";
import pMem from "promise-mem";
import pThrottle from "p-throttle";

import BigIntMath from "./src/bigint-math.js";
import pDoWhilst from "./src/p-do-whilst.js";
import pWhilst from "./src/p-whilst.js";

// Configuration ---------------------------------------------------------------

process.loadEnvFile();

const config = {
  absintheApi: {
    key: process.env.ABSINTHE_API_KEY,
    url: process.env.ABSINTHE_API_URL,
  },
  addresses: {
    governanceToken: "0x4200000000000000000000000000000000000042", // HEMI
    popPayoutSender: "0x8888888888888888888888888888888888888888", // Depositor
  },
  blocks: {
    ignoreLastCount: BigInt((2 * 60 * 60) / 12), // 2 hours worth of Hemi blocks
    maxWindow: 1200n, // Max amount of blocks to process at once
    perDay: BigInt((24 * 60 * 60) / 12), // 24 hours worth of Hemi blocks: 7200
    start: 1142932n, // Defined in the points program rules
  },
  delays: {
    onEnd: 24 * 60 * 60 * 1000, // 24 hours
    onError: 1 * 60 * 1000, // 1 minute
  },
  eventName: "popminer",
  gethRateLimit: { interval: 100, limit: 1000 }, // 100 req/s
  points: {
    bonus: 0.25 * 288, // 25% of the daily maximum
    bonusThreshold: 0.75 * 288, // 75% of the daily maximum
    perPopEvent: 1,
  },
  redis: {
    bestBlockKey: "bestBlock",
    prefixes: {
      mainnet: "hn",
      testnet: "ht",
    },
    url: process.env.REDIS_URL,
  },
  runContinuously: false,
  testnet: true,
  upstashLimits: {
    concurrency: 100,
    daily: { interval: 86400000, limit: 10000 },
    perSecond: { interval: 1000, limit: 1000 },
  },
};

// EVM -------------------------------------------------------------------------

const chain = config.testnet ? hemiSepolia : hemi;
const evmClient = createPublicClient({ chain, transport: http() });

const getBlockNumber = () => evmClient.getBlockNumber();

const getGovernanceTokenTransfers = ({ fromBlock, toBlock }) =>
  evmClient.getContractEvents({
    abi: erc20Abi,
    address: /** @type {`0x${string}`} */ (config.addresses.governanceToken),
    args: { from: zeroAddress },
    eventName: "Transfer",
    fromBlock,
    toBlock,
  });

// Rate limit these calls as the RPC calls may timeout on load
const rpcThrottle = pThrottle(config.gethRateLimit);
const getTransaction = pMem(
  rpcThrottle((hash) => evmClient.getTransaction({ hash }))
);

// Database --------------------------------------------------------------------

const keyPrefix = config.testnet
  ? config.redis.prefixes.testnet
  : config.redis.prefixes.mainnet;
const bestBlockKey = `${keyPrefix}:${config.redis.bestBlockKey}`;

const concurrencyLimit = pLimit(config.upstashLimits.concurrency);
const dailyThrottle = pThrottle(config.upstashLimits.daily);
const perSecondThrottle = pThrottle(config.upstashLimits.perSecond);

const connectToRedis = () =>
  createClient(config.redis)
    .on("connect", function () {
      beforeExit.do(() => this.disconnect());
    })
    .on("error", function (err) {
      console.error("Redis error:", err.code);
      process.exit(1);
    })
    .connect();

const getRedisClient = dailyThrottle(perSecondThrottle(pMem(connectToRedis)));

const getBestBlockNumber = () =>
  concurrencyLimit(() =>
    getRedisClient().then((redisClient) =>
      redisClient
        .get(bestBlockKey)
        .then((bestBlock) => (bestBlock ? BigInt(bestBlock) : undefined))
    )
  );

const setBestBlockNumber = (bestBlock) =>
  concurrencyLimit(() =>
    getRedisClient()
      .then((redisClient) =>
        redisClient.set(bestBlockKey, bestBlock.toString())
      )
      .then(function () {
        console.log(`Best block set to ${bestBlock}`);
      })
  );

// Absinthe --------------------------------------------------------------------

function insertApiPoints(rows) {
  console.log(`Inserting ${rows.length} rows`);
  const headers = new Headers();
  headers.append("Authorization", `Bearer ${config.absintheApi.key}`);
  headers.append("Content-Type", "application/json");
  const graphql = JSON.stringify({
    query: `mutation ($objects: [api_points_insert_input!]!) {
              insert_api_points(objects: $objects) {
                returning { id }
              }
            }`,
    variables: { objects: rows },
  });
  return fetch(/** @type {string} */ (config.absintheApi.url), {
    body: graphql,
    headers,
    method: "POST",
  })
    .then((res) => res.json())
    .then(function ({ errors }) {
      if (errors) {
        throw new Error(`Insertion failed: ${JSON.stringify(errors)}`);
      }

      console.log("Insertion done");
    });
}

// Events processing -----------------------------------------------------------

function getMoreGovernanceTokenTransfers({ fromBlock, toBlock, transfers }) {
  const maxToBlock = BigIntMath.min(
    fromBlock + config.blocks.maxWindow - 1n,
    toBlock
  );
  console.log(`Getting transfers between blocks ${fromBlock}-${maxToBlock}`);
  return getGovernanceTokenTransfers({
    fromBlock,
    toBlock: maxToBlock,
  }).then((moreTransfers) => ({
    fromBlock: maxToBlock + 1n,
    toBlock,
    transfers: transfers.concat(moreTransfers),
  }));
}

const thereAreBlocksToProcess = ({ fromBlock, toBlock }) =>
  fromBlock <= toBlock;

const getAllGovernanceTokenTransfers = ({ fromBlock, toBlock }) =>
  pDoWhilst(getMoreGovernanceTokenTransfers, thereAreBlocksToProcess, {
    fromBlock,
    toBlock,
    transfers: [],
  }).then(({ transfers }) => transfers);

const eventComesFromPayoutSender = (event) =>
  getTransaction(event.transactionHash).then(
    ({ from }) => from === config.addresses.popPayoutSender
  );

function filterPayoutEvents(events) {
  console.log(`Filtering ${events.length} events`);
  return pFilter(events, eventComesFromPayoutSender);
}

const computeBonusPoints = (points) =>
  points < config.points.bonusThreshold ? points : points + config.points.bonus;

const mapEventsToRows = (popEvents) =>
  Object.entries(groupBy(popEvents, "args.to")).map(([address, events]) => ({
    address,
    amount: computeBonusPoints(events.length * config.points.perPopEvent),
    // eslint-disable-next-line camelcase
    event_name: config.eventName,
    metadata: {
      testnet: config.testnet,
      txs: events.map((event) => event.transactionHash),
    },
  }));

const getBestAndLastBlockNumbers = (lastToBlock) =>
  Promise.all([lastToBlock || getBestBlockNumber(), getBlockNumber()]).then(
    ([bestBlock, lastBlock]) => ({
      bestBlock: bestBlock || config.blocks.start - 1n,
      lastBlock: lastBlock - config.blocks.ignoreLastCount,
    })
  );

function processBlocksRange({ bestBlock, lastBlock }) {
  const fromBlock = bestBlock + 1n;
  const toBlock = BigIntMath.min(bestBlock + config.blocks.perDay, lastBlock);
  console.log(`Analyzing blocks ${fromBlock}-${toBlock}`);
  return getAllGovernanceTokenTransfers({ fromBlock, toBlock })
    .then(filterPayoutEvents)
    .then(function (events) {
      if (!events.length) {
        return null;
      }

      return insertApiPoints(mapEventsToRows(events));
    })
    .then(() => setBestBlockNumber(toBlock).then(() => toBlock))
    .then(getBestAndLastBlockNumbers);
}

const processBlocks = () =>
  pWhilst(
    ({ bestBlock, lastBlock }) => bestBlock < lastBlock,
    processBlocksRange,
    getBestAndLastBlockNumbers()
  );

// Initialization and cleanup --------------------------------------------------
// This is only needed when running continuously but not when running in a
// serverless environment.

function loop() {
  processBlocks()
    .then(function () {
      console.log("No more blocks to process");
      if (config.runContinuously) {
        setTimeout(loop, config.delays.onEnd);
      }
    })
    .catch(function (err) {
      console.warn("Unexpected error:", err.message);
      setTimeout(loop, config.delays.onError);
    });
}

loop();
