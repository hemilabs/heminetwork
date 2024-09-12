/**
 * Copyright (c) 2024 Hemi Labs, Inc.
 * Use of this source code is governed by the MIT License,
 * which can be found in the LICENSE file.
 */

// Keep in sync with web/popminer/api.go.

/**
 * Initialisation options.
 *
 * @see init
 */
export type InitOptions = {
  /**
   * The URL for the PoP Miner WASM binary file.
   * This must be provided when running in the browser.
   */
  wasmURL?: string | URL | undefined;
};

/**
 * Loads and configures the browser-based PoP Miner WASM binary.
 *
 * When running in the browser, it is necessary to call this function first and
 * wait for the returned promise to resolve before using any other API
 * functions.
 *
 * @param options Initialisation options.
 * @returns a promise that resolves when WASM has been successfully loaded.
 *
 * @see InitOptions
 */
export declare function init(options: InitOptions): Promise<void>;

/**
 * Closes the PoP Miner WASM instance.
 *
 * @remarks Calling this function is optional, but a recommended optimisation.
 */
export declare function close(): void;

/**
 * A number used to differentiate between error types.
 *
 * @see Error
 */
export enum ErrorCode {
  /**
   * Internal is used when the error is internal, either due to an invalid
   * API function call or a panic. These errors are unlikely to be caused by a
   * user and could be caused by a bug.
   */
  Internal = 1000,

  /**
   * Invalid Value is used when an invalid value was provided in an API function
   * call. Errors with this code are likely caused by incorrect usage of this
   * package.
   */
  InvalidValue = 2000,
}

/**
 * Represents an error that occurred within the PoP Miner WASM.
 *
 * If a Promise returned by an API function is rejected, it will be rejected
 * with this type.
 */
export type Error = {
  /**
   * The error code for this error, used to differentiate between error types.
   */
  readonly code: ErrorCode;

  /**
   * The error message.
   */
  readonly message: string;

  /**
   * The Go debug stack for the error.
   */
  readonly stack: string;

  /**
   * The timestamp the error occurred.
   */
  readonly timestamp: Date;
};

/**
 * Version information for the WASM PoP Miner.
 *
 * @see version
 */
export type VersionResult = {
  /**
   * The version of the WASM PoP Miner.
   */
  readonly version: string;

  /**
   * The SHA-1 hash of the Git commit the WASM binary was built from.
   */
  readonly gitCommit: string;
};

/**
 * Returns version information for the WASM binary.
 */
export declare function version(): Promise<VersionResult>;

/**
 * @see generateKey
 */
export type GenerateKeyArgs = {
  /**
   * Determines which network for which the key will be generated.
   */
  network: 'testnet3' | 'mainnet';
};

/**
 * Contains a secp256k1 key pair and its corresponding Bitcoin address and
 * public key hash, and Ethereum address.
 *
 * @see generateKey
 * @see parseKey
 */
export type KeyResult = {
  /**
   * The Hemi Ethereum address for the key.
   */
  readonly hemiAddress: string;

  /**
   * The network the addresses were created for.
   */
  readonly network: 'testnet3' | 'mainnet';

  /**
   * The secp256k1 private key, encoded as a hexadecimal string.
   */
  readonly privateKey: string;

  /**
   * The secp256k1 public key, in the 33-byte compressed format, encoded as a
   * hexadecimal string.
   */
  readonly publicKey: string;

  /**
   * The Bitcoin pay-to-pubkey-hash address for the key.
   */
  readonly bitcoinPubKeyHash: string;

  /**
   * The Bitcoin pay-to-pubkey-hash script hash for the key.
   */
  readonly bitcoinScriptHash: string;
};

/**
 * Generates returns a new secp256k1 private key and its corresponding public
 * key and addresses.
 *
 * @param args Key generation parameters.
 */
export declare function generateKey(args: GenerateKeyArgs): Promise<KeyResult>;

/**
 * @see parseKey
 */
export type ParseKeyArgs = {
  /**
   * Determines which network the public key will be created for.
   */
  network: 'testnet3' | 'mainnet';

  /**
   * The private key to parse and return the corresponding public key and
   * addresses for, encoded as a hexadecimal string.
   */
  privateKey: string;
};

/**
 * Parses the given private key and returns its corresponding public key and
 * addresses.
 *
 * @param args Key parse parameters.
 */
export declare function parseKey(args: ParseKeyArgs): Promise<KeyResult>;

/**
 * @see bitcoinAddressToScriptHash
 */
export type BitcoinAddressToScriptHashArgs = {
  /**
   * Determines the network the key will be parsed for.
   */
  network: 'testnet3' | 'mainnet';

  /**
   * The Bitcoin address to return the script hash of.
   */
  address: string;
};

/**
 * @see bitcoinAddressToScriptHash
 */
export type BitcoinAddressToScriptHashResult = {
  /**
   * The network the address is for.
   */
  network: 'testnet3' | 'mainnet';

  /**
   * The address the script hash is for.
   */
  address: string;

  /**
   * The script hash for the address.
   */
  scriptHash: string;
};

/**
 * Returns the script hash of the given Bitcoin address.
 *
 * @param args Bitcoin to script hash arguments.
 */
export declare function bitcoinAddressToScriptHash(
  args: BitcoinAddressToScriptHashArgs,
): Promise<BitcoinAddressToScriptHashResult>;

/**
 * Represents a type of event.
 */
export type EventType =
  | 'minerStart'
  | 'minerStop'
  | 'mineKeystone'
  | 'transactionBroadcast';

/**
 * An event that has been dispatched.
 */
export type Event = {
  readonly type: EventType;
};

/**
 * Dispatched when the PoP miner has stopped.
 */
export type EventMinerStart = Event & {
  readonly type: 'minerStart';
};

/**
 * Dispatched when the PoP miner has exited.
 */
export type EventMinerStop = Event & {
  readonly type: 'minerStop';

  /**
   * The error that caused the PoP miner to exit, or null.
   */
  readonly error?: Error;
};

/**
 * Dispatched when the PoP miner begins mining a keystone.
 */
export type EventMineKeystone = Event & {
  readonly type: 'mineKeystone';

  /**
   * The keystone to be mined.
   */
  readonly keystone: L2Keystone;
};

/**
 * Dispatched when the PoP miner broadcasts a PoP transaction to the Bitcoin
 * network.
 */
export type EventTransactionBroadcast = Event & {
  readonly type: 'transactionBroadcast';

  /**
   * The keystone that was mined.
   */
  readonly keystone: L2Keystone;

  /**
   * The hash of the Bitcoin transaction.
   */
  readonly txHash: string;
};

/**
 * An event listener that can receive events.
 */
export interface EventListener {
  (event: Event): void;
}

/**
 * Registers an event listener.
 *
 * @param eventType The event type to listen for. If '*' then listen for all events.
 * @param listener The event listener that will be called when the event is dispatched.
 */
export declare function addEventListener(
  eventType: EventType | '*',
  listener: EventListener,
): Promise<void>;

/**
 * Unregisters an event listener.
 *
 * @param eventType The event type to stop listening for.
 * @param listener The event listener to unregister.
 */
export declare function removeEventListener(
  eventType: EventType | '*',
  listener: EventListener,
): Promise<void>;

/**
 * The type of recommended fee to use when doing automatic fees using
 * the mempool.space REST API.
 */
export type RecommendedFeeType =
  | 'fastest'
  | 'halfHour'
  | 'hour'
  | 'economy'
  | 'minimum';

/**
 * @see startPoPMiner
 */
export type MinerStartArgs = {
  /**
   * The network to start the PoP Miner on.
   */
  network: 'testnet' | 'devnet' | 'mainnet';

  /**
   * The secp256k1 private key for the PoP Miner.
   */
  privateKey: string;

  /**
   * The log level for the PoP miner. This controls the verbosity of logs sent
   * to the console.
   *
   * Options are 'trace', 'debug', 'info', 'warn', 'error' and 'critical'.
   *
   * @remarks
   * The logging library used by the PoP miner allows more granular control over
   * logging levels for individual components. For more information, please
   * see https://github.com/juju/loggo#func-configureloggers
   */
  logLevel?: string;

  /**
   * Whether to do automatic fee estimation using the mempool.space API.
   * Defaults to true. If disabled, then only the staticFee will be used.
   *
   * When the value is true, the 'fastest' recommended fee type will be used.
   */
  automaticFees?: boolean | RecommendedFeeType;

  /**
   * Controls the fee used when automaticFees is enabled. This allows the output
   * fee to be increased or decreased by a percentage. For example, if the
   * recommended fee is 500 and the multiplier is 1.1, the output will be 550.
   * Defaults to 1.1 (+10%).
   */
  automaticFeeMultiplier?: number;

  /**
   * The duration between refreshing recommended fee data from the
   * mempool.space API, in seconds. Defaults to 300 seconds (5 minutes).
   */
  automaticFeeRefreshSeconds?: number;

  /**
   * The number of sats/vB the PoP Miner will pay for fees. If automaticFees
   * is enabled, then this will be used as a fallback fee value.
   */
  staticFee: number;
};

/**
 * Starts the PoP Miner with the given configuration options.
 *
 * @param args Configuration options.
 */
export declare function startPoPMiner(args: MinerStartArgs): Promise<void>;

/**
 * Shuts down the PoP miner.
 *
 * The promise will be rejected if the PoP Miner is not running, or if the PoP
 * Miner exited with an error.
 */
export declare function stopPoPMiner(): Promise<void>;

/**
 * @see minerStatus
 */
export type MinerStatusResult = {
  /**
   * Whether the PoP miner is currently running.
   */
  readonly running: boolean;

  /**
   * Whether the PoP miner is currently connected to a BFG server.
   */
  readonly connected: boolean;

  /**
   * The current fee used by the PoP miner for PoP transactions, in sats/vB.
   */
  readonly fee: number;
};

/**
 * Returns information about the status of the PoP miner.
 */
export declare function minerStatus(): Promise<MinerStatusResult>;

/**
 * @see ping
 */
export type PingResult = {
  /**
   * The timestamp the PoP Miner sent the ping request to BFG.
   */
  readonly originTimestamp: Date;

  /**
   * The timestamp the BFG server sent the ping response to the PoP Miner.
   */
  readonly timestamp: Date;
};

/**
 * Pings the Bitcoin Finality Governor (BFG) RPC server.
 *
 * **The PoP Miner must be running before calling this function.**
 */
export declare function ping(): Promise<PingResult>;

/**
 * @see l2Keystones
 */
export type L2KeystonesArgs = {
  /**
   * The number of L2 keystones to request.
   * Must be between 0 and 10. Defaults to 2 if the number is outside of this
   * range.
   */
  numL2Keystones: number;
};

/**
 * @see l2Keystones
 */
export type L2KeystonesResult = {
  /**
   * The requested L2 keystones.
   */
  readonly l2Keystones: L2Keystone[];
};

/**
 * Represents an L2 keystone.
 */
export type L2Keystone = {
  /**
   * The version of the L2 keystone.
   */
  readonly version: number;

  /**
   * The L1 block number for the keystone.
   */
  readonly l1BlockNumber: number;

  /**
   * The L2 block number for the keystone.
   */
  readonly l2BlockNumber: number;

  /**
   * The hash of the L2 block that contains the PoP payout.
   */
  readonly epHash: string;

  /**
   * The hash of the parent of the L2 block that contains the PoP payout.
   */
  readonly parentEPHash: string;

  /**
   * The hash of the L2 block that contains the previous keystone PoP payout.
   */
  readonly prevKeystoneEPHash: string;

  /**
   * The Ethereum execution payload state root.
   */
  readonly stateRoot: string;
};

/**
 * Retrieves L2 keystones from the Bitcoin Finality Governor RPC server.
 *
 * **The PoP Miner must be running before calling this function.**
 *
 * @param args Retrieval options.
 */
export declare function l2Keystones(
  args: L2KeystonesArgs,
): Promise<L2KeystonesResult>;

/**
 * @see bitcoinBalance
 */
export type BitcoinBalanceArgs = {
  /**
   * The script hash to receive the balance of, encoded as a hexadecimal string.
   */
  scriptHash: string;
};

/**
 * @see bitcoinBalance
 */
export type BitcoinBalanceResult = {
  /**
   * The confirmed balance in satoshis.
   */
  readonly confirmed: number;

  /**
   * The unconfirmed balance in satoshis.
   */
  readonly unconfirmed: number;
};

/**
 * Retrieves the confirmed and unconfirmed balances of a Bitcoin script hash.
 *
 * **The PoP Miner must be running before calling this function.**
 *
 * @param args Retrieval options.
 */
export declare function bitcoinBalance(
  args: BitcoinBalanceArgs,
): Promise<BitcoinBalanceResult>;

/**
 * @see bitcoinInfo
 */
export type BitcoinInfoResult = {
  /**
   * The current best known Bitcoin block height.
   */
  readonly height: number;
};

/**
 * Retrieves the current best known Bitcoin block height.
 *
 * **The PoP Miner must be running before calling this function.**
 */
export declare function bitcoinInfo(): Promise<BitcoinInfoResult>;

/**
 * @see bitcoinUTXOs
 */
export type BitcoinUTXOsArgs = {
  scriptHash: string;
};

/**
 * @see bitcoinUTXOs
 */
export type BitcoinUTXOsResult = {
  /**
   * The UTXOs for the script hash.
   */
  readonly utxos: BitcoinUTXO[];
};

/**
 * Represents a Bitcoin UTXO.
 */
export type BitcoinUTXO = {
  /**
   * The output's transaction hash, encoded as a hexadecimal string.
   */
  readonly hash: string;

  /**
   * The index of the output in the transaction's list of outputs.
   */
  readonly index: number;

  /**
   * The value of the output in satoshis.
   */
  readonly value: number;
};

/**
 * Retrieves the UTXOs of a Bitcoin script hash.
 *
 * **The PoP Miner must be running before calling this function.**
 *
 * @param args Retrieval options.
 */
export declare function bitcoinUTXOs(
  args: BitcoinUTXOsArgs,
): Promise<BitcoinUTXOsResult>;
