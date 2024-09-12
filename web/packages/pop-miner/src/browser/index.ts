/**
 * Copyright (c) 2024 Hemi Labs, Inc.
 * Use of this source code is governed by the MIT License,
 * which can be found in the LICENSE file.
 */

import * as types from '../types';
import type {
  BitcoinAddressToScriptHashResult,
  BitcoinBalanceResult,
  BitcoinInfoResult,
  BitcoinUTXOsResult,
  KeyResult,
  L2KeystonesResult,
  MinerStatusResult,
  PingResult,
  VersionResult,
} from '../types';
import { init, close, dispatch, type DispatchArgs } from './wasm';

export type * from '../types';
export { init, close };

const dispatchVoid = async (args: DispatchArgs) => {
  await dispatch(args);
};

export const version: typeof types.version = () => {
  return dispatch({ method: 'version' }) as Promise<VersionResult>;
};

export const generateKey: typeof types.generateKey = ({ network }) => {
  return dispatch({
    method: 'generateKey',
    network: network,
  }) as Promise<KeyResult>;
};

export const parseKey: typeof types.parseKey = ({ network, privateKey }) => {
  return dispatch({
    method: 'parseKey',
    network: network,
    privateKey: privateKey,
  }) as Promise<KeyResult>;
};

export const bitcoinAddressToScriptHash: typeof types.bitcoinAddressToScriptHash =
  ({ network, address }) => {
    return dispatch({
      method: 'bitcoinAddressToScriptHash',
      network: network,
      address: address,
    }) as Promise<BitcoinAddressToScriptHashResult>;
  };

export const startPoPMiner: typeof types.startPoPMiner = (args) => {
  return dispatchVoid({
    method: 'startPoPMiner',
    network: args.network,
    privateKey: args.privateKey,
    logLevel: args.logLevel ?? '',
    automaticFees: args.automaticFees,
    automaticFeeMultiplier: args.automaticFeeMultiplier,
    automaticFeeRefreshSeconds: args.automaticFeeRefreshSeconds,
    staticFee: args.staticFee,
  });
};

export const stopPoPMiner: typeof types.stopPoPMiner = () => {
  return dispatchVoid({
    method: 'stopPoPMiner',
  });
};

export const minerStatus: typeof types.minerStatus = () => {
  return dispatch({
    method: 'minerStatus',
  }) as Promise<MinerStatusResult>;
};

export const ping: typeof types.ping = () => {
  return dispatch({
    method: 'ping',
  }) as Promise<PingResult>;
};

export const l2Keystones: typeof types.l2Keystones = ({ numL2Keystones }) => {
  return dispatch({
    method: 'l2Keystones',
    numL2Keystones: numL2Keystones,
  }) as Promise<L2KeystonesResult>;
};

export const bitcoinBalance: typeof types.bitcoinBalance = ({ scriptHash }) => {
  return dispatch({
    method: 'bitcoinBalance',
    scriptHash: scriptHash,
  }) as Promise<BitcoinBalanceResult>;
};

export const bitcoinInfo: typeof types.bitcoinInfo = () => {
  return dispatch({
    method: 'bitcoinInfo',
  }) as Promise<BitcoinInfoResult>;
};

export const bitcoinUTXOs: typeof types.bitcoinUTXOs = ({ scriptHash }) => {
  return dispatch({
    method: 'bitcoinUTXOs',
    scriptHash: scriptHash,
  }) as Promise<BitcoinUTXOsResult>;
};

export const addEventListener: typeof types.addEventListener = (
  eventType,
  listener,
) => {
  return dispatchVoid({
    method: 'addEventListener',
    eventType: eventType,
    handler: listener,
  });
};

export const removeEventListener: typeof types.addEventListener = (
  eventType,
  listener,
) => {
  return dispatchVoid({
    method: 'removeEventListener',
    eventType: eventType,
    handler: listener,
  });
};
