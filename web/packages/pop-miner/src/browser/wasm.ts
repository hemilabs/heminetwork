/**
 * Copyright (c) 2024 Hemi Labs, Inc.
 * Use of this source code is governed by the MIT License,
 * which can be found in the LICENSE file.
 */

/* 'any' is used here as interaction with WASM is not typed */
/* eslint-disable @typescript-eslint/no-explicit-any */

import * as types from '../types';
import { Go } from './wasm_exec';

// Keep in sync with Method in web/popminer/api.go
export type Method =
  | 'version'
  | 'wasmPing'
  | 'generateKey'
  | 'parseKey'
  | 'bitcoinAddressToScriptHash'
  | 'startPoPMiner'
  | 'stopPoPMiner'
  | 'minerStatus'
  | 'ping'
  | 'l2Keystones'
  | 'bitcoinBalance'
  | 'bitcoinInfo'
  | 'bitcoinUTXOs'
  | 'addEventListener'
  | 'removeEventListener';

/**
 * Dispatch args.
 *
 * @see dispatch
 */
export type DispatchArgs = Record<string, any> & {
  /**
   * The method to be dispatched.
   *
   * @see Method
   */
  method: Method;
};

/**
 * Dispatches a call to the WASM PoP Miner.
 *
 * @internal This function is for INTERNAL USE ONLY. DO NOT USE DIRECTLY.
 *
 * @param args Dispatch arguments.
 */
export const dispatch = (args: DispatchArgs): Promise<unknown> => {
  return getWASM().dispatch(args);
};

type WASM = {
  dispatch: (args: DispatchArgs) => Promise<unknown>;
};

let loadPromise: Promise<WASM> | undefined;
let globalWASM: WASM | undefined;

export const init: typeof types.init = async ({ wasmURL }) => {
  if (!wasmURL) {
    throw new Error('"wasmURL" option is required');
  }

  if (!loadPromise) {
    loadPromise = loadWASM({ wasmURL }).catch((err) => {
      loadPromise = undefined;
      throw err;
    }) as Promise<WASM>;
  }

  globalWASM = globalWASM || (await loadPromise);
};

export const close: typeof types.close = () => {
  loadPromise = undefined;
  globalWASM = undefined;
  (globalThis as any)['@hemilabs/pop-miner'] = undefined;
};

const getWASM = (): WASM => {
  if (!loadPromise) {
    throw new Error('"init" must be called before calling this function');
  }
  if (!globalWASM) {
    throw new Error('"init" promise must resolve before calling this function');
  }
  return globalWASM;
};

const instantiateWASM = async ({
  wasmURL,
  importObject,
}: {
  wasmURL: string | URL;
  importObject: Record<string, any>;
}): Promise<WebAssembly.WebAssemblyInstantiatedSource> => {
  if (WebAssembly.instantiateStreaming) {
    return await WebAssembly.instantiateStreaming(fetch(wasmURL), importObject);
  }

  // Polyfill for WebAssembly.instantiateStreaming.
  const instantiateStreaming = async () => {
    const source = await fetch(wasmURL).then((res) => res.arrayBuffer());
    return await WebAssembly.instantiate(source, importObject);
  };

  return await instantiateStreaming();
};

const loadWASM = async ({
  wasmURL,
}: {
  wasmURL: string | URL;
}): Promise<WASM> => {
  const go = new Go();
  const wasm = await instantiateWASM({
    wasmURL,
    importObject: go.importObject,
  });
  go.run(wasm.instance); // This continues running in the background.

  const m: any = (globalThis as any)['@hemilabs/pop-miner'];
  return {
    dispatch: (args) => m.dispatch(args),
  };
};
