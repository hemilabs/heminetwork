/**
 * Copyright (c) 2024 Hemi Labs, Inc.
 * Use of this source code is governed by the MIT License,
 * which can be found in the LICENSE file.
 */

let wasm; // This stores the global object created by the WASM binary.

// Called after the WASM binary has been loaded.
async function init() {
  wasm = globalThis['@hemilabs/pop-miner'];
  void registerEventListener();
}

async function dispatch(args) {
  if (!wasm) {
    throw new Error('WASM has not finished loading yet');
  }
  return wasm.dispatch(args);
}

// version
const VersionShow = document.querySelector('.VersionShow');

async function Version() {
  try {
    const result = await dispatch({
      method: 'version',
    });
    VersionShow.innerText = JSON.stringify(result, null, 2);
  } catch (err) {
    VersionShow.innerText = 'Promise rejected: \n' + JSON.stringify(err, null, 2);
    console.error('Caught exception', err);
  }
}

VersionButton.addEventListener('click', () => {
  Version();
});

// generate key
const GenerateKeyShow = document.querySelector('.GenerateKeyShow');

async function GenerateKey() {
  try {
    const result = await dispatch({
      method: 'generateKey',
      network: GenerateKeyNetworkInput.value,
    });
    GenerateKeyShow.innerText = JSON.stringify(result, null, 2);
  } catch (err) {
    GenerateKeyShow.innerText = 'Promise rejected: \n' + JSON.stringify(err, null, 2);
    console.error('Caught exception', err);
  }
}

GenerateKeyButton.addEventListener('click', () => {
  GenerateKey();
});

const ParseKeyShow = document.querySelector('.ParseKeyShow');

async function ParseKey() {
  try {
    const result = await dispatch({
      method: 'parseKey',
      network: ParseKeyNetworkInput.value,
      privateKey: ParseKeyPrivateKeyInput.value,
    });
    ParseKeyShow.innerText = JSON.stringify(result, null, 2);
  } catch (err) {
    ParseKeyShow.innerText = 'Promise rejected: \n' + JSON.stringify(err, null, 2);
    console.error('Caught exception', err);
  }
}

ParseKeyButton.addEventListener('click', () => {
  ParseKey();
});

const BitcoinAddressToScriptHashAddressShow = document.querySelector('.BitcoinAddressToScriptHashAddressShow');

async function BitcoinAddressToScriptHashAddress() {
  try {
    const result = await dispatch({
      method: 'bitcoinAddressToScriptHash',
      network: BitcoinAddressToScriptHashNetworkInput.value,
      address: BitcoinAddressToScriptHashAddressInput.value,
    });
    BitcoinAddressToScriptHashAddressShow.innerText = JSON.stringify(result, null, 2);
  } catch (err) {
    BitcoinAddressToScriptHashAddressShow.innerText = 'Promise rejected: \n' + JSON.stringify(err, null, 2);
    console.error('Caught exception', err);
  }
}

BitcoinAddressToScriptHashAddressButton.addEventListener('click', () => {
  BitcoinAddressToScriptHashAddress();
});

// start pop miner
const StartPopMinerShow = document.querySelector('.StartPopMinerShow');

async function StartPopMiner() {
  try {
    let automaticFees = StartPopMinerAutomaticFeesInput.value;
    if (automaticFees === 'false' || automaticFees === 'true') {
      automaticFees = automaticFees === 'true';
    }
    const result = await dispatch({
      method: 'startPoPMiner',
      network: StartPopMinerNetworkInput.value,
      logLevel: StartPopMinerLogLevelInput.value,
      privateKey: StartPopMinerPrivateKeyInput.value,
      automaticFees: automaticFees,
      automaticFeeMultiplier: Number(StartPopMinerAutomaticFeeMultiplierInput.value),
      automaticFeeRefreshSeconds: Number(StartPopMinerAutomaticFeeRefreshInput.value),
      staticFee: Number(StartPopMinerStaticFeeInput.value),
    });
    StartPopMinerShow.innerText = JSON.stringify(result, null, 2);
  } catch (err) {
    StartPopMinerShow.innerText = 'Promise rejected: \n' + JSON.stringify(err, null, 2);
    console.error('Caught exception', err);
  }
}

StartPopMinerButton.addEventListener('click', () => {
  StartPopMiner();
});

// stop pop miner
const StopPopMinerShow = document.querySelector('.StopPopMinerShow');

async function StopPopMiner() {
  try {
    const result = await dispatch({
      method: 'stopPoPMiner',
    });
    StopPopMinerShow.innerText = JSON.stringify(result, null, 2);
  } catch (err) {
    StopPopMinerShow.innerText = 'Promise rejected: \n' + JSON.stringify(err, null, 2);
    console.error('Caught exception', err);
  }
}

StopPopMinerButton.addEventListener('click', () => {
  StopPopMiner();
});

// miner status
const minerStatusDisplay = document.querySelector('.minerStatusDisplay');

async function minerStatus() {
  try {
    const result = await dispatch({
      method: 'minerStatus',
    });
    minerStatusDisplay.innerText = JSON.stringify(result, null, 2);
  } catch (err) {
    minerStatusDisplay.innerText = 'Promise rejected: \n' + JSON.stringify(err, null, 2);
    console.error('Caught exception', err);
  }
}

minerStatusButton.addEventListener('click', () => {
  minerStatus();
});

// ping
const PingShow = document.querySelector('.PingShow');

async function Ping() {
  try {
    const result = await dispatch({
      method: 'ping', // Timestamp is handled by Go.
    });
    PingShow.innerText = JSON.stringify(result, null, 2);
  } catch (err) {
    PingShow.innerText = 'Promise rejected: \n' + JSON.stringify(err, null, 2);
    console.error('Caught exception', err);
  }
}

PingButton.addEventListener('click', () => {
  Ping();
});

// l2 keystones
const L2KeystonesShow = document.querySelector('.L2KeystonesShow');

async function L2Keystones() {
  try {
    const result = await dispatch({
      method: 'l2Keystones',
      numL2Keystones: Number(L2KeystonesNumL2KeystonesInput.value),
    });
    L2KeystonesShow.innerText = JSON.stringify(result, null, 2);
  } catch (err) {
    L2KeystonesShow.innerText = 'Promise rejected: \n' + JSON.stringify(err, null, 2);
    console.error('Caught exception', err);
  }
}

L2KeystonesButton.addEventListener('click', () => {
  L2Keystones();
});

// bitcoin balance
const BitcoinBalanceShow = document.querySelector('.BitcoinBalanceShow');

async function BitcoinBalance() {
  try {
    const result = await dispatch({
      method: 'bitcoinBalance',
      scriptHash: BitcoinBalanceScriptHashInput.value,
    });
    BitcoinBalanceShow.innerText = JSON.stringify(result, null, 2);
  } catch (err) {
    BitcoinBalanceShow.innerText = 'Promise rejected: \n' + JSON.stringify(err, null, 2);
    console.error('Caught exception', err);
  }
}

BitcoinBalanceButton.addEventListener('click', () => {
  BitcoinBalance();
});

// bitcoin info
const BitcoinInfoShow = document.querySelector('.BitcoinInfoShow');

async function BitcoinInfo() {
  try {
    const result = await dispatch({
      method: 'bitcoinInfo',
    });
    BitcoinInfoShow.innerText = JSON.stringify(result, null, 2);
  } catch (err) {
    BitcoinInfoShow.innerText = 'Promise rejected: \n' + JSON.stringify(err, null, 2);
    console.error('Caught exception', err);
  }
}

BitcoinInfoButton.addEventListener('click', () => {
  BitcoinInfo();
});

// bitcoin utxos
const BitcoinUTXOsShow = document.querySelector('.BitcoinUTXOsShow');

async function BitcoinUTXOs() {
  try {
    const result = await dispatch({
      method: 'bitcoinUTXOs',
      scriptHash: BitcoinUTXOsScriptHashInput.value,
    });
    BitcoinUTXOsShow.innerText = JSON.stringify(result, null, 2);
  } catch (err) {
    BitcoinUTXOsShow.innerText = 'Promise rejected: \n' + JSON.stringify(err, null, 2);
    console.error('Caught exception', err);
  }
}

BitcoinUTXOsButton.addEventListener('click', () => {
  BitcoinUTXOs();
});

// Events
const eventsDisplay = document.querySelector('.eventsDisplay');

async function registerEventListener() {
  try {
    const result = await dispatch({
      method: 'addEventListener',
      eventType: '*',
      handler: handleEvent,
    });
    console.debug('addEventListener: ', JSON.stringify(result, null, 2));
  } catch (err) {
    console.error('Caught exception', err);
  }
}

function handleEvent(event) {
  eventsDisplay.innerText += `\n${JSON.stringify(event, null, 2)}\n`;
}
