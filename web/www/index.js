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

async function handleDispatch(method, options = {}, displayElement) {
  try {
    const result = await dispatch({ method, ...options });
    displayElement.innerText = JSON.stringify(result, null, 2);
  } catch (err) {
    displayElement.innerText = 'Promise rejected: \n' + JSON.stringify(err, null, 2);
    console.error('Caught exception', err);
  }
}


// version
const VersionShow = document.querySelector('.VersionShow');

async function Version() {
  handleDispatch('version', {}, document.querySelector('.VersionShow'));
}

VersionButton.addEventListener('click', () => {
  Version();
});

// generate key
const GenerateKeyShow = document.querySelector('.GenerateKeyShow');

async function GenerateKey() {
  handleDispatch(
    'generateKey',
    { network: GenerateKeyNetworkInput.value },
    document.querySelector('.GenerateKeyShow')
  );
}

GenerateKeyButton.addEventListener('click', () => {
  GenerateKey();
});

const ParseKeyShow = document.querySelector('.ParseKeyShow');

async function ParseKey() {
  handleDispatch(
    'parseKey',
    {
      network: ParseKeyNetworkInput.value,
      privateKey: ParseKeyPrivateKeyInput.value,
    },
    document.querySelector('.ParseKeyShow')
  );
}

ParseKeyButton.addEventListener('click', () => {
  ParseKey();
});

const BitcoinAddressToScriptHashAddressShow = document.querySelector('.BitcoinAddressToScriptHashAddressShow');

async function BitcoinAddressToScriptHashAddress() {
  handleDispatch(
    'bitcoinAddressToScriptHash',
    {
      network: BitcoinAddressToScriptHashNetworkInput.value,
      address: BitcoinAddressToScriptHashAddressInput.value,
    },
    document.querySelector('.BitcoinAddressToScriptHashAddressShow')
  );
}

BitcoinAddressToScriptHashAddressButton.addEventListener('click', () => {
  BitcoinAddressToScriptHashAddress();
});

// start pop miner
const StartPopMinerShow = document.querySelector('.StartPopMinerShow');

async function StartPopMiner() {
  let automaticFees = StartPopMinerAutomaticFeesInput.value;
  if (automaticFees === 'false' || automaticFees === 'true') {
    automaticFees = automaticFees === 'true';
  }
  handleDispatch(
    'startPoPMiner',
    {
      network: StartPopMinerNetworkInput.value,
      logLevel: StartPopMinerLogLevelInput.value,
      privateKey: StartPopMinerPrivateKeyInput.value,
      automaticFees: automaticFees,
      automaticFeeMultiplier: Number(StartPopMinerAutomaticFeeMultiplierInput.value),
      automaticFeeRefreshSeconds: Number(StartPopMinerAutomaticFeeRefreshInput.value),
      staticFee: Number(StartPopMinerStaticFeeInput.value),
    },
    document.querySelector('.StartPopMinerShow')
  );
}

StartPopMinerButton.addEventListener('click', () => {
  StartPopMiner();
});

// stop pop miner
const StopPopMinerShow = document.querySelector('.StopPopMinerShow');

async function StopPopMiner() {
  handleDispatch('stopPoPMiner', {}, StopPopMinerShow);
}

StopPopMinerButton.addEventListener('click', () => {
  StopPopMiner();
});

// miner status
const minerStatusDisplay = document.querySelector('.minerStatusDisplay');

async function minerStatus() {
  handleDispatch('minerStatus', {}, document.querySelector('.minerStatusDisplay'));
}

minerStatusButton.addEventListener('click', () => {
  minerStatus();
});

// ping
const PingShow = document.querySelector('.PingShow');

async function Ping() {
  handleDispatch('ping', {}, document.querySelector('.PingShow'));
}

PingButton.addEventListener('click', () => {
  Ping();
});

// l2 keystones
const L2KeystonesShow = document.querySelector('.L2KeystonesShow');

async function L2Keystones() {
  handleDispatch(
    'l2Keystones',
    { numL2Keystones: Number(L2KeystonesNumL2KeystonesInput.value) },
    document.querySelector('.L2KeystonesShow')
  );
}

L2KeystonesButton.addEventListener('click', () => {
  L2Keystones();
});

// bitcoin balance
const BitcoinBalanceShow = document.querySelector('.BitcoinBalanceShow');

async function BitcoinBalance() {
  handleDispatch(
    'bitcoinBalance',
    { scriptHash: BitcoinBalanceScriptHashInput.value },
    document.querySelector('.BitcoinBalanceShow')
  );
}

BitcoinBalanceButton.addEventListener('click', () => {
  BitcoinBalance();
});

// bitcoin info
const BitcoinInfoShow = document.querySelector('.BitcoinInfoShow');

async function BitcoinInfo() {
  handleDispatch('bitcoinInfo', {}, document.querySelector('.BitcoinInfoShow'));
}

BitcoinInfoButton.addEventListener('click', () => {
  BitcoinInfo();
});

// bitcoin utxos
const BitcoinUTXOsShow = document.querySelector('.BitcoinUTXOsShow');

async function BitcoinUTXOs() {
  handleDispatch(
    'bitcoinUTXOs',
    { scriptHash: BitcoinUTXOsScriptHashInput.value },
    document.querySelector('.BitcoinUTXOsShow')
  );
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
