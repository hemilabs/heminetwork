// wasm ping
const WASMPingShow = document.querySelector('.WASMPingShow');

async function WASMPing() {
  try {
    const result = await dispatch({
      method: 'wasmping',
      message: 'wasm ping',
    });
    WASMPingShow.innerHTML = result;
  } catch (err) {
    WASMPingShow.innerHTML = err;
    console.error('Caught exception', err);
  }
}

WASMPingButton.addEventListener('click', () => {
  WASMPing();
});

// generate key
const GenerateKeyShow = document.querySelector('.GenerateKeyShow');

async function GenerateKey() {
  try {
    const result = await dispatch({
      method: 'generatekey',
      network:  GenerateKeyNetworkInput.value,
    });
    GenerateKeyShow.innerHTML = result;
  } catch (err) {
    GenerateKeyShow.innerHTML = err;
    console.error('Caught exception', err);
  }
}

GenerateKeyButton.addEventListener('click', () => {
  GenerateKey();
});

// run pop miner
const RunPopMinerShow = document.querySelector('.RunPopMinerShow');

async function RunPopMiner() {
  try {
    const result = await dispatch({
      method: 'runpopminer',
      network: RunPopMinerNetworkInput.value,
      logLevel: RunPopMinerLogLevelInput.value,
      privateKey: RunPopMinerPrivateKeyInput.value,
    });
    RunPopMinerShow.innerHTML = result;
  } catch (err) {
    RunPopMinerShow.innerHTML = err;
    console.error('Caught exception', err);
  }
}

RunPopMinerButton.addEventListener('click', () => {
  RunPopMiner();
});

// stop pop miner
const StopPopMinerShow = document.querySelector('.StopPopMinerShow');

async function StopPopMiner() {
  try {
    const result = await dispatch({
      method: 'stoppopminer',
    });
    StopPopMinerShow.innerHTML = result;
  } catch (err) {
    StopPopMinerShow.innerHTML = err;
    console.error('Caught exception', err);
  }
}

StopPopMinerButton.addEventListener('click', () => {
  StopPopMiner();
});

// ping
const PingShow = document.querySelector('.PingShow');

async function Ping() {
  try {
    const result = await dispatch({
      method: 'ping',
      timestamp:  0, // XXX pull timestamp
    });
    PingShow.innerHTML = result;
  } catch (err) {
    PingShow.innerHTML = err;
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
    L2KeystonesShow.innerHTML = result;
  } catch (err) {
    L2KeystonesShow.innerHTML = err;
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
    BitcoinBalanceShow.innerHTML = result;
  } catch (err) {
    BitcoinBalanceShow.innerHTML = err;
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
    BitcoinInfoShow.innerHTML = result;
  } catch (err) {
    BitcoinInfoShow.innerHTML = err;
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
      method: 'bitcoinUtxos',
      scriptHash: BitcoinUTXOsScriptHashInput.value, 
    });
    BitcoinUTXOsShow.innerHTML = result;
  } catch (err) {
    BitcoinUTXOsShow.innerHTML = err;
    console.error('Caught exception', err);
  }
}

BitcoinUTXOsButton.addEventListener('click', () => {
  BitcoinUTXOs();
});

