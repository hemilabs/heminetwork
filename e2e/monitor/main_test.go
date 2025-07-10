// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"slices"
	"testing"
	"time"
	"os/exec"

	// "github.com/ethereum-optimism/optimism/op-e2e/bindingspreview"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	client "github.com/btcsuite/btcd/rpcclient"
	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum-optimism/optimism/op-chain-ops/crossdomain"
	// ope2e "github.com/ethereum-optimism/optimism/op-e2e"
	e2ebindings "github.com/ethereum-optimism/optimism/op-e2e/bindings"
	bindingspreview  "github.com/ethereum-optimism/optimism/op-node/bindings/preview"
	"github.com/ethereum-optimism/optimism/op-e2e/e2eutils/wait"
	"github.com/ethereum-optimism/optimism/op-node/bindings"
	"github.com/ethereum-optimism/optimism/op-node/withdrawals"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethclient/gethclient"
	"github.com/ethereum-optimism/optimism/op-challenger/game/fault/contracts"
	"github.com/ethereum-optimism/optimism/op-challenger/game/fault/contracts/metrics"
	"github.com/ethereum-optimism/optimism/op-e2e/e2eutils/transactions"

	"github.com/ethereum-optimism/optimism/op-service/sources/batching"

	mybindings "github.com/hemilabs/heminetwork/e2e/monitor/bindings"
	"github.com/hemilabs/heminetwork/hemi"
)

const (
	localnetPrivateKey = "dfe61681b31b12b04f239bc0692965c61ffc79244ed9736ffa1a72d00a23a530"
	retries            = 10
	btcAddress         = "mw47rj9rG25J67G6W8bbjRayRQjWN5ZSEG"
)

var (
	// l1StandardBridge = common.Address(common.FromHex("0x0F38Af108B73731E95EA057ef8463E4B2327f36e"))
	abort            = retries - 1
)

func addressAt(t *testing.T, path string) common.Address {
	cmd := exec.Command(
		"docker", 
		"exec", 
		"e2e-op-geth-l2-1", "jq", "-r", "-j", path, "/l2configs/state.json" )
	
		output, err := cmd.Output()
		if err != nil {
			t.Fatalf("Command failed with error: %v -- %s", err, output)
		}
	
		return common.Address(common.FromHex(string(output))) 
}

func disputeGameFactory(t *testing.T) common.Address {
		a := addressAt(t, ".opChainDeployments[0].disputeGameFactoryProxyAddress")
		t.Logf("assuming dispute game factory proxy address is %s", a)
		return a
	}

func l1StandardBridge(t *testing.T) common.Address {
	a := addressAt(t, ".opChainDeployments[0].l1StandardBridgeProxyAddress")
	t.Logf("assuming l1 standard bridge proxy address is %s", a)
	return a
}

func optimismPortalProxy(t *testing.T) common.Address {
	a := addressAt(t, ".opChainDeployments[0].optimismPortalProxyAddress")
	t.Logf("assuming optimism portal proxy address is %s", a)
	return a
}

func game(t *testing.T) common.Address {
	a := addressAt(t, ".opChainDeployments[0].permissionedDisputeGameAddress")
	t.Logf("assuming permissioned dispute game address is %s", a)
	return a
}



// Test_Monitor is a small, bare-bones test to dump the state of localnet
// after 5 minutes and check that it has progressed at least to a certain
// point
func TestMonitor(t *testing.T) {
	// let localnet start, there are smarter ways to do this but this will work
	// for now
	time.Sleep(2 * time.Minute)

	// somewhat arbitrary; we should be able to get to 24 pop txs mined in a
	// reasonable amount of time
	const expectedPopTxs = 24
	t.Logf("expecting at least %d pop txs mined", expectedPopTxs)

	// the expected balance should be at least 1 BaseHEMI per poptx - 20.  We say
	// "- 20" because we lag 20 keystones behind a pop payout
	expectedPayouts := expectedPopTxs - 20
	expectedPayoutBalance := big.NewInt(hemi.HEMIBase)
	expectedPayoutBalance = expectedPayoutBalance.Mul(big.NewInt(int64(expectedPayouts)), expectedPayoutBalance)
	t.Logf("expecting a HEMI balance of at least %d", expectedPayoutBalance)

	// if we get to 10 minutes without the expected number of pop txs
	// and HEMI balance, something is wrong, fail the test
	blockWaitTimeoutTimer := time.NewTimer(15 * time.Minute)

	for {
		// poll every 10 seconds until timeout
		select {
		case <-blockWaitTimeoutTimer.C:
			t.Fatalf("timed out")
		case <-time.After(10 * time.Second):
		}

		// let the goroutines gather stats for 10 seconds, then dump
		// it and check the results, if they're not what we expected try again
		output := monitor(uint(10 * 1000))
		t.Log(output)

		var jo jsonOutput
		if err := json.Unmarshal([]byte(output), &jo); err != nil {
			t.Fatal(err)
		}

		if jo.PopTxCount < uint64(expectedPopTxs) {
			t.Logf("popTxCount %d < %d", jo.PopTxCount, expectedPopTxs)
			continue
		}

		popMinerBalance := big.NewInt(0)
		balance, ok := popMinerBalance.SetString(jo.PopMinerHemiBalance, 10)
		if !ok {
			t.Fatalf("could not parse balance from %s", jo.PopMinerHemiBalance)
		}

		t.Logf("expecting actual balance %d to be greater than %d", balance, expectedPayoutBalance)

		if expectedPayoutBalance.Cmp(balance) > 0 {
			t.Logf("pop miner payout balance received %d, want at least %d", balance, expectedPayoutBalance)
			continue
		}

		// success; we passed the test
		break
	}
}

func TestL1L2Comms(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Minute)
	defer cancel()

	l1Client, err := ethclient.Dial("http://localhost:8545")
	if err != nil {
		t.Fatalf("could not dial eth l1 %s", err)
	}

	l2Client, err := ethclient.Dial("http://localhost:8546")
	if err != nil {
		t.Fatalf("could not dial eth l1 %s", err)
	}

	privateKey, err := crypto.HexToECDSA(localnetPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	l1Address := deployL1TestToken(t, ctx, l1Client, privateKey)

	t.Logf("the l1 address is %s", l1Address.Hex())

	bridgeEthL1ToL2(t, ctx, l1Client, l2Client, privateKey)

	l2Address := deployL2TestToken(t, ctx, l1Address, l2Client, privateKey)
	t.Logf("the l2 address is %s", l2Address.Hex())

	bridgeERC20FromL1ToL2(t, ctx, l1Address, l2Address, privateKey, l1Client, l2Client)

	bridgeERC20FromL2ToL1(t, ctx, l1Address, l2Address, privateKey, l1Client, l2Client)

	bridgeEthL2ToL1(t, ctx, l1Client, l2Client, privateKey)

	hvmTipNearBtcTip(t, ctx, l2Client, privateKey)
	hvmBtcBalance(t, ctx, l2Client, privateKey)
}

func TestOperatorFeeVaultIsPresent(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
	defer cancel()

	l2Client, err := ethclient.Dial("http://localhost:8546")
	if err != nil {
		t.Fatalf("could not dial eth l1 %s", err)
	}

	operatorFeeVaultAddr := common.Address(common.FromHex("0x420000000000000000000000000000000000001B"))

	code, err := l2Client.CodeAt(ctx, operatorFeeVaultAddr, nil)
	if err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(code) != operatorFeeVaultCode {
		t.Fatalf("OperatorFeeVaultCode mismatch")
	}
}

func hvmTipNearBtcTip(t *testing.T, ctx context.Context, l2Client *ethclient.Client, privateKey *ecdsa.PrivateKey) {
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("error casting public key to ECDSA")
	}

	receiverAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	nonce, err := l2Client.PendingNonceAt(ctx, receiverAddress)
	if err != nil {
		t.Fatal(err)
	}

	gasPrice, err := l2Client.SuggestGasPrice(ctx)
	if err != nil {
		t.Fatal(err)
	}

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(901))
	if err != nil {
		t.Fatal(err)
	}
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0)      // in wei
	auth.GasLimit = uint64(3000000) // in units
	auth.GasPrice = gasPrice

	_, tx, l2ReadBalances, err := mybindings.DeployL2ReadBalances(auth, l2Client)
	if err != nil {
		t.Fatal(err)
	}

	waitForTxReceipt(t, ctx, l2Client, tx)

	res, err := l2ReadBalances.L2ReadBalancesCaller.GetBitcoinLastHeader(nil)
	if err != nil {
		t.Fatal(err)
	}

	config := client.ConnConfig{
		User:         "user",
		Pass:         "password",
		Host:         "localhost:18443",
		DisableTLS:   true,
		HTTPPostMode: true,
	}
	c, err := client.New(&config, nil)
	if err != nil {
		t.Fatalf("could not create new client from config %v: %v", config, err)
	}

	hashB := res[4 : 32+4]
	slices.Reverse(hashB)
	hash := chainhash.Hash(hashB)

	block, err := c.GetBlockVerbose(&hash)
	if err != nil {
		t.Fatal(err)
	}

	bestBlockHeight, err := c.GetBlockCount()
	if err != nil {
		t.Fatal(err)
	}

	diff := bestBlockHeight - block.Height
	if diff > 4 || diff < 2 {
		t.Fatalf("invalid diff: %d", diff)
	}
}

func hvmBtcBalance(t *testing.T, ctx context.Context, l2Client *ethclient.Client, privateKey *ecdsa.PrivateKey) {
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("error casting public key to ECDSA")
	}

	receiverAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	nonce, err := l2Client.PendingNonceAt(ctx, receiverAddress)
	if err != nil {
		t.Fatal(err)
	}

	gasPrice, err := l2Client.SuggestGasPrice(ctx)
	if err != nil {
		t.Fatal(err)
	}

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(901))
	if err != nil {
		t.Fatal(err)
	}
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0)      // in wei
	auth.GasLimit = uint64(3000000) // in units
	auth.GasPrice = gasPrice

	_, tx, l2ReadBalances, err := mybindings.DeployL2ReadBalances(auth, l2Client)
	if err != nil {
		t.Fatal(err)
	}

	waitForTxReceipt(t, ctx, l2Client, tx)

	balance, err := l2ReadBalances.L2ReadBalancesCaller.GetBitcoinAddressBalance(nil, "mw47rj9rG25J67G6W8bbjRayRQjWN5ZSEG")
	if err != nil {
		t.Fatal(err)
	}

	if balance.Cmp(big.NewInt(0)) <= 0 {
		t.Fatalf("balance too small: %d", balance)
	}
}

func deployL1TestToken(t *testing.T, ctx context.Context, l1Client *ethclient.Client, privateKey *ecdsa.PrivateKey) common.Address {
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("error casting public key to ECDSA")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	var receipt *types.Receipt
	var address common.Address
	var tx *types.Transaction
	for i := 0; i < retries; i++ {
		nonce, err := l1Client.PendingNonceAt(ctx, fromAddress)
		if err != nil {
			t.Fatal(err)
		}

		gasPrice, err := l1Client.SuggestGasPrice(ctx)
		if err != nil {
			t.Fatal(err)
		}

		auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))
		if err != nil {
			t.Fatal(err)
		}
		auth.Nonce = big.NewInt(int64(nonce))
		auth.Value = big.NewInt(0)      // in wei
		auth.GasLimit = uint64(3000000) // in units
		auth.GasPrice = gasPrice

		address, tx, _, err = mybindings.DeployTesttoken(auth, l1Client)
		if err != nil {
			t.Fatal(err)
		}

		receipt := waitForTxReceipt(t, ctx, l1Client, tx)
		if receipt == nil {
			if i == abort {
				t.Fatal("retries exceeded")
			}
			continue
		}

		if receipt.Status == types.ReceiptStatusFailed {
			t.Fatal("tx failed")
		}

		break
	}

	testToken, err := mybindings.NewTesttoken(address, l1Client)
	if err != nil {
		t.Fatal(err)
	}

	balance, err := testToken.BalanceOf(nil, fromAddress)
	if err != nil {
		t.Fatal(err)
	}

	if balance.String() != "1000000000000000000000000" {
		t.Fatalf("unexpected balance: %s", balance.String())
	}

	for i := 0; i < retries; i++ {
		nonce, err := l1Client.PendingNonceAt(ctx, fromAddress)
		if err != nil {
			t.Fatal(err)
		}

		gasPrice, err := l1Client.SuggestGasPrice(ctx)
		if err != nil {
			t.Fatal(err)
		}

		auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))
		if err != nil {
			t.Fatal(err)
		}

		auth.Nonce = big.NewInt(int64(nonce))
		auth.Value = big.NewInt(0)      // in wei
		auth.GasLimit = uint64(3000000) // in units
		auth.GasPrice = gasPrice

		tx, err = testToken.Approve(auth, l1StandardBridge(t), big.NewInt(100))
		if err != nil {
			t.Fatal(err)
		}

		receipt = waitForTxReceipt(t, ctx, l1Client, tx)

		if receipt == nil {
			if i == abort {
				t.Fatal("retries exceeded")
			}
			continue
		}

		if receipt.Status == types.ReceiptStatusFailed {
			t.Fatal("tx failed")
		}

		t.Logf("l1 erc20 approve tx: %s", tx.Hash())
		break
	}

	return address
}

func bridgeEthL1ToL2(t *testing.T, ctx context.Context, l1Client *ethclient.Client, l2Client *ethclient.Client, privateKey *ecdsa.PrivateKey) {
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("error casting public key to ECDSA")
	}

	receiverAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	t.Logf("receiver address is %s", receiverAddress)

	bridge, err := e2ebindings.NewL1StandardBridge(l1StandardBridge(t), l1Client)
	if err != nil {
		t.Fatal(err)
	}

	var value *big.Int
	for i := 0; i < retries; i++ {
		gasPrice, err := l1Client.SuggestGasPrice(ctx)
		if err != nil {
			t.Fatal(err)
		}

		nonce, err := l1Client.PendingNonceAt(ctx, receiverAddress)
		if err != nil {
			t.Fatal(err)
		}

		auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))
		if err != nil {
			t.Fatal(err)
		}
		auth.Nonce = big.NewInt(int64(nonce))
		auth.Value = big.NewInt(0)      // in wei
		auth.GasLimit = uint64(20000000) // in units
		auth.GasFeeCap = gasPrice
		auth.Value = big.NewInt(9000000000000000000)
		value = auth.Value

		tx, err := bridge.L1StandardBridgeTransactor.BridgeETHTo(auth, receiverAddress, 0, []byte{})
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("tx for bridge eth L1 -> L2: %s", tx.Hash().Hex())

		receipt := waitForTxReceipt(t, ctx, l1Client, tx)
		if receipt == nil {
			if i == abort {
				t.Fatal("retries exceeded")
			}
			continue
		}

		if receipt.Status == types.ReceiptStatusFailed {
			t.Fatalf("receipt status is %d (failed), logs: %v", types.ReceiptStatusFailed, receipt.Logs)
		}

		t.Logf("receipt for tx.  gas used: %d, block number: %d, status %d", receipt.GasUsed, receipt.BlockNumber, receipt.Status)
		break
	}

	balance, err := l2Client.BalanceAt(ctx, receiverAddress, nil)
	if err != nil {
		t.Fatal("err")
	}

	// check that we have at least the sent balance in HemiEth
	if balance.Cmp(value) < 0 {
		t.Fatalf("unexpected balance: %s", balance)
	}
}

func bridgeEthL2ToL1(t *testing.T, ctx context.Context, l1Client *ethclient.Client, l2Client *ethclient.Client, privateKey *ecdsa.PrivateKey) {
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("error casting public key to ECDSA")
	}

	receiverAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	bridge, err := e2ebindings.NewL2StandardBridge(common.Address(common.FromHex("0x4200000000000000000000000000000000000010")), l2Client)
	if err != nil {
		t.Fatal(err)
	}

	otherReceiverAddress := common.Address(common.FromHex("06f0f8ee8119b2a0b7a95ba267231be783d8d2ab"))

	var receipt *types.Receipt
	var tx *types.Transaction
	for i := 0; i < retries; i++ {
		gasPrice, err := l2Client.SuggestGasPrice(ctx)
		if err != nil {
			t.Fatal(err)
		}

		nonce, err := l2Client.PendingNonceAt(ctx, receiverAddress)
		if err != nil {
			t.Fatal(err)
		}

		auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(901))
		if err != nil {
			t.Fatal(err)
		}
		auth.Nonce = big.NewInt(int64(nonce))
		auth.Value = big.NewInt(97)     // in wei
		auth.GasLimit = uint64(3000000) // in units
		auth.GasFeeCap = gasPrice

		tx, err = bridge.L2StandardBridgeTransactor.BridgeETHTo(auth, otherReceiverAddress, 0, []byte{})
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("tx for bridge eth L2 -> L1: %s", tx.Hash().Hex())

		receipt = waitForTxReceipt(t, ctx, l2Client, tx)
		if receipt == nil {
			if i == abort {
				t.Fatal("retries exceeded")
			}
			continue
		}

		if receipt.Status == types.ReceiptStatusFailed {
			t.Fatalf("receipt status is %d, gas used %d (failed), logs: %v", receipt.Status, receipt.GasUsed, receipt.Logs)
		}

		t.Logf("receipt for tx.  gas used: %d, block number: %d, status %d, nonce %d", receipt.GasUsed, receipt.BlockNumber, receipt.Status, tx.Nonce())
		break
	}

	t.Logf("waiting for output root to be published")

	disputeGameFactoryProxy := disputeGameFactory(t)
	optimismPortalProxy := optimismPortalProxy(t)

	bestL2Block, err := l2Client.BlockNumber(ctx)
	if err != nil {
		t.Fatal(err)
	}


	_, err = wait.ForGamePublished(ctx, l1Client, optimismPortalProxy, disputeGameFactoryProxy,  big.NewInt(int64(bestL2Block)))
	if err != nil {
		t.Fatal(err)
	}

	receiptCl := l2Client
	proofCl := gethclient.New(receiptCl.Client())

	// header, err := receiptCl.HeaderByNumber(ctx, big.NewInt(int64(blockNumber)))
	// if err != nil {
	// 	t.Fatal(err)
	// }

	disputeGameCaller, err := bindings.NewDisputeGameFactoryCaller(disputeGameFactoryProxy, l1Client)
	if err != nil {
		t.Fatal(err)
	}

	optimismPortalProxyCaller, err := bindingspreview.NewOptimismPortal2Caller(optimismPortalProxy, l1Client)
	if err != nil {
		t.Fatal(err)
	}


	params, err := withdrawals.ProveWithdrawalParametersFaultProofs(ctx, proofCl, receiptCl, receiptCl, tx.Hash(), disputeGameCaller, optimismPortalProxyCaller)
	if err != nil {
		t.Fatal(err)
	}

	portal, err := bindings.NewOptimismPortal(optimismPortalProxy, l1Client)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < retries; i++ {
		nonce, err := l1Client.PendingNonceAt(ctx, receiverAddress)
		if err != nil {
			t.Fatal(err)
		}

		gasPrice, err := l1Client.SuggestGasPrice(ctx)
		if err != nil {
			t.Fatal(err)
		}

		opts, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))
		if err != nil {
			t.Fatal(err)
		}

		opts.Nonce = big.NewInt(int64(nonce))
		opts.GasLimit = 9000000
		opts.GasFeeCap = gasPrice
		opts.Value = big.NewInt(0)

		t.Logf("going to prove withdrawal transaction")

		t.Logf("the withdraw params: %s", spew.Sdump(params))

		// Prove withdrawal
		tx, err = portal.ProveWithdrawalTransaction(
			opts,
			bindings.TypesWithdrawalTransaction{
				Nonce:    params.Nonce,
				Sender:   params.Sender,
				Target:   params.Target,
				Value:    params.Value,
				GasLimit: params.GasLimit,
				Data:     params.Data,
			},
			params.L2OutputIndex,
			params.OutputRootProof,
			params.WithdrawalProof,
		)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("prove withdrawal tx is %s", tx.Hash())

		receipt = waitForTxReceipt(t, ctx, l1Client, tx)
		if receipt == nil {
			if i == abort {
				t.Fatal("retries exceeded")
			}
			continue
		}

		if receipt.Status == types.ReceiptStatusFailed {
			t.Fatal("tx failed")
		}
		break
	}

	for i := 0; i < retries; i++ {
		nonce, err := l1Client.PendingNonceAt(ctx, receiverAddress)
		if err != nil {
			t.Fatal(err)
		}

		gasPrice, err := l1Client.SuggestGasPrice(ctx)
		if err != nil {
			t.Fatal(err)
		}

		opts, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))
		if err != nil {
			t.Fatal(err)
		}

		opts.Nonce = big.NewInt(int64(nonce))
		opts.GasLimit = 9000000
		opts.GasFeeCap = gasPrice
		opts.Value = big.NewInt(0)

		t.Logf("going to finalize the transaction through the portal")

		wd := crossdomain.Withdrawal{
			Nonce:    params.Nonce,
			Sender:   &params.Sender,
			Target:   &params.Target,
			Value:    params.Value,
			GasLimit: params.GasLimit,
			Data:     params.Data,
		}

		portal2, err := bindingspreview.NewOptimismPortal2(optimismPortalProxy, l1Client)
		if err != nil {
			t.Fatal(err)
		}

		wdHash, err := wd.Hash()
		if err != nil {
			t.Fatal(err)
		}

		provenGame, err := portal2.ProvenWithdrawals(&bind.CallOpts{}, wdHash, opts.From)
		if err != nil {
			t.Fatal(err)
		}

		caller := batching.NewMultiCaller(l1Client.Client(), batching.DefaultBatchSize)
		gameContract, err := contracts.NewFaultDisputeGameContract(ctx, metrics.NoopContractMetrics, provenGame.DisputeGameProxy, caller)
		if err != nil {
			t.Fatal(err)
		}

		if err := gameContract.CallResolveClaim(ctx, 0); err != nil {
			if i == abort {
				t.Fatal(err)
			}
			time.Sleep(1 * time.Second)
			continue
		}

		resolvedtx, err := gameContract.ResolveClaimTx(0)
		if err != nil {
			t.Fatal(err)
		}

		_, _, err = transactions.SendTx(ctx, l1Client, resolvedtx, privateKey)
		if err != nil {
			t.Fatal(err)
		}

		resolvedtx, err = gameContract.ResolveTx()
		if err != nil {
			t.Fatal(err)
		}
		
		transactions.RequireSendTx(t, ctx, l1Client, resolvedtx, privateKey, transactions.WithReceiptStatusIgnore())

		t.Log("FinalizeWithdrawal: waiting for successful withdrawal check...")

		if err := wait.ForWithdrawalCheck(ctx, l1Client, wd, optimismPortalProxy, opts.From); err != nil {
			t.Fatal(err)
		}

		tries := []*types.Transaction{}
		for i := 0;i< retries;i++ {
			nonce, err := l1Client.PendingNonceAt(ctx, receiverAddress)
			if err != nil {
				t.Fatal(err)
			}
	
			gasPrice, err := l1Client.SuggestGasPrice(ctx)
			if err != nil {
				t.Fatal(err)
			}
	
			opts, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))
			if err != nil {
				t.Fatal(err)
			}
	
			opts.Nonce = big.NewInt(int64(nonce))
			opts.GasLimit = 9000000
			opts.GasFeeCap = gasPrice
			opts.Value = big.NewInt(0)
	
			tx, err = portal.FinalizeWithdrawalTransaction(opts, wd.WithdrawalTransaction())
			if err != nil {
				t.Fatal(err)
			}
	
			t.Logf("the finalization tx is %s", tx.Hash())
			
			tries = append(tries, tx)

			receiptFound := false

			for _, try := range tries {
				receipt = waitForTxReceiptForSeconds(t, ctx, l1Client, try, 120 * time.Second)
				if receipt == nil || receipt.Status == types.ReceiptStatusFailed {
					if i == abort {
						t.Fatal("retries exceeded")
					}
				} else if receipt.Status != types.ReceiptStatusFailed {
					receiptFound = true
					break
				}
			}

			if receiptFound {
				break
			}
		}
		break

	}

	balance, err := l1Client.BalanceAt(ctx, otherReceiverAddress, nil)
	if err != nil {
		t.Fatal(err)
	}

	mod := big.NewInt(0)
	mod.Mod(balance, big.NewInt(97))

	// the balance must be greater than zero and divisible by 97.  we
	// send 97 eth from l1 to l2.  if you run this test more than once on the
	// same network, it will send 97 multiple times
	if balance.Cmp(big.NewInt(0)) != 1 || mod.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("unexpected balance: %d", balance)
	}
}

func deployL2TestToken(t *testing.T, ctx context.Context, l1Address common.Address, l2Client *ethclient.Client, privateKey *ecdsa.PrivateKey) common.Address {
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("error casting public key to ECDSA")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	var address common.Address
	var tx *types.Transaction
	for i := 0; i < retries; i++ {
		nonce, err := l2Client.PendingNonceAt(ctx, fromAddress)
		if err != nil {
			t.Fatal(err)
		}

		gasPrice, err := l2Client.SuggestGasPrice(ctx)
		if err != nil {
			t.Fatal(err)
		}

		auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(901))
		if err != nil {
			t.Fatal(err)
		}
		auth.Nonce = big.NewInt(int64(nonce))
		auth.Value = big.NewInt(0)      // in wei
		auth.GasLimit = uint64(2000000) // in units
		auth.GasFeeCap = gasPrice

		address, tx, _, err = e2ebindings.DeployOptimismMintableERC20(auth, l2Client, common.Address(common.FromHex("0x4200000000000000000000000000000000000010")), l1Address, "TestToken", "$TT", 1)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("optimism mintable deployment tx %s", tx.Hash())

		receipt := waitForTxReceipt(t, ctx, l2Client, tx)
		if receipt == nil {
			if i == abort {
				t.Fatal("retries exceeded")
			}
			continue
		}

		if receipt.Status == types.ReceiptStatusFailed {
			t.Fatalf("transaction failed: %v", receipt.Logs)
		}

		break
	}

	return address
}

func bridgeERC20FromL1ToL2(t *testing.T, ctx context.Context, l1Address common.Address, l2Address common.Address, privateKey *ecdsa.PrivateKey, l1Client *ethclient.Client, l2Client *ethclient.Client) {
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("error casting public key to ECDSA")
	}

	receiverAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	bridge, err := e2ebindings.NewL1StandardBridge(l1StandardBridge(t), l1Client)
	if err != nil {
		t.Fatal(err)
	}

	optimismMintableErc2, err := e2ebindings.NewOptimismMintableERC20(l2Address, l2Client)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < retries; i++ {
		gasPrice, err := l2Client.SuggestGasPrice(ctx)
		if err != nil {
			t.Fatal(err)
		}

		nonce, err := l2Client.PendingNonceAt(ctx, receiverAddress)
		if err != nil {
			t.Fatal(err)
		}

		auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(901))
		if err != nil {
			t.Fatal(err)
		}
		auth.Nonce = big.NewInt(int64(nonce))
		auth.Value = big.NewInt(0)      // in wei
		auth.GasLimit = uint64(3000000) // in units
		auth.GasFeeCap = gasPrice

		tx, err := optimismMintableErc2.OptimismMintableERC20Transactor.IncreaseAllowance(auth, l1StandardBridge(t), big.NewInt(10000))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("tx to increase allowance: %s", tx.Hash().Hex())

		receipt := waitForTxReceipt(t, ctx, l2Client, tx)
		if receipt == nil {
			if i == abort {
				t.Fatal("retries exceeded")
			}
			continue
		}

		if receipt.Status == types.ReceiptStatusFailed {
			t.Fatalf("receipt status is %d (failed), logs: %v", types.ReceiptStatusFailed, receipt.Logs)
		}

		break
	}

	for i := 0; i < retries; i++ {
		gasPrice, err := l1Client.SuggestGasPrice(ctx)
		if err != nil {
			t.Fatal(err)
		}

		nonce, err := l1Client.PendingNonceAt(ctx, receiverAddress)
		if err != nil {
			t.Fatal(err)
		}

		auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))
		if err != nil {
			t.Fatal(err)
		}
		auth.Nonce = big.NewInt(int64(nonce))
		auth.Value = big.NewInt(0)      // in wei
		auth.GasLimit = uint64(3000000) // in units
		auth.GasFeeCap = gasPrice

		tx, err := bridge.L1StandardBridgeTransactor.BridgeERC20To(auth, l1Address, l2Address, receiverAddress, big.NewInt(100), 0, []byte{})
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("tx for bridge erc20 L1 -> L2: %s", tx.Hash().Hex())

		receipt := waitForTxReceipt(t, ctx, l1Client, tx)
		if receipt == nil {
			if i == abort {
				t.Fatal("retries exceeded")
			}
			continue
		}

		if receipt.Status == types.ReceiptStatusFailed {
			t.Fatalf("receipt status is %d, gas used %d (failed), logs: %v", receipt.Status, receipt.GasUsed, receipt.Logs)
		}

		t.Logf("receipt for tx.  gas used: %d, block number: %d, status %d", receipt.GasUsed, receipt.BlockNumber, receipt.Status)

		balance, err := optimismMintableErc2.OptimismMintableERC20Caller.BalanceOf(nil, receiverAddress)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("the l2 erc20 balance is %d", balance)

		if balance.String() != "100" {
			t.Fatalf("unexpected balance: %s", balance)
		}

		testToken, err := mybindings.NewTesttoken(l1Address, l1Client)
		if err != nil {
			t.Fatal(err)
		}

		balance, err = testToken.BalanceOf(nil, receiverAddress)
		if err != nil {
			t.Fatal(err)
		}

		if balance.String() != "999999999999999999999900" {
			t.Fatalf("unexpected balance: %s", balance)
		}
		break
	}
}

func bridgeERC20FromL2ToL1(t *testing.T, ctx context.Context, l1Address common.Address, l2Address common.Address, privateKey *ecdsa.PrivateKey, l1Client *ethclient.Client, l2Client *ethclient.Client) {
	optimismPortalProxy := optimismPortalProxy(t)
	optimismPortalProxyCaller, err := bindingspreview.NewOptimismPortal2Caller(optimismPortalProxy, l1Client)
	if err != nil {
		t.Fatal(err)
	}

	seconds, err := optimismPortalProxyCaller.ProofMaturityDelaySeconds(nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("the ProofMaturityDelaySeconds are: %d", seconds)

	l2Sender, err := optimismPortalProxyCaller.L2Sender(nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("the l2sender is: %s", l2Sender)

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("error casting public key to ECDSA")
	}

	receiverAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	bridge, err := e2ebindings.NewL2StandardBridge(common.Address(common.FromHex("0x4200000000000000000000000000000000000010")), l2Client)
	if err != nil {
		t.Fatal(err)
	}

	var receipt *types.Receipt
	var tx *types.Transaction
	for i := 0; i < retries; i++ {
		gasPrice, err := l2Client.SuggestGasPrice(ctx)
		if err != nil {
			t.Fatal(err)
		}

		nonce, err := l2Client.PendingNonceAt(ctx, receiverAddress)
		if err != nil {
			t.Fatal(err)
		}

		auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(901))
		if err != nil {
			t.Fatal(err)
		}
		auth.Nonce = big.NewInt(int64(nonce))
		auth.Value = big.NewInt(0)      // in wei
		auth.GasLimit = uint64(30000000) // in units
		auth.GasFeeCap = gasPrice

		tx, err = bridge.L2StandardBridgeTransactor.BridgeERC20To(auth, l2Address, l1Address, receiverAddress, big.NewInt(50), 0, []byte{})
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("tx for bridge erc20 L2 -> L1: %s", tx.Hash().Hex())

		receipt = waitForTxReceipt(t, ctx, l2Client, tx)
		if receipt == nil {
			if i == abort {
				t.Fatal("retries exceeded")
			}
			continue
		}

		if receipt.Status == types.ReceiptStatusFailed {
			t.Fatalf("receipt status is %d, gas used %d (failed), logs: %v", receipt.Status, receipt.GasUsed, receipt.Logs)
		}

		t.Logf("receipt for tx.  gas used: %d, block number: %d, status %d, nonce %d", receipt.GasUsed, receipt.BlockNumber, receipt.Status, tx.Nonce())
		break
	}

	disputeGameFactoryProxy := disputeGameFactory(t)

	bestL2Block, err := l2Client.BlockNumber(ctx)
	if err != nil {
		t.Fatal(err)
	}


	_, err = wait.ForGamePublished(ctx, l1Client, optimismPortalProxy, disputeGameFactoryProxy,  big.NewInt(int64(bestL2Block)))
	if err != nil {
		t.Fatal(err)
	}

	receiptCl := l2Client
	proofCl := gethclient.New(receiptCl.Client())

	disputeGameCaller, err := bindings.NewDisputeGameFactoryCaller(disputeGameFactoryProxy, l1Client)
	if err != nil {
		t.Fatal(err)
	}


	params, err := withdrawals.ProveWithdrawalParametersFaultProofs(ctx, proofCl, receiptCl, receiptCl, tx.Hash(), disputeGameCaller, optimismPortalProxyCaller)
	if err != nil {
		t.Fatal(err)
	}

	portal, err := bindings.NewOptimismPortal(optimismPortalProxy, l1Client)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < retries; i++ {
		nonce, err := l1Client.PendingNonceAt(ctx, receiverAddress)
		if err != nil {
			t.Fatal(err)
		}

		gasPrice, err := l1Client.SuggestGasPrice(ctx)
		if err != nil {
			t.Fatal(err)
		}

		opts, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))
		if err != nil {
			t.Fatal(err)
		}

		opts.Nonce = big.NewInt(int64(nonce))
		opts.GasLimit = 9000000
		opts.GasFeeCap = gasPrice
		opts.Value = big.NewInt(0)

		t.Logf("going to prove withdrawal transaction")

		t.Logf("the withdraw params: %s", spew.Sdump(params))

		// Prove withdrawal
		tx, err = portal.ProveWithdrawalTransaction(
			opts,
			bindings.TypesWithdrawalTransaction{
				Nonce:    params.Nonce,
				Sender:   params.Sender,
				Target:   params.Target,
				Value:    params.Value,
				GasLimit: params.GasLimit,
				Data:     params.Data,
			},
			params.L2OutputIndex,
			params.OutputRootProof,
			params.WithdrawalProof,
		)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("prove withdrawal tx is %s", tx.Hash())

		receipt = waitForTxReceipt(t, ctx, l1Client, tx)
		if receipt == nil {
			if i == abort {
				t.Fatal("retries exceeded")
			}
			continue
		}

		if receipt.Status == types.ReceiptStatusFailed {
			t.Fatal("tx failed")
		}
		break
	}

	bestL2Block, err = l2Client.BlockNumber(ctx)
	if err != nil {
		t.Fatal(err)
	}

	proofMaturityDelaySeconds := 10
	time.Sleep(time.Duration((proofMaturityDelaySeconds+1)*2 ) * time.Second)


	for i := 0; i < retries; i++ {
		nonce, err := l1Client.PendingNonceAt(ctx, receiverAddress)
		if err != nil {
			t.Fatal(err)
		}

		gasPrice, err := l1Client.SuggestGasPrice(ctx)
		if err != nil {
			t.Fatal(err)
		}

		opts, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))
		if err != nil {
			t.Fatal(err)
		}

		opts.Nonce = big.NewInt(int64(nonce))
		opts.GasLimit = 9000000
		opts.GasFeeCap = gasPrice
		opts.Value = big.NewInt(0)

		t.Logf("going to finalize the transaction through the portal")

		wd := crossdomain.Withdrawal{
			Nonce:    params.Nonce,
			Sender:   &params.Sender,
			Target:   &params.Target,
			Value:    params.Value,
			GasLimit: params.GasLimit,
			Data:     params.Data,
		}

		portal2, err := bindingspreview.NewOptimismPortal2(optimismPortalProxy, l1Client)
		if err != nil {
			t.Fatal(err)
		}

		wdHash, err := wd.Hash()
		if err != nil {
			t.Fatal(err)
		}

		provenGame, err := portal2.ProvenWithdrawals(&bind.CallOpts{}, wdHash, opts.From)
		if err != nil {
			t.Fatal(err)
		}

		caller := batching.NewMultiCaller(l1Client.Client(), batching.DefaultBatchSize)
		gameContract, err := contracts.NewFaultDisputeGameContract(ctx, metrics.NoopContractMetrics, provenGame.DisputeGameProxy, caller)
		if err != nil {
			t.Fatal(err)
		}

		if err := gameContract.CallResolveClaim(ctx, 0); err != nil {
			if i == abort {
				t.Fatal(err)
			}
			time.Sleep(1 * time.Second)
			continue
		}

		resolvedtx, err := gameContract.ResolveClaimTx(0)
		if err != nil {
			t.Fatal(err)
		}

		_, _, err = transactions.SendTx(ctx, l1Client, resolvedtx, privateKey)
		if err != nil {
			t.Fatal(err)
		}

		resolvedtx, err = gameContract.ResolveTx()
		if err != nil {
			t.Fatal(err)
		}
		
		transactions.RequireSendTx(t, ctx, l1Client, resolvedtx, privateKey, transactions.WithReceiptStatusIgnore())

		t.Log("FinalizeWithdrawal: waiting for successful withdrawal check...")
		err = wait.ForWithdrawalCheck(ctx, l1Client, wd, optimismPortalProxy, opts.From)
		if err != nil {
			t.Fatal(err)
		}

		
		tries := []*types.Transaction{}
		for i := 0;i< retries;i++ {
			nonce, err := l1Client.PendingNonceAt(ctx, receiverAddress)
			if err != nil {
				t.Fatal(err)
			}
	
			gasPrice, err := l1Client.SuggestGasPrice(ctx)
			if err != nil {
				t.Fatal(err)
			}
	
			opts, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))
			if err != nil {
				t.Fatal(err)
			}
	
			opts.Nonce = big.NewInt(int64(nonce))
			opts.GasLimit = 9000000
			opts.GasFeeCap = gasPrice
			opts.Value = big.NewInt(0)
	
			tx, err = portal.FinalizeWithdrawalTransaction(opts, wd.WithdrawalTransaction())
			if err != nil {
				t.Fatal(err)
			}
	
			t.Logf("the finalization tx is %s", tx.Hash())
			
			tries = append(tries, tx)

			receiptFound := false

			for _, try := range tries {
				receipt = waitForTxReceiptForSeconds(t, ctx, l1Client, try, 120 * time.Second)
				if receipt == nil || receipt.Status == types.ReceiptStatusFailed {
					if i == abort {
						t.Fatal("retries exceeded")
					}
				} else if receipt.Status != types.ReceiptStatusFailed {
					receiptFound = true
					break
				}
			}

			if receiptFound {
				break
			}
		}
		break
	}

	testToken, err := mybindings.NewTesttoken(l1Address, l1Client)
	if err != nil {
		t.Fatal(err)
	}

	balance, err := testToken.BalanceOf(nil, receiverAddress)
	if err != nil {
		t.Fatal(err)
	}

	if balance.String() != "999999999999999999999950" {
		t.Fatalf("unexpected balance: %d", balance)
	}
}

func waitForTxReceiptForSeconds(t *testing.T, ctx context.Context, client *ethclient.Client, tx *types.Transaction, s time.Duration) *types.Receipt {
	t.Logf("will wait for receipt of tx %s", tx.Hash())
	time.Sleep(s)
	receipt, err := client.TransactionReceipt(ctx, tx.Hash())
	if err != nil {
		t.Logf("error getting tx receipt, will retry: %s", err)
		return nil
	} else {
		return receipt
	}
}

func waitForTxReceipt(t *testing.T, ctx context.Context, client *ethclient.Client, tx *types.Transaction) *types.Receipt {
	return waitForTxReceiptForSeconds(t, ctx, client, tx, 5 * time.Second)
}

// put here for readability
const operatorFeeVaultCode = "0x60806040526004361061005e5760003560e01c80635c60da1b116100435780635c60da1b146100be5780638f283970146100f8578063f851a440146101185761006d565b80633659cfe6146100755780634f1ef286146100955761006d565b3661006d5761006b61012d565b005b61006b61012d565b34801561008157600080fd5b5061006b610090366004610b77565b610224565b6100a86100a3366004610b92565b610296565b6040516100b59190610c8f565b60405180910390f35b3480156100ca57600080fd5b506100d361048c565b60405173ffffffffffffffffffffffffffffffffffffffff90911681526020016100b5565b34801561010457600080fd5b5061006b610113366004610b77565b610523565b34801561012457600080fd5b506100d361058a565b60006101577f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc5490565b905073ffffffffffffffffffffffffffffffffffffffff8116610201576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152602560248201527f50726f78793a20696d706c656d656e746174696f6e206e6f7420696e6974696160448201527f6c697a656400000000000000000000000000000000000000000000000000000060648201526084015b60405180910390fd5b3660008037600080366000845af43d6000803e8061021e573d6000fd5b503d6000f35b7fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035473ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16148061027d575033155b1561028e5761028b81610616565b50565b61028b61012d565b60606102c07fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035490565b73ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614806102f7575033155b1561047d5761033a6040518060400160405280601981526020017f77696c6c2063616c6c20696d706c20617420616464726573730000000000000081525061067f565b6103438461070e565b61038283838080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152506107af92505050565b61038b84610616565b6000808573ffffffffffffffffffffffffffffffffffffffff1685856040516103b5929190610ca2565b600060405180830381855af49150503d80600081146103f0576040519150601f19603f3d011682016040523d82523d6000602084013e6103f5565b606091505b50915091508161041c8773ffffffffffffffffffffffffffffffffffffffff16601461083e565b60405160200161042c9190610cb2565b60405160208183030381529060405290610473576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101f89190610c8f565b5091506104859050565b61048561012d565b9392505050565b60006104b67fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035490565b73ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614806104ed575033155b1561051857507f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc5490565b61052061012d565b90565b7fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035473ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16148061057c575033155b1561028e5761028b81610a81565b60006105b47fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035490565b73ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614806105eb575033155b1561051857507fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035490565b7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc81815560405173ffffffffffffffffffffffffffffffffffffffff8316907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b90600090a25050565b61028b816040516024016106939190610c8f565b604080517fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe08184030181529190526020810180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff167f41304fac00000000000000000000000000000000000000000000000000000000179052610b29565b60405173ffffffffffffffffffffffffffffffffffffffff8216602482015261028b90604401604080517fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe08184030181529190526020810180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff167f2c2ecbc200000000000000000000000000000000000000000000000000000000179052610b29565b61028b816040516024016107c39190610c8f565b604080517fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe08184030181529190526020810180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff167f0be77f5600000000000000000000000000000000000000000000000000000000179052610b29565b6060600061084d836002610d72565b610858906002610daf565b67ffffffffffffffff81111561087057610870610dc7565b6040519080825280601f01601f19166020018201604052801561089a576020820181803683370190505b5090507f3000000000000000000000000000000000000000000000000000000000000000816000815181106108d1576108d1610df6565b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053507f78000000000000000000000000000000000000000000000000000000000000008160018151811061093457610934610df6565b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a9053506000610970846002610d72565b61097b906001610daf565b90505b6001811115610a18577f303132333435363738396162636465660000000000000000000000000000000085600f16601081106109bc576109bc610df6565b1a60f81b8282815181106109d2576109d2610df6565b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a90535060049490941c93610a1181610e25565b905061097e565b508315610485576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820181905260248201527f537472696e67733a20686578206c656e67746820696e73756666696369656e7460448201526064016101f8565b6000610aab7fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035490565b7fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61038381556040805173ffffffffffffffffffffffffffffffffffffffff80851682528616602082015292935090917f7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f910160405180910390a1505050565b61028b8160006a636f6e736f6c652e6c6f679050600080835160208501845afa505050565b803573ffffffffffffffffffffffffffffffffffffffff81168114610b7257600080fd5b919050565b600060208284031215610b8957600080fd5b61048582610b4e565b600080600060408486031215610ba757600080fd5b610bb084610b4e565b9250602084013567ffffffffffffffff80821115610bcd57600080fd5b818601915086601f830112610be157600080fd5b813581811115610bf057600080fd5b876020828501011115610c0257600080fd5b6020830194508093505050509250925092565b60005b83811015610c30578181015183820152602001610c18565b83811115610c3f576000848401525b50505050565b60008151808452610c5d816020860160208601610c15565b601f017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0169290920160200192915050565b6020815260006104856020830184610c45565b8183823760009101908152919050565b7f50726f78793a2064656c656761746563616c6c20746f206e657720696d706c6581527f6d656e746174696f6e20636f6e7472616374206661696c65642e20696d706c3a60208201527f2000000000000000000000000000000000000000000000000000000000000000604082015260008251610d36816041850160208701610c15565b9190910160410192915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b6000817fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0483118215151615610daa57610daa610d43565b500290565b60008219821115610dc257610dc2610d43565b500190565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b600081610e3457610e34610d43565b507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff019056fea164736f6c634300080f000a"
