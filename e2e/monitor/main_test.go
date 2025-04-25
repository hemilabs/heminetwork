// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/hemilabs/heminetwork/hemi"

	// ope2e "github.com/ethereum-optimism/optimism/op-e2e"
	"github.com/ethereum-optimism/optimism/op-node/bindings"
	// "github.com/ethereum-optimism/optimism/op-e2e/bindingspreview"
	"github.com/ethereum-optimism/optimism/op-chain-ops/crossdomain"
	"github.com/ethereum-optimism/optimism/op-e2e/e2eutils/wait"
	"github.com/ethereum-optimism/optimism/op-node/withdrawals"
	"github.com/ethereum/go-ethereum/ethclient/gethclient"
)

const (
	localnetPrivateKey = "dfe61681b31b12b04f239bc0692965c61ffc79244ed9736ffa1a72d00a23a530"
	retries            = 10
)

var (
	l1StandardBridge = common.Address(common.FromHex("654fe8bC4F8Bf51f0CeC4567399aD7067E145C3F"))
	abort            = retries - 1
)

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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
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

		address, tx, _, err = DeployTesttoken(auth, l1Client)
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

	testToken, err := NewTesttoken(address, l1Client)
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

		tx, err = testToken.Approve(auth, l1StandardBridge, big.NewInt(100))
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

	bridge, err := NewL1StandardBridge(l1StandardBridge, l1Client)
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
		auth.GasLimit = uint64(2000000) // in units
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

		address, tx, _, err = DeployOptimismMintableERC20(auth, l2Client, common.Address(common.FromHex("0x4200000000000000000000000000000000000010")), l1Address, "TestToken", "$TT", 1)
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

	bridge, err := NewL1StandardBridge(l1StandardBridge, l1Client)
	if err != nil {
		t.Fatal(err)
	}

	optimismMintableErc2, err := NewOptimismMintableERC20(l2Address, l2Client)
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

		tx, err := optimismMintableErc2.OptimismMintableERC20Transactor.IncreaseAllowance(auth, l1StandardBridge, big.NewInt(10000))
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

		testToken, err := NewTesttoken(l1Address, l1Client)
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
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("error casting public key to ECDSA")
	}

	receiverAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	bridge, err := NewL2StandardBridge(common.Address(common.FromHex("0x4200000000000000000000000000000000000010")), l2Client)
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
		auth.GasLimit = uint64(3000000) // in units
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

	t.Logf("waiting for output root to be published")
	ooproxy := common.Address(common.FromHex("e67575204500AA637a013Db8fF9610940CACf9E6"))
	blockNumber, err := wait.ForOutputRootPublished(ctx, l1Client, ooproxy, receipt.BlockNumber)
	if err != nil {
		t.Fatal(err)
	}

	receiptCl := l2Client
	proofCl := gethclient.New(receiptCl.Client())

	header, err := receiptCl.HeaderByNumber(ctx, big.NewInt(int64(blockNumber)))
	if err != nil {
		t.Fatal(err)
	}

	oracle, err := bindings.NewL2OutputOracleCaller(ooproxy, l1Client)
	if err != nil {
		t.Fatal(err)
	}

	optimismPortalProxy := common.Address(common.FromHex("4859725d8f2f49aE689512eE5F150FdcB76cd72c"))

	params, err := withdrawals.ProveWithdrawalParameters(ctx, proofCl, receiptCl, tx.Hash(), header, oracle)
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

	t.Logf("waiting for the finalization period")
	if err := wait.ForFinalizationPeriod(ctx, l1Client, receipt.BlockNumber, ooproxy); err != nil {
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

		t.Logf("going to finalize the transaction through the portal")

		wd := crossdomain.Withdrawal{
			Nonce:    params.Nonce,
			Sender:   &params.Sender,
			Target:   &params.Target,
			Value:    params.Value,
			GasLimit: params.GasLimit,
			Data:     params.Data,
		}

		tx, err = portal.FinalizeWithdrawalTransaction(opts, wd.WithdrawalTransaction())
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("the finalization tx is %s", tx.Hash())

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

	testToken, err := NewTesttoken(l1Address, l1Client)
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

func waitForTxReceipt(t *testing.T, ctx context.Context, client *ethclient.Client, tx *types.Transaction) *types.Receipt {
	t.Logf("will wait for receipt of tx %s", tx.Hash())
	time.Sleep(5 * time.Second)
	receipt, err := client.TransactionReceipt(ctx, tx.Hash())
	if err != nil {
		t.Logf("error getting tx receipt, will retry: %s", err)
		return nil
	} else {
		return receipt
	}
}
