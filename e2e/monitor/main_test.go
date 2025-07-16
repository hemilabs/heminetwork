// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	client "github.com/btcsuite/btcd/rpcclient"
	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum-optimism/optimism/op-chain-ops/crossdomain"
	"github.com/ethereum-optimism/optimism/op-challenger/game/fault/contracts"
	"github.com/ethereum-optimism/optimism/op-challenger/game/fault/contracts/metrics"
	e2ebindings "github.com/ethereum-optimism/optimism/op-e2e/bindings"
	"github.com/ethereum-optimism/optimism/op-e2e/e2eutils/transactions"
	"github.com/ethereum-optimism/optimism/op-e2e/e2eutils/wait"
	"github.com/ethereum-optimism/optimism/op-node/bindings"
	bindingspreview "github.com/ethereum-optimism/optimism/op-node/bindings/preview"
	"github.com/ethereum-optimism/optimism/op-node/withdrawals"
	"github.com/ethereum-optimism/optimism/op-service/sources/batching"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethclient/gethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/go-test/deep"

	mybindings "github.com/hemilabs/heminetwork/e2e/monitor/bindings"
	"github.com/hemilabs/heminetwork/hemi"
)

const (
	localnetPrivateKey = "dfe61681b31b12b04f239bc0692965c61ffc79244ed9736ffa1a72d00a23a530"
	retries            = 10
	btcAddress         = "mv5gj33YaFviPFDmkkUpb31C4uxoB4ZZ5D"
)

var abort = retries - 1

func addressAt(t *testing.T, path string) common.Address {
	cmd := exec.Command(
		"docker",
		"exec",
		"e2e-op-geth-l2-1", "jq", "-r", "-j", path, "/shared-dir/state.json")

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
		case <-time.Tick(10 * time.Second):
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

		t.Logf("expecting actual balance %v to be greater than %v", balance, expectedPayoutBalance)

		if expectedPayoutBalance.Cmp(balance) > 0 {
			t.Logf("pop miner payout balance received %v, want at least %v", balance, expectedPayoutBalance)
			continue
		}

		if jo.TipHash != jo.TipHashNonSequencing {
			t.Logf("tip mismatch: %s != %s", jo.TipHash, jo.TipHashNonSequencing)
			continue
		}

		// success; we passed the test
		break
	}
}

func TestL1L2Comms(t *testing.T) {
	for _, sequencing := range []bool{true, false} {
		var name string
		if sequencing {
			name = "testing sequencing client"
		} else {
			name = "testing non-sequencing client"
		}
		t.Run(name, func(t *testing.T) {
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

			l2ClientNonSequencing, err := ethclient.Dial("http://localhost:18548")
			if err != nil {
				t.Fatalf("could not dial eth l1 %s", err)
			}

			privateKey, err := crypto.HexToECDSA(localnetPrivateKey)
			if err != nil {
				t.Fatal(err)
			}

			l2ClientToUse := l2Client
			if !sequencing {
				l2ClientToUse = l2ClientNonSequencing
			}

			l1Address := deployL1TestToken(t, ctx, l1Client, privateKey)

			t.Logf("the l1 address is %s", l1Address.Hex())

			bridgeEthL1ToL2(t, ctx, l1Client, l2ClientToUse, privateKey)

			l2Address := deployL2TestToken(t, ctx, l1Address, l2ClientToUse, privateKey)
			t.Logf("the l2 address is %s", l2Address.Hex())

			bridgeERC20FromL1ToL2(t, ctx, l1Address, l2Address, privateKey, l1Client, l2ClientToUse)

			bridgeERC20FromL2ToL1(t, ctx, l1Address, l2Address, privateKey, l1Client, l2ClientToUse)

			bridgeEthL2ToL1(t, ctx, l1Client, l2ClientToUse, privateKey)

			hvmTipNearBtcTip(t, ctx, l2Client, l2ClientNonSequencing, privateKey)
			hvmBtcBalance(t, ctx, l2ClientToUse, privateKey)

			opNodeSequencingEndpoint := "http://localhost:8548"
			opNodeNonSequencingEndpoint := "http://localhost:18547"
			assertOutputRootsAreTheSame(t, ctx, l2ClientToUse, opNodeSequencingEndpoint, opNodeNonSequencingEndpoint)
			assertSafeAndFinalBlocksAreProgressing(t, ctx, l2ClientToUse)
		})
	}
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

func hvmTipNearBtcTip(t *testing.T, ctx context.Context, l2Client *ethclient.Client, l2ClientNonSequencing *ethclient.Client, privateKey *ecdsa.PrivateKey) {
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

	contractAddress, tx, l2ReadBalances, err := mybindings.DeployL2ReadBalances(auth, l2Client)
	if err != nil {
		t.Fatal(err)
	}

	waitForTxReceipt(t, ctx, l2Client, tx)

	res, err := l2ReadBalances.L2ReadBalancesCaller.GetBitcoinLastHeader(nil)
	if err != nil {
		t.Fatal(err)
	}

	l2ReadBalancesNonSequencing, err := mybindings.NewL2ReadBalances(contractAddress, l2ClientNonSequencing)
	if err != nil {
		t.Fatal(err)
	}

	resNonSequencing, err := l2ReadBalancesNonSequencing.L2ReadBalancesCaller.GetBitcoinLastHeader(nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(res, resNonSequencing) {
		t.Fatalf("bitcoin header mismatch between sequencer and non-sequencer: %x != %x", res, resNonSequencing)
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

	balance, err := l2ReadBalances.L2ReadBalancesCaller.GetBitcoinAddressBalance(nil, btcAddress)
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
		auth.Value = big.NewInt(0)       // in wei
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
		t.Fatal(err)
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

	_, err = wait.ForGamePublished(ctx, l1Client, optimismPortalProxy, disputeGameFactoryProxy, big.NewInt(int64(bestL2Block)))
	if err != nil {
		t.Fatal(err)
	}

	receiptCl := l2Client
	proofCl := gethclient.New(receiptCl.Client())

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

		gameContractCaller, err := e2ebindings.NewFaultDisputeGame(provenGame.DisputeGameProxy, l1Client)
		if err != nil {
			t.Fatal(err)
		}

		maxClockDuration, err := gameContractCaller.MaxClockDuration(&bind.CallOpts{})
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("the max clock duration is %d, will wait", maxClockDuration)

		time.Sleep(time.Duration(maxClockDuration)*time.Second + 1)

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

			tx, err = portal.FinalizeWithdrawalTransaction(opts, wd.WithdrawalTransaction())
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("the finalization tx is %s", tx.Hash())

			tries = append(tries, tx)

			receiptFound := false

			for _, try := range tries {
				receipt = waitForTxReceiptForSeconds(t, ctx, l1Client, try, 120*time.Second)
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
		auth.Value = big.NewInt(0)       // in wei
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

	_, err = wait.ForGamePublished(ctx, l1Client, optimismPortalProxy, disputeGameFactoryProxy, big.NewInt(int64(bestL2Block)))
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
	time.Sleep(time.Duration((proofMaturityDelaySeconds+1)*2) * time.Second)

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

		fds, err := portal2.DisputeGameFinalityDelaySeconds(nil)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("the disputeGameFinalityDelaySeconds is %d", fds)

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

		gameContractCaller, err := e2ebindings.NewFaultDisputeGame(provenGame.DisputeGameProxy, l1Client)
		if err != nil {
			t.Fatal(err)
		}

		maxClockDuration, err := gameContractCaller.MaxClockDuration(&bind.CallOpts{})
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("the max clock duration is %d, will wait", maxClockDuration)

		time.Sleep(time.Duration(maxClockDuration)*time.Second + 1)

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

			tx, err = portal.FinalizeWithdrawalTransaction(opts, wd.WithdrawalTransaction())
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("the finalization tx is %s", tx.Hash())

			tries = append(tries, tx)

			receiptFound := false

			for _, try := range tries {
				receipt = waitForTxReceiptForSeconds(t, ctx, l1Client, try, 120*time.Second)
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

func assertSafeAndFinalBlocksAreProgressing(t *testing.T, ctx context.Context, l2Client *ethclient.Client) {
	block, err := l2Client.BlockByNumber(ctx, big.NewInt(int64(rpc.SafeBlockNumber)))
	if err != nil {
		t.Fatalf("error getting safe block: %s", err)
	}

	if block.NumberU64() <= 0 {
		t.Fatalf("safe block number should be greater than 0, received %d", block.NumberU64())
	}

	block, err = l2Client.BlockByNumber(ctx, big.NewInt(int64(rpc.FinalizedBlockNumber)))
	if err != nil {
		t.Fatalf("error getting finalized block: %s", err)
	}

	if block.NumberU64() <= 0 {
		t.Fatalf("finalized block number should be greater than 0, received %d", block.NumberU64())
	}
}

func assertOutputRootsAreTheSame(t *testing.T, ctx context.Context, l2Client *ethclient.Client, opNodeSequencingEndpoint string, opNodeNonSequencingEndpoint string) {
	bigTip, err := l2Client.HeaderByNumber(t.Context(), nil)
	if err != nil {
		t.Fatalf("error getting l2 tip: %s", err)
	}

	tip := bigTip.Number.Uint64()

	tip -= 5

	t.Logf("checking output roots from tip %d", tip)

	type outputAtBlock struct {
		ID      int      `json:"id"`
		Method  string   `json:"method"`
		Params  []string `json:"params"`
		JsonRpc string   `json:"jsonrpc"`
	}

	for tip != 0 {
		hexTip := fmt.Sprintf("%#x", tip)
		requestBody := outputAtBlock{
			ID:      1,
			Method:  "optimism_outputAtBlock",
			Params:  []string{hexTip},
			JsonRpc: "2.0",
		}

		jsonbody, err := json.Marshal(requestBody)
		if err != nil {
			t.Fatalf("error marshalling request body: %s", err)
		}

		t.Logf("sending request json body: %s", string(jsonbody))

		client := &http.Client{}

		res, err := client.Post(opNodeSequencingEndpoint, "application/json", bytes.NewBuffer(jsonbody))
		if err != nil {
			t.Fatalf("error making request to sequencer endpoint: %s", err)
		}

		res2, err := client.Post(opNodeNonSequencingEndpoint, "application/json", bytes.NewBuffer(jsonbody))
		if err != nil {
			t.Fatalf("error making request to sequencer endpoint: %s", err)
		}

		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("error reading response body from sequencer: %s", err)
		}

		resBody2, err := io.ReadAll(res2.Body)
		if err != nil {
			t.Fatalf("error reading response body from non-sequencer: %s", err)
		}

		res.Body.Close()
		res2.Body.Close()

		assertResultNotError := func(body *outputAtBlockResponse) error {
			if body.Error != nil {
				return fmt.Errorf("error in response body: %v", body)
			}

			return nil
		}

		var outputAtBlockResponseOne outputAtBlockResponse
		var outputAtBlockResponseTwo outputAtBlockResponse

		if err := json.Unmarshal(resBody, &outputAtBlockResponseOne); err != nil {
			t.Fatal(err)
		}

		if err := json.Unmarshal(resBody2, &outputAtBlockResponseTwo); err != nil {
			t.Fatal(err)
		}

		if err := assertResultNotError(&outputAtBlockResponseOne); err != nil {
			t.Fatalf("error in response: %v", outputAtBlockResponseOne.Error)
		}

		if err := assertResultNotError(&outputAtBlockResponseTwo); err != nil {
			t.Fatalf("error in response: %v", outputAtBlockResponseTwo.Error)
		}

		assertResultNotError(&outputAtBlockResponseOne)
		assertResultNotError(&outputAtBlockResponseTwo)

		if diff := deep.Equal(outputAtBlockResponseOne, outputAtBlockResponseTwo); len(diff) > 0 {
			t.Fatalf("output roots are not the same: %s", diff)
		}

		tip--
	}
}

func waitForTxReceipt(t *testing.T, ctx context.Context, client *ethclient.Client, tx *types.Transaction) *types.Receipt {
	return waitForTxReceiptForSeconds(t, ctx, client, tx, 5*time.Second)
}

// put here for readability
const operatorFeeVaultCode = "60806040526004361061005e5760003560e01c80635c60da1b116100435780635c60da1b146100be5780638f283970146100f8578063f851a440146101185761006d565b80633659cfe6146100755780634f1ef286146100955761006d565b3661006d5761006b61012d565b005b61006b61012d565b34801561008157600080fd5b5061006b6100903660046106dd565b610224565b6100a86100a33660046106f8565b610296565b6040516100b5919061077b565b60405180910390f35b3480156100ca57600080fd5b506100d3610419565b60405173ffffffffffffffffffffffffffffffffffffffff90911681526020016100b5565b34801561010457600080fd5b5061006b6101133660046106dd565b6104b0565b34801561012457600080fd5b506100d3610517565b60006101577f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc5490565b905073ffffffffffffffffffffffffffffffffffffffff8116610201576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152602560248201527f50726f78793a20696d706c656d656e746174696f6e206e6f7420696e6974696160448201527f6c697a656400000000000000000000000000000000000000000000000000000060648201526084015b60405180910390fd5b3660008037600080366000845af43d6000803e8061021e573d6000fd5b503d6000f35b7fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035473ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16148061027d575033155b1561028e5761028b816105a3565b50565b61028b61012d565b60606102c07fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035490565b73ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614806102f7575033155b1561040a57610305846105a3565b6000808573ffffffffffffffffffffffffffffffffffffffff16858560405161032f9291906107ee565b600060405180830381855af49150503d806000811461036a576040519150601f19603f3d011682016040523d82523d6000602084013e61036f565b606091505b509150915081610401576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152603960248201527f50726f78793a2064656c656761746563616c6c20746f206e657720696d706c6560448201527f6d656e746174696f6e20636f6e7472616374206661696c65640000000000000060648201526084016101f8565b91506104129050565b61041261012d565b9392505050565b60006104437fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035490565b73ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16148061047a575033155b156104a557507f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc5490565b6104ad61012d565b90565b7fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035473ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161480610509575033155b1561028e5761028b8161060c565b60006105417fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035490565b73ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161480610578575033155b156104a557507fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035490565b7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc81815560405173ffffffffffffffffffffffffffffffffffffffff8316907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b90600090a25050565b60006106367fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035490565b7fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61038381556040805173ffffffffffffffffffffffffffffffffffffffff80851682528616602082015292935090917f7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f910160405180910390a1505050565b803573ffffffffffffffffffffffffffffffffffffffff811681146106d857600080fd5b919050565b6000602082840312156106ef57600080fd5b610412826106b4565b60008060006040848603121561070d57600080fd5b610716846106b4565b9250602084013567ffffffffffffffff8082111561073357600080fd5b818601915086601f83011261074757600080fd5b81358181111561075657600080fd5b87602082850101111561076857600080fd5b6020830194508093505050509250925092565b600060208083528351808285015260005b818110156107a85785810183015185820160400152820161078c565b818111156107ba576000604083870101525b50601f017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe016929092016040019392505050565b818382376000910190815291905056fea164736f6c634300080f000a"

type outputAtBlockResponse struct {
	Jsonrpc string       `json:"jsonrpc"`
	ID      int          `json:"id"`
	Error   *interface{} `json:"error,omitempty"`
	Result  struct {
		Version    string `json:"version"`
		OutputRoot string `json:"outputRoot"`
		BlockRef   struct {
			Hash       string `json:"hash"`
			Number     int    `json:"number"`
			ParentHash string `json:"parentHash"`
			Timestamp  int    `json:"timestamp"`
			L1Origin   struct {
				Hash   string `json:"hash"`
				Number int    `json:"number"`
			} `json:"l1origin"`
			SequenceNumber int `json:"sequenceNumber"`
		} `json:"blockRef"`
		WithdrawalStorageRoot string `json:"withdrawalStorageRoot"`
		StateRoot             string `json:"stateRoot"`
	} `json:"result"`
}
