// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"math/big"
	"testing"
	"context"
	"crypto/ecdsa"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/hemilabs/heminetwork/hemi"
)

const localnetPrivateKey = "dfe61681b31b12b04f239bc0692965c61ffc79244ed9736ffa1a72d00a23a530"

// Test_Monitor is a small, bare-bones test to dump the state of localnet
// after 5 minutes and check that it has progressed at least to a certain
// point
func TestMonitor(t *testing.T) {
	// let localnet start, there are smarter ways to do this but this will work
	// for now
	waitForSomeBlocks()

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
	ctx, cancel := context.WithTimeout(context.Background(), 5 * time.Minute)
	defer cancel()

	l1Address := deployL1TestToken(t, ctx)
	t.Logf("the l1 address is %s", l1Address.Hex())

	privateKey, err := crypto.HexToECDSA(localnetPrivateKey)
    if err != nil {
        t.Fatal(err)
    }

	publicKey := privateKey.Public()
    publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
    if !ok {
        t.Fatal("error casting public key to ECDSA")
    }

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	bridgeEthL1ToL2(t, ctx, fromAddress)

	waitForSomeBlocks()

	l2Address := deployL2TestToken(t, ctx, l1Address)
	t.Logf("the l2 address is %s", l2Address.Hex())

	bridgeERC20FromL1ToL2(t, ctx, l1Address, l2Address, fromAddress)

	bridgeERC20FromL2ToL1(t, ctx, l1Address, l2Address, fromAddress)
}

func deployL1TestToken(t *testing.T, ctx context.Context) common.Address {
	client, err := ethclient.Dial("http://localhost:8545")
    if err != nil {
        t.Fatalf("could not dial eth l1 %s", err)
    }

	privateKey, err := crypto.HexToECDSA(localnetPrivateKey)
    if err != nil {
        t.Fatal(err)
    }

	publicKey := privateKey.Public()
    publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
    if !ok {
        t.Fatal("error casting public key to ECDSA")
    }

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

    nonce, err := client.PendingNonceAt(ctx, fromAddress)
    if err != nil {
        t.Fatal(err)
    }

	gasPrice, err := client.SuggestGasPrice(ctx)
    if err != nil {
        t.Fatal(err)
    }

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))
	if err != nil {
		t.Fatal(err)
	}
    auth.Nonce = big.NewInt(int64(nonce))
    auth.Value = big.NewInt(0)     // in wei
    auth.GasLimit = uint64(3000000) // in units
    auth.GasPrice = gasPrice

    address, tx, _, err := DeployTesttoken(auth, client)
    if err != nil {
        t.Fatal(err)
    }

    waitForSomeBlocks()

	receipt, err := client.TransactionReceipt(ctx, tx.Hash())
	if err != nil {
		t.Fatal(err)
	}

	if receipt.Status == types.ReceiptStatusFailed {
		t.Fatal("tx failed")
	}

	testToken, err := NewTesttoken(address, client)
	if err != nil {
		t.Fatal(err)
	}

	balance, err := testToken.BalanceOf(nil, fromAddress)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("the balance is %d", balance)

	nonce, err = client.PendingNonceAt(ctx, fromAddress)
    if err != nil {
        t.Fatal(err)
    }

	gasPrice, err = client.SuggestGasPrice(ctx)
    if err != nil {
        t.Fatal(err)
    }

	auth, err = bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))
	if err != nil {
		t.Fatal(err)
	}

    auth.Nonce = big.NewInt(int64(nonce))
    auth.Value = big.NewInt(0)     // in wei
    auth.GasLimit = uint64(3000000) // in units
    auth.GasPrice = gasPrice
	auth.Nonce = big.NewInt(int64(nonce))

	tx, err = testToken.Approve(auth, common.Address(common.FromHex("654fe8bC4F8Bf51f0CeC4567399aD7067E145C3F")), big.NewInt(100))
	if err != nil {
		t.Fatal(err)
	}

	waitForSomeBlocks()

	receipt, err = client.TransactionReceipt(ctx, tx.Hash())
	if err != nil {
		t.Fatal(err)
	}

	if receipt.Status == types.ReceiptStatusFailed {
		t.Fatal("tx failed")
	}

	t.Logf("l1 erc20 approve tx: %s", tx.Hash())

	return address
}

func bridgeEthL1ToL2(t *testing.T, ctx context.Context, receiverAddress common.Address) {
	client, err := ethclient.Dial("http://localhost:8545")
    if err != nil {
        t.Fatalf("could not dial eth l1 %s", err)
    }

	bridge, err := NewL1StandardBridge(common.Address(common.FromHex("654fe8bC4F8Bf51f0CeC4567399aD7067E145C3F")), client)
	if err != nil {
		t.Fatal(err)
	}

	gasPrice, err := client.SuggestGasPrice(ctx)
    if err != nil {
        t.Fatal(err)
    }

	nonce, err := client.PendingNonceAt(ctx, receiverAddress)
    if err != nil {
        t.Fatal(err)
    }

	tx, err := bridge.L1StandardBridgeTransactor.BridgeETHTo(&bind.TransactOpts{
		From: receiverAddress,
		Value: big.NewInt(9000000000000000000),
		GasLimit: 30000000,
		GasPrice: gasPrice, 
		Nonce: big.NewInt(int64(nonce)), 
		Signer: func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
			privateKey, err := crypto.HexToECDSA(localnetPrivateKey)
			if err != nil {
				return nil, err
			}
			signedTx, err := types.SignTx(tx, types.NewCancunSigner(big.NewInt(1337)), privateKey)
			if err != nil {
				return nil, err
			}

			return signedTx, nil
		},
	}, receiverAddress,0, []byte{} )
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("tx for bridge eth L1 -> L2: %s", tx.Hash().Hex())

	waitForSomeBlocks()

	receipt, err := client.TransactionReceipt(ctx, tx.Hash())
	if err != nil {
		t.Fatal(err)
	}

	if receipt.Status == types.ReceiptStatusFailed {
		t.Fatalf("receipt status is %d (failed), logs: %v",types.ReceiptStatusFailed , receipt.Logs)
	}

	t.Logf("receipt for tx.  gas used: %d, block number: %d, status %d", receipt.GasUsed, receipt.BlockNumber, receipt.Status)

	waitForSomeBlocks()
}

func deployL2TestToken(t *testing.T, ctx context.Context, l1Address common.Address) common.Address {
	client, err := ethclient.Dial("http://localhost:8546")
    if err != nil {
        t.Fatalf("could not dial eth l1 %s", err)
    }

	privateKey, err := crypto.HexToECDSA(localnetPrivateKey)
    if err != nil {
        t.Fatal(err)
    }

	publicKey := privateKey.Public()
    publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
    if !ok {
        t.Fatal("error casting public key to ECDSA")
    }

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

    nonce, err := client.PendingNonceAt(ctx, fromAddress)
    if err != nil {
        t.Fatal(err)
    }

	gasPrice, err := client.SuggestGasPrice(ctx)
    if err != nil {
        t.Fatal(err)
    }

	auth , err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(901))
	if err != nil {
		t.Fatal(err)
	}
    auth.Nonce = big.NewInt(int64(nonce))
    auth.Value = big.NewInt(0)     // in wei
    auth.GasLimit = uint64(2000000) // in units
	auth.GasFeeCap = gasPrice

    address, tx, _, err := DeployOptimismMintableERC20(auth, client, common.Address(common.FromHex("0x4200000000000000000000000000000000000010")), l1Address, "TestToken", "$TT", 1)
    if err != nil {
        t.Fatal(err)
    }

	t.Logf("optimism mintable deployment tx %s", tx.Hash())

	waitForSomeBlocks()

	receipt, err := client.TransactionReceipt(ctx, tx.Hash())
	if err != nil {
		t.Fatal(err)
	}

	if receipt.Status == types.ReceiptStatusFailed {
		t.Fatalf("transaction failed: %v", receipt.Logs)
	}

    t.Log(address.Hex())
    t.Log(tx.Hash().Hex())

	return address
}

func bridgeERC20FromL1ToL2(t *testing.T, ctx context.Context, localTokenAddress common.Address, remoteTokenAddress common.Address, receiverAddress common.Address) {
	client, err := ethclient.Dial("http://localhost:8545")
    if err != nil {
        t.Fatalf("could not dial eth l1 %s", err)
    }

	l2Client, err := ethclient.Dial("http://localhost:8546")
	if err != nil {
		t.Fatal(err)
	}

	privateKey, err := crypto.HexToECDSA(localnetPrivateKey)
    if err != nil {
        t.Fatal(err)
    }

	bridge, err := NewL1StandardBridge(common.Address(common.FromHex("654fe8bC4F8Bf51f0CeC4567399aD7067E145C3F")), client)
	if err != nil {
		t.Fatal(err)
	}

	optimismMintableErc2, err := NewOptimismMintableERC20(remoteTokenAddress, l2Client)
	if err != nil {
		t.Fatal(err)
	}

	gasPrice, err := l2Client.SuggestGasPrice(ctx)
    if err != nil {
        t.Fatal(err)
    }

	nonce, err := l2Client.PendingNonceAt(ctx, receiverAddress)
    if err != nil {
        t.Fatal(err)
    }

	tx, err := optimismMintableErc2.OptimismMintableERC20Transactor.IncreaseAllowance(&bind.TransactOpts{
		From: receiverAddress,
		Value: big.NewInt(0),
		GasLimit: 10000000,
		GasPrice: gasPrice, 
		Nonce: big.NewInt(int64(nonce)), 
		Signer: func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
			privateKey, err := crypto.HexToECDSA(localnetPrivateKey)
			if err != nil {
				return nil, err
			}
			signedTx, err := types.SignTx(tx, types.NewCancunSigner(big.NewInt(901)), privateKey)
			if err != nil {
				return nil, err
			}

			return signedTx, nil
		},
	}, common.Address(common.FromHex("654fe8bC4F8Bf51f0CeC4567399aD7067E145C3F")), big.NewInt(10000))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("tx to increase allowance: %s", tx.Hash().Hex())

	waitForSomeBlocks()


	receipt, err := l2Client.TransactionReceipt(ctx, tx.Hash())
	if err != nil {
		t.Fatal(err)
	}

	if receipt.Status == types.ReceiptStatusFailed {
		t.Fatalf("receipt status is %d (failed), logs: %v",types.ReceiptStatusFailed , receipt.Logs)
	}


	gasPrice, err = client.SuggestGasPrice(ctx)
    if err != nil {
        t.Fatal(err)
    }

	nonce, err = client.PendingNonceAt(ctx, receiverAddress)
    if err != nil {
        t.Fatal(err)
    }

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))
	if err != nil {
		t.Fatal(err)
	}
    auth.Nonce = big.NewInt(int64(nonce))
    auth.Value = big.NewInt(0)     // in wei
    auth.GasLimit = uint64(3000000) // in units
    auth.GasFeeCap = gasPrice

	tx, err = bridge.L1StandardBridgeTransactor.BridgeERC20To(auth, localTokenAddress, remoteTokenAddress, receiverAddress, big.NewInt(100),0, []byte{} )
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("tx for bridge erc20 L1 -> L2: %s", tx.Hash().Hex())

		waitForSomeBlocks()
	
		receipt, err = client.TransactionReceipt(ctx, tx.Hash())
		if err != nil {
			t.Fatal(err)
		}
	
		if receipt.Status == types.ReceiptStatusFailed {
			t.Fatalf("receipt status is %d, gas used %d (failed), logs: %v",receipt.Status, receipt.GasUsed , receipt.Logs)
		}


	t.Logf("receipt for tx.  gas used: %d, block number: %d, status %d", receipt.GasUsed, receipt.BlockNumber, receipt.Status)

	waitForSomeBlocks()

	// Clayton: also check balance of ERC20 on l1

	balance, err := optimismMintableErc2.OptimismMintableERC20Caller.BalanceOf(nil, receiverAddress)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("the l2 erc20 balance is %d", balance)
}

func bridgeERC20FromL2ToL1(t *testing.T, ctx context.Context, l1Address common.Address, l2Address common.Address, receiverAddress common.Address) {
	client, err := ethclient.Dial("http://localhost:8545")
	if err != nil {
		t.Fatal(err)
	}
	
	l2Client, err := ethclient.Dial("http://localhost:8546")
	if err != nil {
		t.Fatal(err)
	}

	privateKey, err := crypto.HexToECDSA(localnetPrivateKey)
    if err != nil {
        t.Fatal(err)
    }

	bridge, err := NewL2StandardBridge(common.Address(common.FromHex("0x4200000000000000000000000000000000000010")), l2Client)
	if err != nil {
		t.Fatal(err)
	}

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
    auth.Value = big.NewInt(0)     // in wei
    auth.GasLimit = uint64(3000000) // in units
    auth.GasFeeCap = gasPrice

	tx, err := bridge.L2StandardBridgeTransactor.BridgeERC20To(auth, l2Address, l1Address, receiverAddress, big.NewInt(50),0, []byte{} )
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("tx for bridge erc20 L2 -> L1: %s", tx.Hash().Hex())

		waitForSomeBlocks()
	
		receipt, err := l2Client.TransactionReceipt(ctx, tx.Hash())
		if err != nil {
			t.Fatal(err)
		}
	
		if receipt.Status == types.ReceiptStatusFailed {
			t.Fatalf("receipt status is %d, gas used %d (failed), logs: %v",receipt.Status, receipt.GasUsed , receipt.Logs)
		}


	t.Logf("receipt for tx.  gas used: %d, block number: %d, status %d", receipt.GasUsed, receipt.BlockNumber, receipt.Status)

	testToken, err := NewTesttoken(l1Address, client)
	if err != nil {
		t.Fatal(err)
	}

	balance, err := testToken.BalanceOf(nil, receiverAddress)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("the balance is %d", balance)
}

func waitForSomeBlocks() {
	time.Sleep(12 * time.Second)
}