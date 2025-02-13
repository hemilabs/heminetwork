package tbcgozer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/davecgh/go-spew/spew"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/gozer"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/vinzclortho"
	"github.com/hemilabs/heminetwork/service/tbc"
	"github.com/juju/loggo"
)

func TestTBCWallet(t *testing.T) {

	mnemonic := "dinosaur banner version pistol need area dream champion kiss thank business shrug explain intact puzzle"
	w, err := vinzclortho.VinzClorthoNew(&chaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}
	err = w.Unlock(mnemonic)
	if err != nil {
		t.Fatal(err)
	}

	ek, err := w.DeriveHD(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	addr, pub, err := vinzclortho.AddressAndPublicFromExtended(&chaincfg.TestNet3Params, ek)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%v", addr)
	t.Logf("%v", pub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect tbc service
	tbcCfg := &tbc.Config{
		AutoIndex:            false,
		BlockCacheSize:       "10mb",
		BlockheaderCacheSize: "1mb",
		BlockSanity:          false,
		LevelDBHome:          t.TempDir(),
		// LogLevel:                "tbcd=TRACE:tbc=TRACE:level=DEBUG",
		MaxCachedTxs:            1000, // XXX
		Network:                 "localnet",
		PrometheusListenAddress: "",
		Seeds:                   []string{"127.0.0.1:18444"},
		ListenAddress:           "localhost:8881",
	}
	_ = loggo.ConfigureLoggers(tbcCfg.LogLevel)
	s, err := tbc.NewServer(tbcCfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()

	time.Sleep(1 * time.Second)

	b, err := TBCGozerNew(ctx1, "http://localhost:8881/v1/ws")
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * time.Second)

	feeEstimates, err := b.FeeEstimates(ctx)
	if err != nil {
		t.Fatal(err)
	}

	feeEstimate, err := gozer.FeeByConfirmations(6, feeEstimates)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(spew.Sdump(feeEstimate))

	utxos, err := b.UtxosByAddress(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("balance %v: %v", addr, gozer.BalanceFromUtxos(utxos))
}
