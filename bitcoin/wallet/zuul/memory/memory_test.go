package memory

import (
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/go-test/deep"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/vinzclortho"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/zuul"
)

type keyInfo struct {
	ek   *hdkeychain.ExtendedKey
	priv *btcec.PrivateKey
	addr *btcutil.Address
	nk   *zuul.NamedKey
}

func keyInfoFromXprevs(xprevs []string) ([]keyInfo, error) {

	keyInfoList := make([]keyInfo, 0)

	for _, xp := range xprevs {

		ek, err := hdkeychain.NewKeyFromString(xp)
		if err != nil {
			return nil, err
		}

		addr, _, err := vinzclortho.AddressAndPublicFromExtended(&chaincfg.TestNet3Params, ek)
		if err != nil {
			return nil, err
		}

		nk := zuul.NamedKey{
			Name:       "pk",
			Account:    0,
			Child:      0,
			HD:         true,
			PrivateKey: ek,
		}

		expectedPriv, err := ek.ECPrivKey()
		if err != nil {
			return nil, err
		}

		ki := keyInfo{
			ek:   ek,
			addr: &addr,
			priv: expectedPriv,
			nk:   &nk,
		}

		keyInfoList = append(keyInfoList, ki)
	}

	return keyInfoList, nil
}

func TestMemoryZuul(t *testing.T) {

	xprivList := []string{
		"xprv9s21ZrQH143K3ScRXhao5KSyozmph3B3Bop8C1iqnyCgXSpUDE8oYDsz2hDp897fwwqdsTFYKNQVg5jn5nLH2QkZWeF9MZeMwkbkN8uAafy",
		"xprv9s21ZrQH143K2pxg5xps4opEVnydz9MexEvEQMGCdVpaYyVxMsfSLHwh4QRgxZQTh6TkdhZvi1339vKUoDZz5XinoqKxrVKhmrjVMdAnChT",
		"xprv9s21ZrQH143K44uicYsxgM8kSYF96MykdxgTm66MVTChY7epoVBEfdDMzZwUo6WcyzvvkuautC5gRN2LkQEqpME1uVH1unXoYQiMao4734N",
		"xprv9s21ZrQH143K2MreeuJfJ2aV4PgzZZ4jNq4czYdXTzZvhfkHoBdetWq7mtMiM8WSKqxf8AKKr16mXvfLjLZxbrShfiE51n4DqCDGHKezcYC",
	}

	type kiCmd struct {
		cmd      string   // type of 'put' or 'purge'
		privKeys []string // list of privkeys to run the command with
		fail     bool     // expected to fail
	}

	type testTableItem struct {
		name        string
		cmds        []kiCmd  // commands to run during test
		expectedIn  []string // expected to be in zuul at end of test
		expectedOut []string // expected to NOT be in zuul at end of test
	}

	testTable := []testTableItem{
		{
			name:        "testEmpty",
			expectedOut: xprivList,
		},
		{
			name:        "testInsert",
			cmds:        []kiCmd{{cmd: "put", privKeys: xprivList}},
			expectedIn:  xprivList,
			expectedOut: nil,
		},
		{
			name: "testInsertDup",
			cmds: []kiCmd{{cmd: "put", privKeys: xprivList},
				{cmd: "put", privKeys: xprivList, fail: true}},
			expectedIn: xprivList,
		},
		{
			name: "testPurge",
			cmds: []kiCmd{{cmd: "put", privKeys: xprivList},
				{cmd: "purge", privKeys: xprivList}},
			expectedOut: xprivList,
		},
		{
			name:        "testPurgeInvalid",
			cmds:        []kiCmd{{cmd: "purge", privKeys: xprivList, fail: true}},
			expectedOut: xprivList,
		},
		{
			name:        "testMixedInsert",
			cmds:        []kiCmd{{cmd: "put", privKeys: xprivList[:2]}},
			expectedOut: xprivList[2:],
			expectedIn:  xprivList[:2],
		},
		{
			name: "testMixedPurge",
			cmds: []kiCmd{{cmd: "put", privKeys: xprivList},
				{cmd: "purge", privKeys: xprivList[:2]}},
			expectedOut: xprivList[:2],
			expectedIn:  xprivList[2:],
		},
	}

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {

			m, err := MemoryNew(&chaincfg.TestNet3Params)
			if err != nil {
				t.Fatal(err)
			}

			// run each of the commands
			for _, command := range tti.cmds {
				switch command.cmd {
				case "put":
					privKeys, err := keyInfoFromXprevs(command.privKeys)
					if err != nil {
						t.Fatal(err)
					}
					for _, ki := range privKeys {
						err = m.Put(ki.nk)
						if !command.fail {
							if err != nil {
								t.Fatal(err)
							}
						} else {
							if err == nil || !errors.Is(err, zuul.ErrKeyExists) {
								t.Fatalf("expected '%v' error, got '%v'", zuul.ErrKeyExists, err)
							}
						}
					}
				case "purge":

					privKeys, err := keyInfoFromXprevs(command.privKeys)
					if err != nil {
						t.Fatal(err)
					}
					for _, ki := range privKeys {
						err = m.Purge(*(ki.addr))
						if !command.fail {
							if err != nil {
								t.Fatal(err)
							}
						} else {
							if err == nil || !errors.Is(err, zuul.ErrKeyDoesntExist) {
								t.Fatalf("expected '%v' error, got '%v'", zuul.ErrKeyDoesntExist, err)
							}
						}
					}
				default:
					t.Fatalf("unknown command...")
				}
			}

			// check if keys in expectedIn are in zuul
			expectedIn, err := keyInfoFromXprevs(tti.expectedIn)
			if err != nil {
				t.Fatal(err)
			}
			for _, ki := range expectedIn {

				nk, err := m.Get(*ki.addr)
				if err != nil {
					t.Fatal(err)
				}
				if diff := deep.Equal(ki.nk, nk); len(diff) > 0 {
					t.Fatalf("unexpected error diff: %s", diff)
				}

				priv, ok, err := m.LookupByAddr(*ki.addr)
				if err != nil {
					t.Fatal(err)
				}
				if !ok {
					t.Fatalf("Expected %v on lookup, got %v", true, ok)
				}
				if diff := deep.Equal(ki.priv, priv); len(diff) > 0 {
					t.Fatalf("unexpected error diff: %s", diff)

				}
			}

			// check if keys in expectedOut are NOT in zuul
			expectedOut, err := keyInfoFromXprevs(tti.expectedOut)
			if err != nil {
				t.Fatal(err)
			}
			for _, ki := range expectedOut {

				_, err = m.Get(*ki.addr)
				if err == nil || !errors.Is(err, zuul.ErrKeyDoesntExist) {
					t.Fatalf("expected '%v' error, got '%v'", zuul.ErrKeyDoesntExist, err)
				}
				_, _, err = m.LookupByAddr(*ki.addr)
				if err == nil || !errors.Is(err, zuul.ErrKeyDoesntExist) {
					t.Fatalf("expected '%v' error, got '%v'", zuul.ErrKeyDoesntExist, err)
				}

			}
		})
	}
}
