module github.com/hemilabs/heminetwork/e2e/monitor

go 1.23

toolchain go1.23.0

replace github.com/hemilabs/heminetwork => ../../

require (
	github.com/btcsuite/btcd v0.24.2
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
	github.com/gosuri/uilive v0.0.4
	github.com/hemilabs/heminetwork v0.1.0
	github.com/jedib0t/go-pretty/v6 v6.5.8
)

require (
	github.com/btcsuite/btcd/btcec/v2 v2.3.4 // indirect
	github.com/btcsuite/btcd/btcutil v1.1.5 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd // indirect
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/juju/loggo v1.0.0 // indirect
	github.com/mattn/go-isatty v0.0.0-20160806122752-66b8e73f3f5c // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	golang.org/x/crypto v0.22.0 // indirect
	golang.org/x/sys v0.23.0 // indirect
)
