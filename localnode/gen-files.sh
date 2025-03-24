#!/bin/sh
# Copyright (c) 2025 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

set -e

if [[ $# != 2 ]]; then
	echo "usage ./gen-files.sh NETWORK SYNCMODE"
	exit
fi

NET=$1
MODE=$2

if [[ "$NET" != "mainnet" && "$NET" != "testnet" ]]; then
	echo "Network must be 'mainnet' or 'testnet'"
	exit
fi

if [[ "$MODE" != "snap" && "$MODE" != "archive" ]]; then
	echo "Sync Mode must be 'snap' or 'archive'"
	exit
fi

echo "Setup for $NET $MODE"

ENTRYFILE=""
GENESIS=""
ID=""
TBCNET=""
HVMGENESIS=""
HVMGENESISHEADER=""
OVERRIDES=""
BOOTNODES=""

if [[ $NET == "mainnet" ]]; then
	ENTRYFILE="mainnet-entrypointl2.sh"
	GENEIS="genesis.json"
	ID=43111
	TBCNET="mainnet"
	OVERRIDES="--override.ecotone=1725868497 \\
	--override.canyon=1725868497 \\
	--override.cancun=1725868497 \\
	--override.hvm0=1739286001 \\"
	HVMGENESIS=883092
	HVMGENESISHEADER="0000003efaaa2ba65de684c512bb67ef115298d1d16bcb49b16c02000000000000000000ed31a56788c4488afc4ee69e0791ad6aeeb9ea05f069e0fdde6159068765ad3f4128a96726770217e7f41c86"
	BOOTNODES="--bootnodes=enode://f591af0f0c25b794f008254262da082df23282f946c397128f4ca13f53842a09867cff8d8b68a39fddcfee885abc5b60ba21b98f88dcf7983a834c3ebc5b0254@34.13.162.152:30303,enode://e7970a29d89f8b158371a8d4aca909ee8c1c759e711547b797a6a6f01513c1e7c85121dd2600397ca20cebf3cea21025001be7c0f577b496caf32ea0433a1cfd@34.90.21.246:30303,enode://8eedf09af5bd8bb14479dfeabf522e6d80ac624d272d5ea87779121960c3f8fe4f16e6f1d344e92369a7e855e9e96bc003c8a31f82b73305b74684edc72ac90e@34.13.171.139:30303,enode://ebb5c1de8e66c27e57ddafbf9ef8d9da81e25dc68a5ff9d901a45e970671dd93f46d7b19b33624c23813281c924d27b4f8865d2c2daec858561a69706b04be7e@34.91.216.121:30303,enode://0a9d3aaadbc403d9034fc587836969ae14ca096a86bef7330f9c4da7a68113f07e70b9bc543b966ff545f0a4c5408d498b6105d0f37fd1f173599d6ac2baefd8@34.141.148.19:30303"
fi

if [[ $NET == "testnet" ]]; then
	ENTRYFILE="entrypointl2.sh"
	GENEIS="testnet-genesis.json"
	ID=743111
	TBCNET="testnet3"
	OVERRIDES="--override.ecotone=1715865630 \\
	--override.canyon=1715865630 \\
	--override.cancun=1715865630 \\
	--override.hvm0=1733930401 \\"
	HVMGENESIS=3522419
	HVMGENESISHEADER="00c05732cdc3e0d654efe86351f0cbfc6c79325e9f9fa7886a39b552f5c4d90700000000dae4079485e26f1f77425b84a13760038a352d07a0fef92b5188bd04c2999162afca58679121011962b9d0a5"
	BOOTNODES="--nodiscover"
fi

SYNCMODE=""
OPSYNCMODE=""
if [[ $MODE == "snap" ]]; then
	SYNCMODE="snap"
	OPSYNCMODE="execution-layer"
fi
if [[ $MODE == "archive" ]]; then
	SYNCMODE="full"
	OPSYNCMODE="concensus-layer"
fi

ENTRYFILECONTENTS="#!/bin/sh
# Copyright (c) 2024-2025 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

set -xe

if [ -d \"/tmp/datadir/geth\" ]; then
  echo \"geth data dir exists, skipping genesis.\"
else
	geth init --datadir /tmp/datadir/geth /tmp/genesis.json
fi

geth \\
	--config=/tmp/l2-config.toml \\
	--http \\
	--http.corsdomain=* \\
	--http.vhosts=* \\
	--http.addr=0.0.0.0 \\
	--http.api=web3,eth,txpool,net \\
	--http.port=18546 \\
	--ws \\
	--ws.rpcprefix=/ \\
	--ws.addr=0.0.0.0 \\
	--ws.port=28546 \\
	--ws.origins=* \\
	--ws.api=eth,txpool,net \\
	--syncmode=$SYNCMODE \\
	--gcmode=archive \\
	--maxpeers=100 \\
	--networkid=$ID \\
	--authrpc.vhosts=* \\
	--authrpc.addr=0.0.0.0 \\
	--authrpc.port=8551 \\
	--authrpc.jwtsecret=/tmp/jwt/jwt.hex \\
	--rollup.disabletxpoolgossip=false \\
	--datadir=/tmp/datadir/geth \\
	$OVERRIDES
	--tbc.leveldbhome=/tbcdata/data \\
    --hvm.headerdatadir=/tbcdata/headers \\
	--tbc.network=$TBCNET \\
    --hvm.genesisheader=$HVMGENESISHEADER \\
    --hvm.genesisheight=$HVMGENESIS \\
	$BOOTNODES"

echo "$ENTRYFILECONTENTS" > "$ENTRYFILE"
echo "OPSYNCMODE=$OPSYNCMODE" > .env
