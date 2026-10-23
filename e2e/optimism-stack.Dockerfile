# Copyright (c) 2024-2025 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

# increment me to break the cache: 4

# hemilabs/op-geth hemi and hemilabs/optimism hemi with the Glamsterdam
# changes merged (op-geth PR #111, optimism PR #53): the L2 keeps running
# its current forks and only learns to follow an L1 that has activated
# Glamsterdam.  The optimism commit pins exactly this op-geth commit in its
# go.mod, so op-node, op-batcher and op-proposer are linked against the
# same code that runs as the L2 execution client.
ARG OP_GETH_COMMIT=c1771608d7edd4224b05e9d224056984f87c1f5d
ARG OPTIMISM_COMMIT=37b5d86d87c51b5140cfee41a2ce15c1ca4414eb

# hemilabs/optimism with Hemi's hVM ported into op-reth (branch op-reth-hemi,
# based on 9892fe9b7ebe4b09cec4eae34f7874eeac512162).  op-reth runs as the L2
# execution client; op-node, op-batcher and op-proposer stay on
# OPTIMISM_COMMIT.
ARG OP_RETH_COMMIT=37b5d86d87c51b5140cfee41a2ce15c1ca4414eb

# commit near tip on "master" (main) branch.  the most recent release is
# broken
ARG FOUNDRY_COMMIT=4072e48705af9d93e3c0f6e29e93b5e9a40caed8

FROM golang:1.26.5-trixie@sha256:4ee9ffa999b4583ce281939cdff828763083610292f252279a0cee77473bd9a7 AS foundry_build
ARG FOUNDRY_COMMIT

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="${PATH}:/root/.cargo/bin"

WORKDIR /git
RUN git clone https://github.com/foundry-rs/foundry.git

WORKDIR /git/foundry
RUN git checkout $FOUNDRY_COMMIT
RUN cargo build --release --package forge

FROM golang:1.26.5-trixie@sha256:4ee9ffa999b4583ce281939cdff828763083610292f252279a0cee77473bd9a7 AS just_build

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="${PATH}:/root/.cargo/bin"

WORKDIR /git
RUN git clone https://github.com/casey/just
WORKDIR /git/just
# 1.46.0
RUN git checkout f028de5b258a0cc4696b9dea729cc7d4d5828baa
RUN cargo install just

# op-reth with Hemi hVM.  The hVM Go bridge (rust/op-reth/crates/hemi/hvm-go)
# is compiled by cargo, so this stage needs both Go and Rust.
FROM golang:1.26.5-trixie@sha256:4ee9ffa999b4583ce281939cdff828763083610292f252279a0cee77473bd9a7 AS opreth_build
ARG OP_RETH_COMMIT

RUN apt-get update && apt-get install -y --no-install-recommends clang libclang-dev pkg-config
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain none --profile minimal
ENV PATH="${PATH}:/root/.cargo/bin"

WORKDIR /git
RUN git clone https://github.com/hemilabs/optimism
WORKDIR /git/optimism
RUN git checkout $OP_RETH_COMMIT
# op-reth's chainspec embeds the superchain registry
RUN git submodule update --init superchain-registry

WORKDIR /git/optimism/rust
RUN cargo build --profile release -p op-reth --bin op-reth
RUN ./target/release/op-reth --version

FROM golang:1.26.5-trixie@sha256:4ee9ffa999b4583ce281939cdff828763083610292f252279a0cee77473bd9a7 AS build_1
ARG OP_GETH_COMMIT
ARG OPTIMISM_COMMIT
ARG FOUNDRY_COMMIT

WORKDIR /git

RUN git clone https://github.com/hemilabs/op-geth
WORKDIR /git/op-geth
RUN git checkout $OP_GETH_COMMIT

RUN go run build/ci.go install -static ./cmd/geth

FROM golang:1.26.5-trixie@sha256:4ee9ffa999b4583ce281939cdff828763083610292f252279a0cee77473bd9a7 AS build_2
ARG OP_GETH_COMMIT
ARG OPTIMISM_COMMIT

# store the latest geth here, build with go 1.23.  The L2 runs op-reth; geth
# stays for "geth attach" used by e2e/monitor against op-reth's IPC endpoint.
COPY --from=build_1 /git/op-geth/build/bin/geth /bin/geth
COPY --from=opreth_build /git/optimism/rust/target/release/op-reth /bin/op-reth

RUN apt-get update
RUN apt-get install -y jq yq xxd zip

WORKDIR /git
COPY --from=build_1 /git/op-geth /git/op-geth
WORKDIR /git
RUN git clone https://github.com/hemilabs/optimism
WORKDIR /git/optimism
RUN git fetch origin
RUN git checkout $OPTIMISM_COMMIT

WORKDIR /git/optimism
RUN go mod tidy

RUN git submodule update --init --recursive

# op-core/superchain embeds superchain-configs.zip, which is gitignored and
# generated from the superchain-registry submodule.  The generator needs
# mikefarah's yq v4 (the apt "yq" package is a different tool), installed
# into its own directory so it doesn't shadow the apt one.
RUN GOBIN=/opt/yq4 go install github.com/mikefarah/yq/v4@v4.44.3
RUN PATH=/opt/yq4:$PATH bash op-core/superchain/sync-superchain.sh

WORKDIR /git/optimism

# as of now, we have the pop points address hard-coded as the rewards address
# for pop miners, this should change once we do TGE and mint HEMI
# we have no way to configure this AFAIK, so just replace the address in the 
# file so we reward to the GovernanceTokenAddr
# once this is changed back in optimism, remove this line
RUN sed -i 's/predeploys.PoPPointsAddr/predeploys.GovernanceTokenAddr/g' ./op-node/rollup/derive/pop_payout.go

COPY --from=just_build /root/.cargo/bin/just /usr/bin/just

WORKDIR /git/optimism/op-node
RUN just op-node

WORKDIR /git/optimism/op-batcher
RUN just op-batcher

WORKDIR /git/optimism/op-proposer
RUN just op-proposer


COPY --from=foundry_build /git/foundry/target/release/forge /usr/bin/forge

RUN forge --help

WORKDIR /git/optimism/packages/contracts-bedrock
RUN forge install

WORKDIR /git/optimism

RUN git reset --hard
