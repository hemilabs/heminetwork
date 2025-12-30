# Copyright (c) 2024-2025 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

ARG OP_GETH_COMMIT=73dbd17c8d105ce2a3cc9dd1684b2ab261028408
ARG OPTIMISM_COMMIT=b1f96f2dbfad6a076fa3a1eb3d4854e0d68f18d8

# commit near tip on "master" (main) branch.  the most recent release is
# broken
ARG FOUNDRY_COMMIT=97fba0a51e335a174442b19d92b64df9d2ab72ab

FROM golang:1.25.5-trixie@sha256:8e8f9c84609b6005af0a4a8227cee53d6226aab1c6dcb22daf5aeeb8b05480e1 AS build_1
ARG OP_GETH_COMMIT
ARG OPTIMISM_COMMIT
ARG FOUNDRY_COMMIT

WORKDIR /git

RUN git clone https://github.com/hemilabs/op-geth
WORKDIR /git/op-geth
RUN git checkout $OP_GETH_COMMIT

RUN go run build/ci.go install -static ./cmd/geth

FROM golang:1.25.5-trixie@sha256:8e8f9c84609b6005af0a4a8227cee53d6226aab1c6dcb22daf5aeeb8b05480e1 AS build_2
ARG OP_GETH_COMMIT
ARG OPTIMISM_COMMIT
ARG FOUNDRY_COMMIT

# store the latest geth here, build with go 1.23
COPY --from=build_1 /git/op-geth/build/bin/geth /bin/geth

RUN apt-get update
RUN apt-get install -y jq nodejs npm netcat-openbsd yq

RUN npm install -g pnpm


RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="${PATH}:/root/.cargo/bin"

WORKDIR /git
RUN git clone https://github.com/casey/just
WORKDIR /git/just
RUN cargo install just

WORKDIR /git

RUN git clone https://github.com/foundry-rs/foundry.git

WORKDIR /git/foundry
RUN git checkout $FOUNDRY_COMMIT
RUN cargo build --release
RUN cp /git/foundry/target/release/forge /usr/bin/forge

WORKDIR /git


RUN curl -L https://foundry.paradigm.xyz | bash

RUN . /root/.bashrc

ENV PATH="${PATH}:/root/.foundry/bin"

RUN foundryup

RUN forge --help

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

WORKDIR /git/optimism

# as of now, we have the pop points address hard-coded as the rewards address
# for pop miners, this should change once we do TGE and mint HEMI
# we have no way to configure this AFAIK, so just replace the address in the 
# file so we reward to the GovernanceTokenAddr
# once this is changed back in optimism, remove this line
RUN sed -i 's/predeploys.PoPPointsAddr/predeploys.GovernanceTokenAddr/g' ./op-node/rollup/derive/pop_payout.go

WORKDIR /git/optimism/op-node
RUN just op-node

WORKDIR /git/optimism/op-batcher
RUN just op-batcher

WORKDIR /git/optimism/op-proposer
RUN just op-proposer

WORKDIR /git/optimism/op-conductor
RUN just op-conductor

WORKDIR /git/optimism
