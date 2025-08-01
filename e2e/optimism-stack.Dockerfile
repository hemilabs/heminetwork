# Copyright (c) 2024-2025 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

ARG OP_GETH_COMMIT=ed68446430a8b726f1dceceb0e85cdc5f10f248e
ARG OPTIMISM_COMMIT=7bb2a14f63d01bcb4de3ab3165b007fd85a6b1f9

FROM golang:1.24.4-bookworm@sha256:c83619bb18b0207412fffdaf310f57ee3dd02f586ac7a5b44b9c36a29a9d5122 AS build_1

WORKDIR /git

RUN git clone https://github.com/hemilabs/op-geth
WORKDIR /git/op-geth
RUN git checkout $OP_GETH_COMMIT

RUN go run build/ci.go install -static ./cmd/geth

FROM golang:1.24.4-bookworm@sha256:c83619bb18b0207412fffdaf310f57ee3dd02f586ac7a5b44b9c36a29a9d5122 AS build_2

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

WORKDIR /git/optimism/op-deployer
RUN just build

WORKDIR /git/optimism
