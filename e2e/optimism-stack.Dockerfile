# Copyright (c) 2024-2025 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

FROM golang:1.23.4-bookworm@sha256:ef30001eeadd12890c7737c26f3be5b3a8479ccdcdc553b999c84879875a27ce AS build_1

WORKDIR /git

ARG OP_GETH_CACHE_BREAK=12F2
RUN git clone https://github.com/hemilabs/op-geth
WORKDIR /git/op-geth
RUN git checkout 59242a8f35fc76869a49c9c09fe98383a72d0046

RUN go run build/ci.go install -static ./cmd/geth

FROM golang:1.24.2-bookworm@sha256:00eccd446e023d3cd9566c25a6e6a02b90db3e1e0bbe26a48fc29cd96e800901 AS build_2

# store the latest geth here, build with go 1.23
COPY --from=build_1 /git/op-geth/build/bin/geth /bin/geth

RUN apt-get update
RUN apt-get install -y jq nodejs npm netcat-openbsd

RUN npm install -g pnpm

WORKDIR /git
COPY --from=build_1 /git/op-geth /git/op-geth
WORKDIR /git
RUN git clone https://github.com/hemilabs/optimism
WORKDIR /git/optimism
RUN git checkout 789fca1eaf83ed5a4cca2ba8c3fb433d33c65c70

WORKDIR /git/optimism
RUN go mod tidy

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="${PATH}:/root/.cargo/bin"

WORKDIR /git
RUN git clone https://github.com/casey/just
WORKDIR /git/just
RUN cargo install just

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