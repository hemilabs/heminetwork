# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

FROM golang:1.23.4-bookworm@sha256:ef30001eeadd12890c7737c26f3be5b3a8479ccdcdc553b999c84879875a27ce AS build_1

WORKDIR /git

ARG OP_GETH_CACHE_BREAK=12F2
RUN git clone https://github.com/hemilabs/op-geth
WORKDIR /git/op-geth
RUN git checkout 2de5bf59a919697f46d0ded4356d80f4febe37fb

WORKDIR /git/op-geth

RUN make

RUN go build -o /tmp ./...

FROM golang:1.22.6-bookworm@sha256:f020456572fc292e9627b3fb435c6de5dfb8020fbcef1fd7b65dd092c0ac56bb AS build_2

# store the latest geth here, build with go 1.23
COPY --from=build_1 /tmp/geth /bin/geth

RUN apt-get update

RUN apt-get install -y jq nodejs npm


RUN curl -L https://foundry.paradigm.xyz | bash

RUN . /root/.bashrc

ENV PATH="${PATH}:/root/.foundry/bin"

RUN foundryup

RUN npm install -g pnpm

WORKDIR /git
RUN git clone https://github.com/hemilabs/optimism
WORKDIR /git/optimism
RUN git checkout 0e70403b3e15d056e187664cf1a591cb1698ebdf

# as of now, we have the pop points address hard-coded as the rewards address
# for pop miners, this should change once we do TGE and mint HEMI
# we have no way to configure this AFAIK, so just replace the address in the 
# file so we reward to the GovernanceTokenAddr
# once this is changed back in optimism, remove this line
RUN sed -i 's/predeploys.PoPPointsAddr/predeploys.GovernanceTokenAddr/g' ./op-node/rollup/derive/pop_payout.go

RUN git submodule update --init --recursive
RUN pnpm install
RUN pnpm install:abigen
WORKDIR /git/optimism/packages/contracts-bedrock
RUN sed -e '/build_info/d' -i ./foundry.toml
WORKDIR /git/optimism
RUN go mod tidy
WORKDIR /git/optimism/op-bindings
RUN go mod tidy
WORKDIR /git/optimism
RUN make op-bindings op-node

RUN pnpm build

WORKDIR /git/optimism/packages/contracts-bedrock
RUN forge install
RUN forge build

WORKDIR /git/optimism

RUN make devnet-allocs

RUN apt-get install -y netcat-openbsd