# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

FROM golang:1.22.6-bookworm@sha256:f020456572fc292e9627b3fb435c6de5dfb8020fbcef1fd7b65dd092c0ac56bb

RUN apt-get update

RUN apt-get install -y nodejs npm jq

RUN npm install -g pnpm

WORKDIR /git

RUN curl -L https://foundry.paradigm.xyz | bash

RUN . /root/.bashrc

ENV PATH="${PATH}:/root/.foundry/bin"

RUN foundryup

ARG OP_GETH_CACHE_BREAK=12F
RUN git clone https://github.com/hemilabs/op-geth
WORKDIR /git/op-geth
RUN git checkout 4c818bcfa33873c808cfb697ea1b713748338117

WORKDIR /git

ARG OPTIMISM_CACHE_BREAK=1
RUN git clone https://github.com/hemilabs/optimism
WORKDIR /git/optimism
RUN git checkout adf68923d2b278641e405dd5bfc4f53196d58bbe

WORKDIR /git/op-geth

RUN make
RUN go install ./...

WORKDIR /git/optimism

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
RUN make op-bindings op-node op-batcher op-proposer
RUN make -C ./op-conductor op-conductor

RUN pnpm build

WORKDIR /git/optimism/packages/contracts-bedrock
RUN forge install
RUN forge build

WORKDIR /git/optimism

RUN make devnet-allocs
