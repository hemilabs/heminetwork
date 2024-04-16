# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

FROM golang:1.22

RUN apt-get update

RUN apt-get install -y nodejs npm jq

RUN npm install -g pnpm

WORKDIR /git

RUN curl -L https://foundry.paradigm.xyz | bash

RUN . /root/.bashrc

ENV PATH="${PATH}:/root/.foundry/bin"

RUN foundryup


ARG OP_GETH_CACHE_BREAK=1
RUN git clone https://github.com/hemilabs/op-geth
WORKDIR /git/op-geth
RUN git checkout hemi

WORKDIR /git

ARG OPTIMISM_CACHE_BREAK=1
RUN git clone https://github.com/hemilabs/optimism
WORKDIR /git/optimism
RUN git checkout hemi

WORKDIR /git/op-geth

RUN make
RUN go install ./...
RUN abigen --version

WORKDIR /git/optimism

RUN git submodule update --init --recursive
RUN pnpm install
WORKDIR /git/optimism/packages/contracts-bedrock
RUN sed -e '/build_info/d' -i ./foundry.toml
WORKDIR /git/optimism
RUN make op-bindings op-node op-batcher op-proposer
RUN pnpm build

WORKDIR /git/optimism/packages/contracts-bedrock
RUN forge install
RUN forge build

WORKDIR /git/optimism