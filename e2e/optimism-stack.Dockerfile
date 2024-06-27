# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

FROM golang:1.22.2-bookworm@sha256:b03f3ba515751657c75475b20941fef47341fccb3341c3c0b64283ff15d3fb46

RUN apt-get update

RUN apt-get install -y nodejs npm jq

RUN npm install -g pnpm

WORKDIR /git

RUN curl -L https://foundry.paradigm.xyz | bash

RUN . /root/.bashrc

ENV PATH="${PATH}:/root/.foundry/bin"

RUN foundryup

ARG OP_GETH_CACHE_BREAK=3
RUN git clone https://github.com/hemilabs/op-geth
WORKDIR /git/op-geth
RUN git checkout f07e5b67e67fdf5ede943d2ae8eebd6eae175154

WORKDIR /git

ARG OPTIMISM_CACHE_BREAK=2
RUN git clone https://github.com/hemilabs/optimism
WORKDIR /git/optimism
RUN git checkout 3443a621aefd8d4a669683d7988407062383634c

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
RUN pnpm build

WORKDIR /git/optimism/packages/contracts-bedrock
RUN forge install
RUN forge build

WORKDIR /git/optimism

RUN make devnet-allocs