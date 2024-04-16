# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

FROM golang@sha256:450e3822c7a135e1463cd83e51c8e2eb03b86a02113c89424e6f0f8344bb4168

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
RUN git checkout a012302a04f050d09c11a8fd5deb630ab7a376ad

WORKDIR /git

ARG OPTIMISM_CACHE_BREAK=1
RUN git clone https://github.com/hemilabs/optimism
WORKDIR /git/optimism
RUN git checkout 50a6efe980e90751b47e2cb5a8e1146b16320959

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
