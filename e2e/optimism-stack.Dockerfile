# Copyright (c) 2024-2025 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

# increment me to break the cache: 2

ARG OP_GETH_COMMIT=e92aa4e51692bcc1bd5bceb16b990f19d610cad4
ARG OPTIMISM_COMMIT=c5af0b9241e5c882eda7bbe5fe3503464783285b

# commit near tip on "master" (main) branch.  the most recent release is
# broken
ARG FOUNDRY_COMMIT=97fba0a51e335a174442b19d92b64df9d2ab72ab

FROM golang:1.25.6-trixie@sha256:fb4b74a39c7318d53539ebda43ccd3ecba6e447a78591889c0efc0a7235ea8b3 AS foundry_build
ARG FOUNDRY_COMMIT

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="${PATH}:/root/.cargo/bin"

WORKDIR /git
RUN git clone https://github.com/foundry-rs/foundry.git

WORKDIR /git/foundry
RUN git checkout $FOUNDRY_COMMIT
RUN cargo build --package forge

FROM golang:1.25.6-trixie@sha256:fb4b74a39c7318d53539ebda43ccd3ecba6e447a78591889c0efc0a7235ea8b3 AS just_build

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="${PATH}:/root/.cargo/bin"

WORKDIR /git
RUN git clone https://github.com/casey/just
WORKDIR /git/just
# 1.46.0
RUN git checkout f028de5b258a0cc4696b9dea729cc7d4d5828baa
RUN cargo install just

FROM golang:1.25.6-trixie@sha256:fb4b74a39c7318d53539ebda43ccd3ecba6e447a78591889c0efc0a7235ea8b3 AS build_1
ARG OP_GETH_COMMIT
ARG OPTIMISM_COMMIT
ARG FOUNDRY_COMMIT

WORKDIR /git

RUN git clone https://github.com/hemilabs/op-geth
WORKDIR /git/op-geth
RUN git checkout $OP_GETH_COMMIT

RUN go run build/ci.go install -static ./cmd/geth

FROM golang:1.25.6-trixie@sha256:fb4b74a39c7318d53539ebda43ccd3ecba6e447a78591889c0efc0a7235ea8b3 AS build_2
ARG OP_GETH_COMMIT
ARG OPTIMISM_COMMIT

# store the latest geth here, build with go 1.23
COPY --from=build_1 /git/op-geth/build/bin/geth /bin/geth

RUN apt-get update
RUN apt-get install -y jq yq

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

COPY --from=just_build /root/.cargo/bin/just /usr/bin/just

WORKDIR /git/optimism/op-node
RUN just op-node

WORKDIR /git/optimism/op-batcher
RUN just op-batcher

WORKDIR /git/optimism/op-proposer
RUN just op-proposer


COPY --from=foundry_build /git/foundry/target/debug/forge /usr/bin/forge

RUN forge --help

WORKDIR /git/optimism

RUN git reset --hard
