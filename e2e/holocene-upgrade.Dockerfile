FROM docker:28-rc@sha256:b0016f62aac43cd8d6cdeeb2b5ca7f5b3594e53d52a57ab9496c7edabfc1855e

RUN apk add curl just bash shadow

WORKDIR /git

RUN chsh -s /bin/bash root

RUN curl -L https://foundry.paradigm.xyz | bash

RUN . /root/.bashrc

ENV PATH="${PATH}:/root/.foundry/bin"

RUN foundryup

RUN chsh -s /bin/bash root

RUN curl -L https://foundry.paradigm.xyz | bash
 
RUN . /root/.bashrc
 
ENV PATH="${PATH}:/root/.foundry/bin"
 
RUN foundryup

WORKDIR /git

RUN git clone --branch clayton/op-contracts/v1.8.0-rc.4 --depth 1 https://github.com/hemilabs/optimism.git

WORKDIR /git/optimism/packages/contracts-bedrock/scripts/upgrades/holocene

RUN cp .env.example .env 
