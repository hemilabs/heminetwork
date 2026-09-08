FROM golang:1.27.1-alpine3.24@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125

WORKDIR /geth

RUN git clone https://github.com/ethereum/go-ethereum

WORKDIR /geth/go-ethereum

RUN git checkout aa1f2fcf512988eb8890d9352e601b898d6fdb2c

RUN make geth

RUN geth --version

ENTRYPOINT geth


