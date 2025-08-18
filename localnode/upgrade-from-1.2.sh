#! /bin/bash


set -ex

IMPL_SALT="$(date +%s)" 

DEPLOYMENT_CONTEXT=hemi-testnet 

PRIVATE_KEY=0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6

RPC_URL='http://172.17.0.1:9988'


# upgrade to 1.3

git fetch origin

git checkout op-contracts/v1.3.0-rc.1

git submodule update --init --recursive

IMPL_SALT=$IMPL_SALT DEPLOYMENT_CONTEXT=$DEPLOYMENT_CONTEXT forge script scripts/Deploy.s.sol:Deploy --non-interactive --private-key=$PRIVATE_KEY  --rpc-url $RPC_URL --broadcast

# upgrade to 1.8 / holocene

git fetch origin

git checkout clayton/op-contracts/v1.8.0-rc.4
git log -1
exit 0

git submodule update --init --recursive

cp ~/other/heminetwork/localnode/hemi-testnet.env ./scripts/upgrades/holocene/.env

(cd ./scripts/upgrades/holocene ; just build-image)

(cd ./scripts/upgrades/holocene ; just run ~/other/heminetwork/localnode/hemi-testnet-deploy-config.json)