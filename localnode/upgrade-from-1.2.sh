#! /bin/bash


set -ex

IMPL_SALT=testsalt

DEPLOYMENT_CONTEXT=hemi-testnet 

PRIVATE_KEY=0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6

RPC_URL='http://172.17.0.1:9988'


# upgrade to 1.3

# git fetch origin

# git checkout -f op-contracts/v1.3.0-rc.1

# git submodule update --init --recursive

# IMPL_SALT=$IMPL_SALT DEPLOYMENT_CONTEXT=$DEPLOYMENT_CONTEXT forge script scripts/Deploy.s.sol:Deploy --non-interactive --private-key=$PRIVATE_KEY  --rpc-url $RPC_URL --broadcast

# upgrade to 1.8 / holocene

git fetch op

git checkout -f op-contracts/v1.8.0-rc.4

git submodule update --init --recursive

# cp ~/other/heminetwork/localnode/hemi-testnet.env ./scripts/upgrades/holocene/.env

# (cd ./scripts/upgrades/holocene ; just build-image)

# (cd ./scripts/upgrades/holocene ; just run ~/other/heminetwork/localnode/hemi-testnet-deploy-config.json)

# # Clayton note: pin
# git checkout origin/hemi

# git submodule update --init --recursive

(cd ./../../op-deployer ; just build)

./../../op-deployer/bin/op-deployer bootstrap opcm \
    --l1-rpc-url http://localhost:9988 \
    --private-key "$PRIVATE_KEY" \
    --artifacts-locator "file://$(pwd)/forge-artifacts" > ./opcm-output.json

echo "the output is"

tail -n 15 ./opcm-output.json

cat >tmp-config.json <<EOL
{
  "prank": "0xc43ED1E8D70d0e5801514833fAD3D93Ba16Da4Aa",
  "opcm": "$(tail -n 15 ./opcm-output.json | jq -r '.OpcmProxy')",
  "chainConfigs": [
    {
      "systemConfigProxy": "0xfa73580F4D72294Ae9EE3DAaC36D8bF111B37Ce9",
      "proxyAdmin": "0xc43ED1E8D70d0e5801514833fAD3D93Ba16Da4Aa",
      "absolutePrestate": "0x0000000000000000000000000000000000000000000000000000000000000000"
    }
  ]
}
EOL

cat tmp-config.json

git checkout -f origin/hemi

(cd ./../../op-deployer ; just build)

./../../op-deployer/bin/op-deployer upgrade v3.0.0 \
    --config tmp-config.json \
    --l1-rpc-url http://localhost:9988
