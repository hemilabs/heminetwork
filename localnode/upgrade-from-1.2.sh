#! /bin/bash


set -ex

PRIVATE_KEY=0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6

RPC_URL='http://172.17.0.1:9988'

git fetch op

git checkout -f op-contracts/v1.8.0-rc.4

git submodule update --init --recursive

(cd ./../../op-deployer ; just build)

./../../op-deployer/bin/op-deployer bootstrap opcm \
    --l1-rpc-url http://localhost:9988 \
    --private-key "$PRIVATE_KEY" \
    --artifacts-locator "file://$(pwd)/forge-artifacts" > ./opcm-output.json

echo "the output is"

tail -n 15 ./opcm-output.json

cat >tmp-config.json <<EOL
{
  "prank": "0x382D0AA958998408DD7695c8965C46BdaBBC3003",
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
