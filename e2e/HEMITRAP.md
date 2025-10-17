# Hemitrap

Hemitrap is a feature that allows a user to fork a synced production 
(testnet or mainnet) hemi node and run a local, isolated private network
for (mainly) testing contract upgrades.

## How to use

You will need the hemi-node repo cloned

```shell
git clone https://github.com/hemilabs/hemi-node
```

Then, sync a node. 


_NOTE_: As of now only testnet is supported.

```shell
cd /path/to/hemi-node

./scripts/gen.sh testnet snap hemi-min

docker compose -f ./testnet/docker-compose.yml up --profiles hemi-min
```

Let that sync.

Once your node is synced, you could be able to tell by:

_NOTE_: there are ways to do this in one command, but this works.

```shell
docker compose -f ./testnet/docker-compose.yml exec -it op-geth-l2
geth attach datadir/geth/geth.ipc
eth.syncing
```

Then, stop your containers (ctrl+c).

Then, similar to the above, run:

_NOTE_: Before you run the below command, I suggest updating the `rollup.json`
file to have the network run a little faster for local testing. Updating these
two values:
```json
{
    "max_sequencer_drift": 200,
    "seq_window_size": 20
}
```

```shell
docker compose -f ./testnet/docker-compose.yml up --profiles hemitrap
```

Now you should have a local private network with your own sequencer running.

### Ensure the proposer works

The proposer will need to be updated, at the smart contract level in order to
publish transactions.

Please run one of these scripts, based on the current version you're running in
your fork.

_NOTE_: The upgrade program itself expects the proposer to be a certain "code".
  So it's easiest to only run this once per fork.

```shell
./e2e/proposer-code-1.2.sh
```

## Example: upgrading testnet 1.2 --> 1.3

### Step 1: Sync your node

```shell
cd /path/to/hemi-node
./scripts/gen.sh testnet snap hemi-min
GETHL1ENDPOINT=... PRYSMENDPOINT=... docker compose -f ./testnet/docker-compose.yml up --profiles hemi-min 
```

### Step 2: Once synced, stop
```shell
docker compose -f ./testnet/docker-compose.yml exec -it op-geth-l2 sh
geth attach datadir/geth/geth.ipc
eth.syncing
```

once `eth.syncing === false`, then you're synced.

### Step 3: Stop the daemons

You can `ctrl+c` or `docker stop -t 60 $(docker ps -q)`

### Step 4: Run the forked network (i.e. hemitrap)

Optional: Update `rollup.json` file to have faster sequencing values, as
mentioned previously in this file.

```shell
GETHL1ENDPOINT=... PRYSMENDPOINT=... docker compose -f ./testnet/docker-compose.yml up --profiles hemitrap
```

### Step 5: Deploy upgraded implementations, upgrade proxies

```shell
cd /path/to/hemilabs/optimism
git checkout origin/clayton/op-contracts/v1.3.0
go build -o ./bin/hemi-uprade ./op-chain-ops/cmd/hemi-upgrade/
cd packages/contracts-bedrock
IMPL_SALT=something4 forge script --rpc-url http://localhost:9988 --private-key 0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a --sig 'deployImplementations()' scripts/Deploy.s.sol --broadcast
cd ../..
./op-chain-ops/bin/hemi-upgrade --private-key 47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a --l1-rpc-url=http://localhost:9988 --l2-chain-id=743111 --deploy-config /path/to/testnet/deploy-config.json
```

```shell
cd /path/to/heminetwork
./e2e/proposer-code-1.3.sh
```

### Step 6: Run your tests!

```shell
TESTING_FORK=true go test -run 'TestL1L2Comms/testing_sequencing_client' -timeout 60m -count 1 -v .
```
