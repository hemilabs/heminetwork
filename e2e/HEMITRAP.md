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