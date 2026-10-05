# A Prysm consensus layer for the localnet L1

With `L1_CONSENSUS=prysm` and `docker compose --profile prysm`, the localnet
L1 is a real proof-of-stake chain: geth-l1 is driven over the engine API by a
Prysm beacon node (`prysm-beacon`) and a validator client (`prysm-validator`)
with 64 validators, instead of geth's simulated consensus layer (`--dev`).
The L1 then has real slots and finality, a real Beacon API that the op-nodes
fetch blobs from, and activates the Gloas fork on the consensus layer at the
same time as Amsterdam on the execution layer, the way Sepolia does.

* `generate-genesis.sh` is run by `genesisl2.sh` once the execution layer
  genesis exists.  It writes the Prysm chain config with Gloas at the epoch
  of the Amsterdam time (3 second slots, 32 slot epochs, so
  `L1_AMSTERDAM_OFFSET_SECONDS` must be a multiple of 96), rewrites the
  execution genesis the way `prysmctl` needs it, and generates the beacon
  genesis state with the validators.
* `keys/` holds the EIP-2335 keystores of those validators, the
  deterministic "interop" keys of the consensus specs that `prysmctl` puts
  into a genesis state.  `mkkeystores.py` regenerates them.  They are public
  by construction and only usable on a localnet started from that genesis.
  `wallet-password.txt` is their password.  `prysm-validator-import` imports
  them into a wallet before the validator starts.
* `deposit-contract.json` is the deposit contract that Prysm expects to find
  in the execution genesis; the localnet never deposits.

The validator proposes with the beacon node's own payloads (self-built, no
external builder).  Prysm needs a few epochs after it comes up to finalize,
which the services that wait for L2 finality wait for.
