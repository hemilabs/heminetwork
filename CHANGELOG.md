# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Guard `MsgTx` dispatch on `MempoolEnabled` in `handleGeneric`. When
  the mempool is disabled, unsolicited P2P transaction messages caused a
  nil pointer dereference crash.

- Fix a remote crash vulnerability in `tbc` caused by the first element
  of an inventory message list being accessed before ensuring the slice
  isn't empty ([#1039](https://github.com/hemilabs/heminetwork/pull/1039)).

- Set default `POPM_MAX_FEE` to 100 sats/vB (was 0, uncapped). Prevents
  a malicious or compromised fee source from draining PoP miner UTXOs.
  Set `POPM_MAX_FEE=0` to restore the previous uncapped behavior.
- Fix `KeystonesByHeight` panic when primary keystone hash keys collide
- Add `CheckBlockSanity` to `tbc` block insert RPC path as
  defense-in-depth hardening. The RPC binds to localhost by default and
  is used by internal services to feed forked-off blocks
  ([#1057](https://github.com/hemilabs/heminetwork/pull/1057)).

### Breaking Changes

- `BlockHashByTxId` now returns `(*chainhash.Hash, wire.TxLoc, error)`;
  callers that only need the hash use `bh, _, err :=`
  ([#1052](https://github.com/hemilabs/heminetwork/pull/1052)).
- Rename `TBC_BLOCKHEADER_CACHE_SIZE` environment variable to
  `TBC_HEADER_CACHE_SIZE`
  ([#1034](https://github.com/hemilabs/heminetwork/pull/1034)).

- `wallet.TransactionCreate` and `wallet.TransactionSign` now use
  `PrevOuts` (`map[string]*wire.TxOut`) instead of `map[string][]byte`.
  Witness sighash algorithms require the spent output's value; the old type
  carried only the pkScript
  ([#971](https://github.com/hemilabs/heminetwork/pull/971)).

### Added

- Add `BlockRawByHash` to DB interface and `lazyBlock` type for zero-copy
  per-tx block access without full deserialization
  ([#1051](https://github.com/hemilabs/heminetwork/pull/1051)).
- Store tx byte location (`TxLoc`) in tx index `'t'` entry values for
  O(1) tx lookup; DB version 5 → 6
  ([#1052](https://github.com/hemilabs/heminetwork/pull/1052)).
- Add generic `lru` package with cost-based LRU cache (`lru.Cache[K,V]`)
  ([#1034](https://github.com/hemilabs/heminetwork/pull/1034)).
- Add utxo read LRU cache (`TBC_UTXO_READ_CACHE_SIZE`) to reduce LevelDB
  reads during UTXO fixup; cleared when indexer reaches tip
  ([#1035](https://github.com/hemilabs/heminetwork/pull/1035)).
- Add ZK indexers.
- Add RPC request method whitelist to hproxy ([#691](https://github.com/hemilabs/heminetwork/pull/691)).
- Add TBC notification system ([#725](https://github.com/hemilabs/heminetwork/pull/725)).
- Add Continuum Transfuctioner protocol and daemon to handle threshold signatures ([#752](https://github.com/hemilabs/heminetwork/pull/752)).
- Add Trust, rust version of TBC Headers only mode ([#970](https://github.com/hemilabs/heminetwork/pull/970))
- Add Authenticated RPC route for administrative requests to TBC ([#1003](https://github.com/hemilabs/heminetwork/pull/1003)).
- Add `MempoolUtxos` RPC command returning unspent mempool outputs matching a required set of script hashes
  ([#987](https://github.com/hemilabs/heminetwork/pull/987)).
- Add filtered transaction notifications to TBC for commerce (TxWatch/TxUnwatch API)
  ([#986](https://github.com/hemilabs/heminetwork/pull/986)).
- Add native P2WPKH and BIP-86 P2TR key-path signing to
  `wallet.TransactionSign`, with BIP-143/BIP-341 sighash handling
  ([#971](https://github.com/hemilabs/heminetwork/pull/971)).
- Add multi-form key indexing to `zuul/memory`: `PutKey` now derives
  P2PKH, P2WPKH, and BIP-86 P2TR addresses from a single compressed
  public key and indexes the key under all three
  ([#971](https://github.com/hemilabs/heminetwork/pull/971)).
- Add `TxByID` to the `gozer.Gozer` interface with `tbcGozer`
  implementation backed by TBC RPC
  ([#971](https://github.com/hemilabs/heminetwork/pull/971)).
- Add multiple RPC commands to regular and authenticated TBC routes ([#1026](https://github.com/hemilabs/heminetwork/pull/1026)).
- Add maximum fee configuration to `popmd` ([#1037](https://github.com/hemilabs/heminetwork/pull/1037)).
- Add external ECDSA and schnorr signature injection to `bitcoin/wallet`,
  enabling threshold signature committees, hardware wallets, and PSBT flows
  to produce signatures out of band and hand them to the wallet for
  witness/sigScript assembly.  Includes `TransactionApplyECDSA`,
  `TransactionApplySchnorr`, `ECDSASigFromRS` DER helper, and
  `VerifyECDSA`/`VerifySchnorr` pre-broadcast gates.
- Add `bitcoin/zuul.TSSNamedKey` storage for keys controlled by an external
  threshold signature scheme, alongside symmetrical `PutTSSKey` /
  `GetTSSKey` / `PurgeTSSKey` / `LookupTSSKeyByAddr` interface methods.

### Changed

- `BlockTxUpdate` uses stack-allocated reusable buffers instead of slicing
  loop variables, avoiding potential data integrity issues
  ([#1052](https://github.com/hemilabs/heminetwork/pull/1052),
  [#1050](https://github.com/hemilabs/heminetwork/issues/1050)).
- Replace block and header caches in level package with generic `lru.Cache[K,V]`
  ([#1034](https://github.com/hemilabs/heminetwork/pull/1034)).

- Update required Go version to [Go 1.26](https://tip.golang.org/doc/go1.26)
  ([#673](https://github.com/hemilabs/heminetwork/pull/673), [#698](https://github.com/hemilabs/heminetwork/pull/698),
  [#896](https://github.com/hemilabs/heminetwork/pull/896)).

- Move `localnode` to dedicated [hemilabs/hemi-node](https://github.com/hemilabs/hemi-node)
  repository ([#687](https://github.com/hemilabs/heminetwork/pull/687)).

- Move `testutil` into the `internal/` package, removing it from the public API
  ([#735](https://github.com/hemilabs/heminetwork/pull/735)).

- Update `localnet` and `localnode` `geth-l1` versions to 16.7 and fix tests
  ([#746](https://github.com/hemilabs/heminetwork/pull/746)).

- Improved signal handling in the daemons ([#763](https://github.com/hemilabs/heminetwork/pull/763)).

- Bump tbcd database schema to v5; first start after upgrade wipes the stored block bodies and re-downloads them
  with witness data, triggered by the witness-download fix below
  ([#972](https://github.com/hemilabs/heminetwork/pull/972)).

### Fixed

- Fix typos across the codebase
  ([#694](https://github.com/hemilabs/heminetwork/pull/694), [#733](https://github.com/hemilabs/heminetwork/pull/733),
  [#751](https://github.com/hemilabs/heminetwork/pull/751), [#755](https://github.com/hemilabs/heminetwork/pull/755)).

- Fix bug that led to early exit during Daemon configuration parsing ([#885](https://github.com/hemilabs/heminetwork/pull/885))

- Fix bug that allowed invalid headers to be indexed ([#950](https://github.com/hemilabs/heminetwork/pull/950))

- Fix bug that led to delayed request processing in tbcgozer ([#969](https://github.com/hemilabs/heminetwork/pull/969))

- Fix `signP2WPKH` and `signP2TRKeyPath` not clearing `SignatureScript` after
  signing.  `TransactionCreate` pre-populates `SignatureScript` for fee
  estimation; native segwit requires an empty scriptSig
  ([#971](https://github.com/hemilabs/heminetwork/pull/971)).

- Fix tbcd requesting witness-stripped blocks and txs from peers (BIP-144); on-disk blocks are now
  witness-inclusive after a v5 upgrade plus resync
  ([#972](https://github.com/hemilabs/heminetwork/pull/972)).

- Fix inverted conditions in `synced()` causing tbcd to incorrectly report
  itself as not-synced when an optional indexer is enabled.
  ([#1036](https://github.com/hemilabs/heminetwork/pull/1036))

- Fix bug in `popm` that led to a panic when prometheus called geth before
 the client was set ([#1030](https://github.com/hemilabs/heminetwork/pull/1030)).

## [v2.0.0]

### Breaking Changes

- Rework how PoP Miners and BFG work ([#396](https://github.com/hemilabs/heminetwork/pull/396)).
  For details on running a v2 PoP Miner, see [the `popmd` readme](cmd/popmd/README.md).
  - Rewrite `bfgd` to serve as an API layer for finality data. PoP miners no longer use `bfgd`.
  - Remove `bssd`. PoP payouts are now handled by [`op-geth`](https://github.com/hemilabs/op-geth).
  - Add indexing for Hemi Keystones published to Bitcoin by PoP
    miners ([#549](https://github.com/hemilabs/heminetwork/pull/549)).
  - Rewrite `popmd`. To run `popmd`, the following data sources are now required:
    - A Hemi `op-geth` node (for keystone notifications).
    - A "Gozer" Bitcoin data source, such as [TBC](cmd/tbcd), to retrieve Bitcoin data and publish PoP transactions.
      Gozer can also be used to provide fee estimations.
  - PoP Miners can now use either a static fee or dynamic fee estimations from Gozer.

- Rename Go module to `github.com/hemilabs/heminetwork/v2` (add `/v2`
  suffix) ([#622](https://github.com/hemilabs/heminetwork/pull/622)).

### Added

- Add **hproxyd**, a simple and efficient RPC request proxy to replace
  `proxyd` ([#568](https://github.com/hemilabs/heminetwork/pull/568), [#574](https://github.com/hemilabs/heminetwork/pull/574),
  [#576](https://github.com/hemilabs/heminetwork/pull/576)).

- Add Prometheus metrics and health check endpoints to `bfgd` and
  `popmd` ([#619](https://github.com/hemilabs/heminetwork/pull/619)).

- Add supply chain attestations for releases ([#634](https://github.com/hemilabs/heminetwork/pull/634)).

- Add [documentation for running `popmd`](https://github.com/hemilabs/heminetwork/blob/main/cmd/popmd/README.md)
  ([#597](https://github.com/hemilabs/heminetwork/pull/597)).

#### `bitcoin` package

- Add `bitcoin/gozer` package: Bitcoin data interface layer, with a basic implementation for Blockstream (Electrs)
  and a complete implementation supporting the TBC RPC API ([#562](https://github.com/hemilabs/heminetwork/pull/562)).
- Add `bitcoin/vinzclortho` package: Bitcoin wallet interface that handles creation and derivation of Bitcoin
  addresses ([#562](https://github.com/hemilabs/heminetwork/pull/562)).
- Add `bitcoin/zuul` package: Interface for handling the storage of secret material, such as Bitcoin wallet private
  keys ([#562](https://github.com/hemilabs/heminetwork/pull/562)).

#### Tiny Bitcoin Client (TBC)

- Add support for Bitcoin testnet4 ([#521](https://github.com/hemilabs/heminetwork/pull/521)).
- Add indexing for Hemi Keystones published to Bitcoin by PoP
  miners ([#549](https://github.com/hemilabs/heminetwork/pull/549)).
- Add Bitcoin mempool support ([#549](https://github.com/hemilabs/heminetwork/pull/549)).
- Add transaction fee estimation ([#549](https://github.com/hemilabs/heminetwork/pull/549)). This can be used by `popmd`
  when creating PoP transactions.
- Add Hemi Keystone height hash index with V4 database upgrade, allowing keystones to be retrieved at a specified block
  height ([#539](https://github.com/hemilabs/heminetwork/pull/539)). Used in `op-geth` for handling PoP payouts.
- Add standalone TBC Docker image: [`hemilabs/tbcd`](https://hub.docker.com/r/hemilabs/tbcd), [
  `ghcr.io/hemilabs/tbcd`](https://ghcr.io/hemilabs/tbcd) ([#531](https://github.com/hemilabs/heminetwork/pull/531)).

#### localnode

> [!NOTE]
> The `localnode` directory still uses an older version of the Hemi stack. After this release, all node-running
> resources and documentation will move to a separate repository, maintained and versioned independently, with its own
> changelog.

- Add easy-to-follow quickstart section to the node running
  documentation ([#656](https://github.com/hemilabs/heminetwork/pull/656)).

### Changed

- Update localnode config with new testnet P2P nodes ([#650](https://github.com/hemilabs/heminetwork/pull/650)).

- Move common test utilities into a new `testutil` package to reduce duplication and simply
  testing ([#530](https://github.com/hemilabs/heminetwork/pull/530)).

- Update Hemi keystone genesis block on Bitcoin testnet4
  to `00000000a14c6e63123ba02d7e9fd173d4b04412c71a31b7a6ab8bb3106c9231`
  ([#654](https://github.com/hemilabs/heminetwork/pull/654)). The previous block was removed by a long re-org.

- Replace `time.After` with `time.Tick` to avoid issues on sleeping dev
  machines ([#580](https://github.com/hemilabs/heminetwork/pull/580)).

- Update [`README.md`](README.md) file with current
  information ([#593](https://github.com/hemilabs/heminetwork/pull/593)).

### Removed

- Remove WebAssembly support from the PoP Miner ([#526](https://github.com/hemilabs/heminetwork/pull/526)).

- Remove `extool`, an unused Electrum/Electrs CLI utility ([#625](https://github.com/hemilabs/heminetwork/pull/625)).

### Fixed

- Fix duplicate `flag.Parse` call in `cmd/keygen` ([#565](https://github.com/hemilabs/heminetwork/pull/565)).
- Fix typos across the codebase
  ([#550](https://github.com/hemilabs/heminetwork/pull/550), [#564](https://github.com/hemilabs/heminetwork/pull/564),
  [#633](https://github.com/hemilabs/heminetwork/pull/633), [#658](https://github.com/hemilabs/heminetwork/pull/658),
  [#663](https://github.com/hemilabs/heminetwork/pull/663)).

### Contributors

Thank you to everyone who contributed to this release!

- [@AL-CT](https://github.com/AL-CT)
- [@ClaytonNorthey92](https://github.com/ClaytonNorthey92)
- [@Dzmitryy1812](https://github.com/Dzmitryy1812)
- [@Galoretka](https://github.com/Galoretka)
- [@jcvernaleo](https://github.com/jcvernaleo)
- [@joshuasing](https://github.com/joshuasing)
- [@kks-code](https://github.com/kks-code)
- [@lechpzn](https://github.com/lechpzn)
- [@leopardracer](https://github.com/leopardracer)
- [@marcopeereboom](https://github.com/marcopeereboom)
- [@max-sanchez](https://github.com/max-sanchez)
- [@moshderte](https://github.com/moshderte)
- [@pxwanglu](https://github.com/pxwanglu)
- [@tosynthegeek](https://github.com/tosynthegeek)
- [@yinwenyu6](https://github.com/yinwenyu6)

---

_Looking for the changelog for an older version? Check <https://github.com/hemilabs/heminetwork/releases>_

[Unreleased]: https://github.com/hemilabs/heminetwork/compare/v2.0.0...HEAD
[v2.0.0]: https://github.com/hemilabs/heminetwork/releases/tag/v2.0.0
