# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add RPC request method whitelist to hproxy ([#691](https://github.com/hemilabs/heminetwork/pull/691)).

### Changed

- Update required Go version to [Go 1.25](https://tip.golang.org/doc/go1.25).

### Fixed

- Fix typos across the codebase
  ([#694](https://github.com/hemilabs/heminetwork/pull/694)).

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

_Looking for the changelog for an older version? Check https://github.com/hemilabs/heminetwork/releases_

[Unreleased]: https://github.com/hemilabs/heminetwork/compare/v2.0.0...HEAD
[v2.0.0]: https://github.com/hemilabs/heminetwork/releases/tag/v2.0.0
