# Hemi Network

[![Go Reference](https://pkg.go.dev/badge/github.com/hemilabs/heminetwork.svg)](https://pkg.go.dev/github.com/hemilabs/heminetwork)
[![Go Report Card](https://goreportcard.com/badge/github.com/hemilabs/heminetwork)](https://goreportcard.com/report/github.com/hemilabs/heminetwork)
[![Go Build Status](https://github.com/hemilabs/heminetwork/actions/workflows/go.yml/badge.svg)](https://github.com/hemilabs/heminetwork/actions/workflows/go.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-ff6c15)](LICENSE)

Hemi is an EVM-compatible L2 blockchain that combines the security of Bitcoin with the programmability of Ethereum.

This repository contains the core daemons of the Hemi Network, including:

- **bfgd**: Hemi Bitcoin Finality Governor daemon.
- **popmd**: The Hemi PoP Miner daemon.
- **tbcd**: A fully custom, embeddable Bitcoin node written in Go.

---

## Components

The Hemi Network is composed of many services. The core Hemi services in this repository are:

| Name                                               | Description                                |
|----------------------------------------------------|--------------------------------------------|
| [Bitcoin Finality Governor (`bfgd`)](./cmd/bfgd)   | todo                                       |
| [Hemi RPC Proxy Daemon (`hproxyd`)](./cmd/hproxyd) | Proxies RPC requests to Hemi op-geth nodes |
| [Hemi PoP Miner Daemon (`popmd`)](./cmd/popmd)     | The Hemi Proof-of-Proof miner daemon       |
| [Hemi Tiny Bitcoin Daemon (`tbcd`)](./cmd/tbcd)    | Embeddable Bitcoin node                    |

## Installation

### Binaries

Pre-built binaries for Linux, macOS, Windows and OpenBSD are available
from [GitHub Releases](https://github.com/hemilabs/heminetwork/releases).

### Docker

Docker images are published to both [GitHub Container Registry](https://github.com/hemilabs/heminetwork/packages)
and [Docker Hub](https://hub.docker.com/u/hemilabs/). Docker images are currently available for:

- `hemilabs/bfgd` - Hemi Bitcoin Finality Governor
- `hemilabs/hproxy` - Hemi RPC proxy
- `hemilabs/popmd` - Hemi PoP Miner Daemon
- `hemilabs/tbcd` - Hemi Tiny Bitcoin Daemon

### Building from source

**Prerequisites**

- Go v1.24 or newer (https://go.dev/dl/)
- `git`
- `make`

**Build**

1. Clone the `heminetwork` repository:
   ```shell
   git clone https://github.com/hemilabs/heminetwork.git
   cd heminetwork
   ```

2. Setup and build binaries:
   ```shell
   make deps    # Download and install dependencies
   make install # Build binaries
   ```

Output binaries will be written to the `bin/` directory.

## Contributing

All contributions are welcome!

### Contact

This repository is maintained by the Protocol Engineering team at Hemi Labs. You can contact us in the [official Hemi
Discord server](https://discord.gg/hemixyz).

#### Security Vulnerabilities

If you discover vulnerabilities in Hemi, we encourage responsible disclosure of the vulnerability so that we can take
steps to resolve the vulnerability as quickly as possible. We ask you to help us better protect Hemi and our users by
reporting vulnerabilities through HackerOne. **Never report security vulnerabilities publicly, especially on GitHub
issues.**

- [Submit a report through Hemi's HackerOne VDP program](https://hackerone.com/hemi_labs_vdp)

If you have discovered a security vulnerability, please report it in accordance with
our [Security Policy](https://github.com/hemilabs/.github/blob/main/SECURITY.md).

## License

The contents of this repository are distributed under the terms of the MIT License, except where otherwise noted.<br/>
For more information, please refer to the [LICENSE](https://github.com/hemilabs/heminetwork/blob/main/LICENSE) file.
