## Welcome!

Welcome to the [heminetwork](https://github.com/hemilabs/heminetwork) repository. First off, thank you for taking the
time to consider contributing!

<details>
  <summary>Table of Contents</summary>

<!-- TOC -->
  * [Welcome!](#welcome)
  * [Code of Conduct](#code-of-conduct)
  * [Contributing](#contributing)
    * [Security](#security)
    * [Developer setup](#developer-setup)
    * [Code style](#code-style)
    * [Commit messages](#commit-messages)
    * [Pull Requests](#pull-requests)
    * [Changelog](#changelog)
  * [Maintainer's Guide](#maintainers-guide)
    * [Versioning](#versioning)
    * [Release cycle](#release-cycle)
    * [Release preparation](#release-preparation)
    * [Create release](#create-release)
<!-- TOC -->
</details>

## Code of Conduct

Please read and follow the [Code of Conduct](https://github.com/hemilabs/.github/blob/main/CODE_OF_CONDUCT.md) before
contributing to this repository.

## Contributing

- Found a bug or have an idea for a new feature? Open an [issue](https://github.com/hemilabs/heminetwork/issues).
- Want to build something new? Start with a [proposal issue](https://github.com/hemilabs/heminetwork/issues).
- Have improvements for our code or docs? Pull requests are very welcome!

Join the discussion in our [Discord server](https://discord.gg/hemixyz) or keep an eye
on [issues](https://github.com/hemilabs/heminetwork/issues)
and [pull requests](https://github.com/hemilabs/heminetwork/pulls).

_All contributions to this repository must be made under the terms of the [MIT License](LICENSE)._

### Security

> [!CAUTION]
> Never report security vulnerabilities publicly, especially in GitHub issues.

If you discover vulnerabilities in Hemi, please report it responsibly so we can resolve it quickly. We ask you to help
us better protect Hemi and our users by reporting vulnerabilities through HackerOne.

- [Submit a report through Hemi's HackerOne VDP program](https://hackerone.com/hemi_labs_vdp)

If you have discovered a security vulnerability, please report it in accordance with
our [Security Policy](https://github.com/hemilabs/.github/blob/main/SECURITY.md).

### Developer setup

**Prerequisites**

- Go v1.25 or newer - https://go.dev/dl/
- `git`, `make`

**Setup**

To setup your development environment:

```shell
# Install build dependencies
make deps
```

**Useful commands**

```shell
# Build, lint, and test
make

# Build all binaries
make build

# Build specific binaries
make bfgd
make popmd

# Run linters and formatters
make lint

# Run tests
make test
```

### Code style

- Follow [Effective Go](https://go.dev/doc/effective_go).
- Keep lines under 80 characters where possible.
  - Don't wrap long function signatures; it makes them harder to read.
  - Avoid wrapping of nested `if err := abc; err != nil`; move the `err` assignment above the if statement.
- Document exported functions and types clearly (following the godoc syntax).
- All new code should include unit tests where practical. You can run tests with `make test`.

We use `golangci-lint` to run formatters and linters on this codebase. You can run the linter by running `make lint`,
or manually with `golangci-lint run ./...`. **All changes must pass the linter before being submitted or merged in pull
requests.**

### Commit messages

Commit messages should follow [Go's guidelines](https://go.dev/doc/contribute#commit_messages). For example:

```
service/bfg: handle abc when xyz

[longer description]

Fixes #12345
```

For the subject line (first line):

- Use the package or area affected, followed by a colon.
- Use present tense, e.g. "add foo", not "added foo".
- Keep it short (preferably under ~76 characters).
- No trailing periods or emojis.

For the body (longer description):

- Wrap text to ~76 characters where possible, unless you need longer lines (e.g. tables, long links).
- Separate with a blank line after the subject.
- Reference issues with `Fixes #123` or `Resolves #123, #456` (below the description, separated by a blank line).
- Don't use Markdown formatting.

### Pull Requests

- Pull request titles and descriptions should follow the same rules as [commit messages](#commit-messages).
- Keep pull requests small and focused; large unrelated changes are harder to review.
- Make sure `make test` and `make lint` pass locally before opening a PR.
- CI must pass before merging, and should pass before requesting reviews.
- Mark work-in-progress PRs as drafts in GitHub.

### Changelog

We maintain a [CHANGELOG.md](CHANGELOG.md) for all notable changes. Update it in the same pull request as your change.

Pull requests are automatically labeled based on changelog status:

- **`changelog: required`** - Added by default when no changelog entry is detected
- **`changelog: done`** - Automatically applied when `CHANGELOG.md` is updated
- **`changelog: skip`** - Only for internal changes invisible to users (CI/build scripts, test fixes, minor typos in
  non-user docs). Most changes affecting code behavior, APIs, or user-facing features require changelog entries.

Follow the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) style:

- **Breaking changes** - Breaking changes that may need attention
- **Added** - New features
- **Changed** - Updates, improvements and other changes
- **Deprecated** - Notices for features pending removal
- **Removed** - Removed features
- **Fixed** - Bug fixes
- **Security** - Security-related changes

Keep entries concise and understandable, as if explaining the change to a colleague or friend.

## Maintainer's Guide

> [!TIP]
> This section is for use by Hemi Labs team members only. You don't need to worry about anything under this section!

### Versioning

We use [Semantic Versioning](https://semver.org/spec/v2.0.0.html) for this repository.

- Major - Breaking changes or removals
- Minor - New features or notable changes
- Patch - Bug fixes and small changes

For unstable changes, beta releases (e.g. `v2.0.0-beta.1`) should be made before a stable release.

### Release cycle

We aim to create minor releases regularly, and patch releases as needed for bug fixes.

### Release preparation

1. Update `Major`, `Minor` and `Patch` constants in `version/version.go`.
2. Ensure the `CHANGELOG.md` file is up-to-date and complete.
3. Create a pull request with the above changes (using `gh` CLI):
   ```shell
   VERSION=2.0.0 # <- replace
   git commit -am "version: prepare to release v$VERSION"
   gh pr create --fill
   ```

### Create release

1. Complete [Release preparation](#release-preparation).
2. Run the `scripts/release.sh` script. This will create the version tag from the latest commit on `upstream/main` and
   push the tag. You will be prompted to confirm whether you want to create, then push the tag. Once pushed, this will
   trigger release CI.
   ```shell
   VERSION=2.0.0 # <- replace
   ./scripts/release.sh "$VERSION"
   ```

3. Ensure release GitHub Actions workflow succeeds. The release workflow will run tests, then build and publish
   binaries, archives and Docker images. Once complete, the release should be visible
   at https://github.com/hemilabs/heminetwork/releases
