# Hemi Network – Release Guide

This is a guide to releasing new releases of **Hemi Network**.

---

## Versions – What Are Those Numbers?

We use **SemVer**, it's `MAJOR.MINOR.PATCH`. Here's the deal:

- **MAJOR** – Major changes that break everything. API, config, protocols. Users need to fix their configs or they're screwed.  
- **MINOR** – New features, old stuff still works. Upgrade and enjoy.  
- **PATCH** – Bug fixes, code improvements, documentation. Upgrade safely, no stress.

**Examples**:  
- `2.0.0` – Protocol rewrite, get ready for manual config changes.  
- `2.1.0` – Validator detection added.  
- `2.1.1` – Memory leak fixed.

---

## Changelog – Tell Us What Changed

The changelog is your story about what you wrote and why. Don't just say "something changed", but explain it as if you were talking to a friend. Tell us what's new, what's fixed, and what might break.

**Example**:
```
[2.0.0] - 2025-08-07
News
- Added support for X, now you can process Y faster.
- New validator protocol runs smoother.
Improvements
- About 20 seconds faster startup.
- Rewritten sync logic, fewer errors.
Bugfixes
- Fixed a memory leak in the PoP module.
What might break
- Renamed syncMode to mode - update your configs, otherwise it's all over.
- Replaced /v1/nodes endpoint with /v2/nodes - fix your scripts.
```

**Tip**: Write in a way that users understand what to do. If this is difficult, ask the team for help in the chat.

---

## What We Ship

Each release requires a few files to allow users to run Hemi. Here's what needs to be built:

- **A Docker image**: `docker build -t hemilabs/hemi:<VERSION> . && docker push hemilabs/hemi:<VERSION>` – produces `hemilabs/hemi:<VERSION>`.  
- **A Linux binary**: `make build-linux` – produces `./bin/hemi-<VERSION>-linux-amd64`.  
- **A Helm chart (if needed)**: `helm package ./charts/hemi` – produces `hemi-<VERSION>.tgz`.

**Tip**: If the command fails, don't worry, just contact the team.

---

## How to Ship a Release

Step by step, without confusion:

1. **Test the code**: Run `make test`. Everything green? Great. If not, let the team know.  
2. **Upgrade**: Get `bump2version` (`pip install bump2version`), then `bump2version <major|minor|patch>`. Update `VERSION` and tags. Push: `git push && git push --tags`.  
3. **Write a changelog**: Open `CHANGELOG.md`, add a new section as above. Don't overload, don't bore users.  
4. **Build artifacts**: Run Docker commands, binaries, and Helm. Make sure everything works.  
5. **Publish a release**: On GitHub, go to "Releases" and click "Create a new release". Add a tag (e.g. `v2.0.0`), paste the changelog, attach the binary and Helm chart.  

---

## Tools

- **Versions**: `bump2version` — saves you from manual editing.  
- **Tests**: Set up GitHub Actions to automatically check your code.  
- **Changelog**: Write your own or play around with `git-chglog` if you want.

---
