This is a guide to releasing new releases of **Hemi Network**. It's super easy, even if you're new and afraid of breaking something. We'll write it as is, no extra words.

Versions – What are those numbers? We use SemVer, it's MAJOR.MINOR.PATCH. Here's the deal:

**MAJOR** – Major changes that break everything. API, config, protocols. Users need to fix their configs or they're screwed. 

**MINOR** – New features, old stuff still works. Upgrade and enjoy. 

**PATCH** – Bug fixes, code improvements, documentation. Upgrade safely, no stress.

Examples:

`2.0.0` – Protocol rewrite, get ready for manual config changes.

`2.1.0` – Validator detection added.

`2.1.1` – Memory leak fixed.


Changelog - tell us what changed. The changelog is your story about what you wrote and why. Don't just say "something changed", but explain it as if you were talking to a friend. Tell us what's new, what's fixed, and what might break. 

*Example:*
[2.0.0] - 2025-08-07
News
Added support for X, now you can process Y faster.
New validator protocol runs smoother.
Improvements
About 20 seconds faster startup.
Rewritten sync logic, fewer errors.
Bugfixes
Fixed a memory leak in the PoP module.
What might break
Renamed syncMode to mode - update your configs, otherwise it's all over.
Replaced /v1/nodes endpoint with /v2/nodes - fix your scripts. Tip: Write in a way that users understand what to do. If this is difficult, ask the team for help in the chat.

What we ship. Each release requires a few files to allow users to run Hemi. Here's what needs to be built:

A Docker image: docker build -t hemilabs/hemi: . && docker push hemilabs/hemi: – produces hemilabs/hemi:. A Linux binary: make build-linux – produces ./bin/hemi--linux-amd64. A Helm chart (if needed): helm package ./charts/hemi – produces hemi-.tgz.

Tip: If the command fails, don't worry, just contact the team.

How to ship a release step by step, without confusion:

Test the code: run make test.

Everything green? Great. If not, let the team know.
Upgrade: Get bump2version (pip install bump2version), then bump2version <major|minor|patch>.
Update VERSION and tags. Push: git push && git push --tags.

Write a changelog: Open CHANGELOG.md, add a new section as above. Don't overload, don't bore users. Build artifacts: Run Docker commands, binaries, and Helm. Make sure everything works. Publish a release: On GitHub, go to "Releases" and click "Create a new release". Add a tag (e.g. v2.0.0), paste the changelog, attach the binary and Helm chart.
Notify your team in chat or discord: "Version 2.0.0 released, check out what's new!"

Tools:

Versions: bump2version — saves you from manual editing. Tests: Set up GitHub actions to automatically check your code. Changelog: Write your own or play around with git-chglog if you want.

If it all goes to hell

Bug in a release? Push a patch (2.0.1) to fix it. Lost on a step? Ask in chat or in an Issue, no shame. Users complaining? Check the changelog — have you explained how to upgrade?

This is an easy way to revert releases without going crazy. Any questions?
