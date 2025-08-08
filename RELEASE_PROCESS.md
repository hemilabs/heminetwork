### Hemi Network – How to Drop a Release
Yo, this is the guide for pushing out new Hemi Network releases. It’s dead simple, even if you’re a newbie scared of breaking stuff. Writing this like it is, no fancy fluff.

Versions – What’s with the Numbers?
We use SemVer, that’s MAJOR.MINOR.PATCH. Here’s the deal:

MAJOR – Big changes that break stuff. APIs, configs, protocols. Users gotta fix their setups or they’re screwed.
MINOR – New features, old stuff still works. Update and enjoy.
PATCH – Bug fixes, code tweaks, docs. Safe to update, no stress.

Examples:
2.0.0 – Rewrote the protocol, brace for manual config changes.
2.1.0 – Added validator discovery thing.
2.1.1 – Plugged a memory leak.
Tip: Not sure which version to bump? Ping the team in chat, they’ll sort you out.

 Changelog – Spill What Changed
Changelog is your story of what you coded and why. Don’t just say “changed stuff,” explain it like you’re chatting with a buddy. Say what’s new, what’s fixed, and what might break.
Example:
## [2.0.0] – 2025-08-07

###  New Stuff
- Added X support, now you can do Y faster.
- New validator protocol, runs smoother.

###  Tweaks
- Sped up startup by like 20 seconds.
- Rewrote sync logic, fewer bugs.

###  Fixes
- Killed a memory leak in the PoP module.

###  Stuff That Might Break
- Renamed `syncMode` to `mode` – update your configs or it’s toast.
- Swapped `/v1/nodes` endpoint for `/v2/nodes` – fix your scripts.

Tip: Write so users get what to do. If it’s a pain, ask the team in chat for help.

 What We Ship
Each release needs a few files so users can run Hemi. Here’s what to build:

Docker image: docker build -t hemilabs/hemi:<VERSION> . && docker push hemilabs/hemi:<VERSION> – gets you hemilabs/hemi:<VERSION>.
Linux binary: make build-linux – spits out ./bin/hemi-<VERSION>-linux-amd64.
Helm chart (if needed): helm package ./charts/hemi – makes hemi-<VERSION>.tgz.

Tip: If a command fails, don’t freak, just ping the team.

How to Push a Release
Step-by-step, no confusion:

Check the code: Run make test. All green? Sweet. If not, yell for the team.
Bump the version: Grab bump2version (pip install bump2version), then bump2version <major|minor|patch>. Updates VERSION and tags. Push it: git push && git push --tags.
Write the changelog: Open CHANGELOG.md, slap in a new section like above. Keep it clear, don’t bore people.
Build artifacts: Run the Docker, binary, and Helm commands. Make sure it all works.
Post the release: On GitHub, go to “Releases,” hit “Create a new release.” Add the tag (like v2.0.0), paste the changelog, attach the binary and Helm chart.
Shout it out: Tell the team in chat or tweet: “Dropped 2.0.0, check what’s new!”

Tip: Stuck somewhere? It’s not the end of the world, hit up the team chat.

Tools to Save Your Butt

Versions: bump2version – saves you from manual edits.
Tests: Set up GitHub Actions to auto-check code.
Changelog: Write it yourself or mess with git-chglog if you’re feeling fancy.


 If It All Goes to Hell

Bug in the release? Push a patch (2.0.1) to fix it.
Lost on a step? Ask in chat or the Issue, no shame.
Users whining? Check the changelog – did you explain how to update?


This is a simple way to drop releases without losing your mind. Got questions? 
