#!/bin/sh
# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

set -e

#
# hemilabs/heminetwork release script
#
# Tags the latest remote commit in the heminetwork repository's main branch and
# pushes the tag to the repository, triggering the release CI which will build
# all necessary binaries, Docker images, etc. and create a GitHub release.
#
# This script will create a new remote called 'upstream' (configurable with
# REMOTE_NAME). This remote is used to fetch the latest commit on the main
# branch, allowing a tag to be created on the latest remote commit while
# ignoring any local changes.
#
# The provided version (and all version bumps) must follow the Semantic
# Versioning 2.0.0 specification (<major>.<minor>.<patch>), as per
# https://semver.org/. This allows the versioning to stay consistent while
# easily communicating the type of change the version contains to users.
#
# This script will always confirm with you before creating or pushing the tag,
# in an attempt to prevent accidental tag creation or pushes.
#
# Usage:
#   release.sh <version>
#
# Environment variables:
#   DRY_RUN - If set to `true`, the script will not create or push any tags.
#
# Requirements:
#   - git (configured correctly)
#   - gpg (and git configured to use signing key)
#   - ssh (and key with access to repository)
#   - grep
#   - sed
#

REPOSITORY="https://github.com/hemilabs/heminetwork"
REMOTE_NAME=${REMOTE_NAME:-"upstream"}
REMOTE_URL=${REMOTE_URL:-"git+ssh://git@github.com/hemilabs/heminetwork.git"}
BRANCH_NAME="main"

log() {
	echo "release: $*"
}

fatal() {
	echo "release: $*" >&2
	exit 1
}

setup_remote() {
	log "setting up remote '$REMOTE_NAME' for $REMOTE_URL"

	if ! git remote get-url "$REMOTE_NAME" >/dev/null 2>&1; then
		log "remote '$REMOTE_NAME' does not exist, adding with URL $REMOTE_URL"
		git remote add "$REMOTE_NAME" "$REMOTE_URL" || \
			fatal "failed to add remote '$REMOTE_NAME'"
		return
	fi

	old_remote_url="$(git remote get-url "$REMOTE_NAME")"
	if [ "$old_remote_url" != "$REMOTE_URL" ]; then
		log "remote '$REMOTE_NAME' exists with unexpected URL: $old_remote_url"

		if ! confirm "Override remote '$REMOTE_NAME' URL with $REMOTE_URL"; then
			fatal "remote URL override aborted"
		fi
		git remote set-url "$REMOTE_NAME" "$REMOTE_URL" || \
			fatal "failed to set remote '$REMOTE_NAME' URL"
		return
	fi

	log "remote '$REMOTE_NAME' already exists with URL $REMOTE_URL"
}

fetch_branch() {
	log "fetching $REMOTE_NAME/$BRANCH_NAME"
	git fetch -q "$REMOTE_NAME" "$BRANCH_NAME" || \
		fatal "failed to fetch remote branch $REMOTE_NAME/$BRANCH_NAME"
	REF=$(git rev-parse --verify -q 'FETCH_HEAD') || \
		fatal "failed to verify FETCH_HEAD"
}

create_tag() {
	log "tagging $1 as $2"
	skip_dryrun git tag -a -s -m "$2" "$2" "$1"
}

push_tag() {
	log "pushing $1 to $REMOTE_NAME ($REMOTE_URL)"
	skip_dryrun git push "$REMOTE_NAME" "$1"
}

confirm() {
	echo
	printf "%s [y/N]? " "$1"
	read -r answer
	if [ "$answer" = "${answer#[Yy]}" ]; then
		return 1
	fi
	return 0
}

skip_dryrun() {
	if [ "$DRY_RUN" = true ]; then
		log "dry-run mode: skipping: $*"
		return
	fi
	"$@"
}

print_success() {
	log "successfully pushed tag $1 to $REMOTE_NAME!"
	log "See workflow status: $REPOSITORY/actions/workflows/release.yml"
	log "see release (once workflow has finished): $REPOSITORY/releases/tag/$1"
}

# https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string
SEMVER_REGEX='^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$'

release() {
	VERSION=$(echo "$1" | sed -e 's/^v//')
	TAG=$(echo "$1" | sed -E 's/^([^v])/v\1/g')
	if ! echo "$1" | grep -Eq "$SEMVER_REGEX"; then
		fatal "invalid version: $1. must be in semver format: https://semver.org/"
	fi
	TYPE='unstable'
	if echo "$VERSION" | grep -Eq '^[1-9][0-9]*\.[0-9]+\.[0-9]+$'; then
		TYPE='stable'
	fi

	# Setup remote and fetch main branch
	setup_remote
	fetch_branch

	# Create tag
	git --no-pager show "$REF" --pretty=fuller --show-signature --no-patch
	if ! confirm "Do you want to tag $REF as $TAG ($TYPE)"; then
		fatal "tagging aborted"
	fi
	create_tag "$REF" "$TAG"

	# Push tag
	skip_dryrun git --no-pager show "$TAG" --pretty=fuller --show-signature --no-patch
	if ! confirm "Do you want to push tag $TAG ($TYPE) to $REMOTE_NAME ($REMOTE_URL)"; then
		fatal "push aborted"
	fi
	push_tag "$TAG"

	skip_dryrun print_success "$TAG"
}

if [ $# -ne 1 ]; then
	echo "usage: $0 <version>"
	exit 1
fi

if [ "$DRY_RUN" = true ]; then
	log "running in dry-run mode. tags will not be created or pushed"
fi

release "$1"
