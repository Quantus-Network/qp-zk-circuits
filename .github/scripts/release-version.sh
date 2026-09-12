#!/usr/bin/env bash
set -euo pipefail

pattern='^ci: Automate workspace version bump to (v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))$'
if [[ ! "$PR_TITLE" =~ $pattern ]]; then
	echo "::error::Invalid release proposal title" >&2
	exit 1
fi
version=${BASH_REMATCH[1]}
if [[ "$IS_DRAFT" != true && "$IS_DRAFT" != false ]]; then
	echo "::error::Invalid draft-release flag" >&2
	exit 1
fi
printf 'version=%s\nis_draft=%s\n' "$version" "$IS_DRAFT" >> "$GITHUB_OUTPUT"
