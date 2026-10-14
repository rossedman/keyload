#!/usr/bin/env bash
# Tags a release: make release VERSION=vX.Y.Z
#
# Creates vX.Y.Z and grpccreds/vX.Y.Z on the head of origin/main and pushes
# both in one go. Pushing the tags starts the Release workflow, which publishes
# the GitHub release with the CHANGELOG.md section as its notes.
#
# Tags are created here, not by the workflow, because the repository's tag
# ruleset only lets the maintainer create tags.
set -euo pipefail

tag="${1:-}"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || {
	echo "usage: make release VERSION=vX.Y.Z" >&2
	exit 1
}

git fetch --quiet origin main --tags
commit=$(git rev-parse origin/main)

# Check the files as they are on origin/main, not in the working tree.
git show "$commit:CHANGELOG.md" | grep -q "^## \[${tag#v}\]" || {
	echo "CHANGELOG.md on origin/main has no '## [${tag#v}]' section. Add it and merge first." >&2
	exit 1
}
git show "$commit:grpccreds/go.mod" | grep -q "github.com/rossedman/keyload $tag\$" || {
	echo "grpccreds/go.mod on origin/main does not require keyload $tag. Run 'make bump VERSION=$tag' and merge first." >&2
	exit 1
}

push=()
for t in "$tag" "grpccreds/$tag"; do
	if git rev-parse -q --verify "refs/tags/$t" >/dev/null; then
		existing=$(git rev-list -n1 "$t")
		[ "$existing" = "$commit" ] || {
			echo "$t already exists on ${existing:0:7}, not on origin/main (${commit:0:7})." >&2
			exit 1
		}
		echo "$t already exists on ${commit:0:7}"
		continue
	fi
	git tag -a "$t" -m "keyload $t" "$commit"
	push+=("refs/tags/$t")
done

if [ ${#push[@]} -eq 0 ]; then
	echo "Nothing to push."
	exit 0
fi
git push --atomic origin "${push[@]}"
echo "Pushed ${push[*]#refs/tags/} on ${commit:0:7}."
if [[ " ${push[*]} " == *" refs/tags/$tag "* ]]; then
	echo "The Release workflow is publishing the release:"
else
	echo "$tag was already there, so the Release workflow didn't start. To publish or refresh"
	echo "the release, run it from the Actions tab with $tag:"
fi
echo "  https://github.com/rossedman/keyload/actions/workflows/release.yml"
