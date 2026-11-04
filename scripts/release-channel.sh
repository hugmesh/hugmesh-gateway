#!/usr/bin/env bash
# Decides what one run of .github/workflows/release.yml may publish, from the
# ref that started it. The release channel comes from the TAG, never from a
# setting:
#
#   ref                      version in the file   result
#   refs/heads/main          any valid version     kind=main    :main + :sha-<12>
#   refs/heads/release/X.Y   X.Y.*                 kind=branch  :sha-<12> only
#   refs/tags/vX.Y.Z-beta.N  X.Y.Z-beta.N          kind=release channel=beta
#                                                  :X.Y.Z-beta.N + :beta + :sha-<12>
#                                                  (the commit must be on main)
#   refs/tags/vX.Y.Z         X.Y.Z                 kind=release channel=stable
#                                                  :X.Y.Z + :sha-<12>, plus
#                                                  :X.Y     if no newer vX.Y.* is published
#                                                  :latest  if no newer v*.*.* is published
#                                                  (the commit must be on release/X.Y)
#   anything else            -                     refused
#
# "Newer" is decided with sort -V over the repository's own stable tags
# (vMAJOR.MINOR.PATCH, read from the remote with ls-remote), ignoring the tag
# being released. "Published" means the image :A.B.C is in the registry, so a
# refused or mistaken stable tag, which never got an image, holds nothing back.
# So a patch on the newest stable line moves :X.Y and :latest, a patch on an
# older line moves :X.Y but not :latest, and re-running an old stable release
# never moves :X.Y or :latest backwards. A beta never moves :X.Y or :latest.
# :X.Y.Z itself is immutable (the workflow's overwrite guard). :beta has no such
# check: it follows the most recent beta run.
#
# The answer goes stale, because a newer stable can publish after this runs. A
# "Re-run failed jobs" also reuses the outputs of a version job that passed. So
# the workflow runs this script again in the image job right before the push
# and in the github-release job right before gh release create, and those two
# answers are the only ones it acts on. The version job's run only refuses early.
#
# Input (environment): VERSION (already read from the version file),
# GITHUB_REF, GITHUB_SHA, IMAGE_NAME; optional VERSION_FILE (named in error
# messages) and RELEASE_REMOTE (default origin). It must run inside a git
# checkout with full history whose RELEASE_REMOTE is the GitHub repository.
# It asks ghcr.io with curl and an anonymous pull token, so it needs no docker
# and no login (it may run on a self-hosted runner). It contacts the registry
# only when a newer stable tag exists.
#
# Output (stdout, GITHUB_OUTPUT format): version, kind, channel, line, sha12,
# move_minor, move_latest and the multi-line image_tags. Every refusal is a
# ::error:: line on stderr and a non-zero exit, before anything is published.
#
# Tested by scripts/test-release-channel.sh, which the version job runs first.
set -euo pipefail

die() {
  echo "::error::$*" >&2
  exit 1
}

remote="${RELEASE_REMOTE:-origin}"
version_file="${VERSION_FILE:-the version file}"
version="${VERSION:?VERSION is not set}"
ref="${GITHUB_REF:?GITHUB_REF is not set}"
sha="${GITHUB_SHA:?GITHUB_SHA is not set}"
image="${IMAGE_NAME:?IMAGE_NAME is not set}"

if [[ ! "$version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-beta\.[1-9][0-9]*)?$ ]]; then
  die "version '$version' is not MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-beta.N"
fi
line="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
# Peel to the commit (a signed tag is an annotated tag object).
sha="$(git rev-parse --verify --quiet "$sha^{commit}")" ||
  die "$GITHUB_SHA is not a commit in this checkout"
sha12="${sha:0:12}"

# commit_on_branch BRANCH: exit 0 when $sha is on $remote's BRANCH, 1 when it
# is not. Refuses (exit via die) when the branch is missing or unreadable, so
# a network error can never pass for "on the branch".
commit_on_branch() {
  local branch rc
  branch="$1"
  rc=0
  git ls-remote --exit-code --heads "$remote" "refs/heads/$branch" >/dev/null || rc=$?
  if [ "$rc" = 2 ]; then
    return 3
  elif [ "$rc" != 0 ]; then
    die "could not read branch $branch from $remote (git ls-remote exit $rc)"
  fi
  git fetch --quiet --no-tags "$remote" "+refs/heads/$branch:refs/remotes/$remote/$branch" ||
    die "could not fetch branch $branch from $remote"
  rc=0
  git merge-base --is-ancestor "$sha" "refs/remotes/$remote/$branch" || rc=$?
  case "$rc" in
    0) return 0 ;;
    1) return 1 ;;
    *) die "git merge-base could not compare $sha with $branch (exit $rc)" ;;
  esac
}

# stable_versions: every vMAJOR.MINOR.PATCH tag on $remote, without the "v",
# one per line. Beta tags and other names are ignored.
stable_versions() {
  local listing
  listing="$(git ls-remote --tags --refs "$remote" 'v*')" ||
    die "could not list the v* tags of $remote"
  printf '%s\n' "$listing" |
    sed -n 's#^[0-9a-f]*[[:space:]][[:space:]]*refs/tags/v\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)$#\1#p'
}

# is_newest CANDIDATE OTHERS: exit 0 when no version in OTHERS (one per line)
# sorts after CANDIDATE with sort -V.
is_newest() {
  local top
  top="$(printf '%s\n%s\n' "$2" "$1" | sed '/^$/d' | sort -V | tail -n 1)"
  [ "$top" = "$1" ]
}

# image_published VERSION: exit 0 when $image:VERSION is in the registry, 1 when
# the registry says it is not. Any other answer refuses (exit via die), so an
# outage can never pass for "not published" and move a floating tag backwards.
image_published() {
  local repo
  local token
  local code
  case "$image" in
    ghcr.io/*) repo="${image#ghcr.io/}" ;;
    *) die "cannot ask the registry about $image: only ghcr.io images are supported" ;;
  esac
  token="$(curl -fsS --retry 2 --max-time 30 "https://ghcr.io/token?scope=repository:$repo:pull" |
    sed -n 's/.*"token":"\([^"]*\)".*/\1/p')" ||
    die "could not get a pull token for $image from ghcr.io, so could not tell whether $image:$1 is published"
  if [ -z "$token" ]; then
    die "ghcr.io gave no pull token for $image, so could not tell whether $image:$1 is published"
  fi
  code="$(curl -sS --retry 2 --max-time 30 -o /dev/null -w '%{http_code}' -I \
    -H "Authorization: Bearer $token" \
    -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json' \
    "https://ghcr.io/v2/$repo/manifests/$1")" ||
    die "could not ask ghcr.io whether $image:$1 is published"
  case "$code" in
    200) return 0 ;;
    404) return 1 ;;
    *) die "could not tell whether $image:$1 is published: ghcr.io answered HTTP $code" ;;
  esac
}

channel=none
move_minor=false
move_latest=false

case "$ref" in
  refs/heads/main)
    kind=main
    tags="$image:main"
    ;;
  refs/heads/release/*)
    branch="${ref#refs/heads/}"
    if [[ ! "$branch" =~ ^release/([0-9]+)\.([0-9]+)$ ]]; then
      die "refusing to publish from $ref: a release branch is named release/X.Y (for example release/0.3); nothing else under release/ publishes"
    fi
    if [ "${BASH_REMATCH[1]}.${BASH_REMATCH[2]}" != "$line" ]; then
      die "$branch carries version $version in $version_file; a release/X.Y branch must carry an X.Y.* version (this one belongs on release/$line)"
    fi
    kind=branch
    tags=""
    ;;
  refs/tags/v*)
    tag="${ref#refs/tags/}"
    if [ "${tag#v}" != "$version" ]; then
      die "tag $tag does not match $version_file version $version"
    fi
    kind=release
    rc=0
    case "$version" in
      *-*)
        channel=beta
        commit_on_branch main || rc=$?
        if [ "$rc" = 3 ]; then
          die "beta tag $tag needs branch main on $remote, which does not exist"
        elif [ "$rc" != 0 ]; then
          die "beta tag $tag points at $sha, which is not on main. A beta tag (vX.Y.Z-beta.N) is cut from main only; a stable tag (vX.Y.Z) is cut from release/X.Y."
        fi
        tags="$image:$version"$'\n'"$image:beta"
        ;;
      *)
        channel=stable
        commit_on_branch "release/$line" || rc=$?
        if [ "$rc" = 3 ]; then
          die "stable tag $tag needs branch release/$line on $remote, which does not exist. A stable tag (vX.Y.Z) is cut from release/X.Y only; a beta tag (vX.Y.Z-beta.N) is cut from main."
        elif [ "$rc" != 0 ]; then
          die "stable tag $tag points at $sha, which is not on release/$line. A stable tag (vX.Y.Z) is cut from release/X.Y only, never from main or another line; a beta tag (vX.Y.Z-beta.N) is cut from main."
        fi
        all="$(stable_versions)"
        # Only a newer tag can hold a floating tag back, and only if its image
        # exists. A stable tag that was refused, or never finished, has none.
        newer_published=""
        while IFS= read -r other; do
          [ -n "$other" ] || continue
          if is_newest "$version" "$other"; then
            continue
          fi
          if image_published "$other"; then
            newer_published="$newer_published$other"$'\n'
          fi
        done <<<"$all"
        same_line="$(printf '%s' "$newer_published" | awk -v p="$line." 'index($0, p) == 1')"
        if [ -z "$same_line" ]; then
          move_minor=true
        fi
        if [ -z "$newer_published" ]; then
          move_latest=true
        fi
        tags="$image:$version"
        if [ "$move_minor" = true ]; then
          tags="$tags"$'\n'"$image:$line"
        fi
        if [ "$move_latest" = true ]; then
          tags="$tags"$'\n'"$image:latest"
        fi
        ;;
    esac
    ;;
  *)
    die "refusing to publish from $ref (only main, release/X.Y branches and v* tags publish)"
    ;;
esac

if [ -n "$tags" ]; then
  tags="$tags"$'\n'"$image:sha-$sha12"
else
  tags="$image:sha-$sha12"
fi

echo "version=$version"
echo "kind=$kind"
echo "channel=$channel"
echo "line=$line"
echo "sha12=$sha12"
echo "move_minor=$move_minor"
echo "move_latest=$move_latest"
echo "image_tags<<EOF_IMAGE_TAGS"
echo "$tags"
echo "EOF_IMAGE_TAGS"
