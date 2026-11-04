#!/usr/bin/env bash
# Tests for scripts/release-channel.sh and for the parts of
# .github/workflows/release.yml that depend on it. Needs bash, git, python3,
# sed, sha256sum and sort -V; no network and no docker (the "remote" is a bare
# repository in a temp directory; curl, docker and gh are stubs on PATH that
# answer the way ghcr.io and real buildx were measured to). Run by the release
# workflow's version job before it decides anything; run locally with:
# bash scripts/test-release-channel.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
script="$here/release-channel.sh"
workflow="$root/.github/workflows/release.yml"
image="$(sed -n 's/^  IMAGE_NAME: *//p' "$workflow")"
if [ -z "$image" ]; then
  echo "FAIL: no env IMAGE_NAME in $workflow" >&2
  exit 1
fi

work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/release-channel-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok   $*"; }
bad() { fail=$((fail + 1)); echo "FAIL $*"; }

g() {
  git -C "$work/clone" -c user.name=test -c user.email=test@example.invalid \
    -c commit.gpgsign=false -c tag.gpgsign=false "$@"
}

# --- fixture -----------------------------------------------------------------
# main:        m1(0.2.0-beta.1) - m2(0.3.0-beta.1) - m5(0.4.0-beta.1) - m6(0.5.0-beta.1)
# release/0.2: m1 - r20(0.2.0)
# release/0.3: m2 - r30(0.3.0) - r31(0.3.1) - r32(0.3.2)
# release/0.4: m5 - r40(0.4.0) - r41(0.4.1)
# release/0.9 and release/0.10 for the sort -V check.
# Stable tags already on the remote: v0.2.0, v0.3.0, v0.3.1, v0.4.0.
git init -q --bare "$work/origin.git"
git init -q -b main "$work/clone"
g remote add origin "$work/origin.git"

commit() { # commit MESSAGE -> prints the sha
  g commit -q --allow-empty -m "$1"
  g rev-parse HEAD
}

m1="$(commit 'main 0.2.0-beta.1')"
m2="$(commit 'main 0.3.0-beta.1')"
g checkout -q -b release/0.2 "$m1"
r20="$(commit 'release 0.2.0')"
g checkout -q -b release/0.3 "$m2"
r30="$(commit 'release 0.3.0')"
r31="$(commit 'release 0.3.1')"
r32="$(commit 'release 0.3.2')"
r3b="$(commit 'release/0.3 commit that is not on main')"
g checkout -q main
m5="$(commit 'main 0.4.0-beta.1')"
g checkout -q -b release/0.4 "$m5"
r40="$(commit 'release 0.4.0')"
r41="$(commit 'release 0.4.1')"
g checkout -q main
m6="$(commit 'main 0.5.0-beta.1')"
g checkout -q -b release/0.9 "$m6"
r90="$(commit 'release 0.9.0')"
g checkout -q -b release/0.10 "$m6"
r100="$(commit 'release 0.10.0')"
g checkout -q -b release/attest-something "$m6"
g checkout -q main
g tag v0.2.0 "$r20"
g tag v0.3.0 "$r30"
g tag v0.3.1 "$r31"
g tag v0.4.0 "$r40"
g tag v0.5.0-beta.1 "$m6"
g tag not-a-version "$m6"
g push -q origin main release/0.2 release/0.3 release/0.4 release/0.9 release/0.10 release/attest-something
g push -q origin --tags
# The workflow's steps call the script by its path in the checkout.
mkdir -p "$work/clone/scripts"
cp "$script" "$work/clone/scripts/release-channel.sh"

# --- stubs -------------------------------------------------------------------
# $reg/published  image tags the registry has, one per line
# $reg/calls      every curl and gh call
# $reg/manifests/ one file per tag: the manifest bytes docker --raw prints
# $reg/token-denied, $reg/manifest-500: make the registry misbehave
reg="$work/registry"
mkdir -p "$reg/manifests" "$work/bin"
: >"$reg/calls"
printf '%s\n' 0.2.0 0.3.0 0.3.1 0.4.0 >"$reg/published"

cat >"$work/bin/curl" <<'STUB'
#!/usr/bin/env bash
# Answers as ghcr.io does: 403 for a token it refuses, 200/404 for a manifest.
echo "curl $*" >>"$STUB_REG/calls"
url="${*: -1}"
case "$url" in
  https://ghcr.io/token\?scope=repository:*:pull)
    if [ -e "$STUB_REG/token-denied" ]; then
      echo "curl: (22) The requested URL returned error: 403" >&2
      exit 22
    fi
    echo '{"token":"anonymous"}'
    ;;
  https://ghcr.io/v2/*/manifests/*)
    if [ -e "$STUB_REG/manifest-500" ]; then
      printf 500
    elif grep -Fx -e "${url##*/}" "$STUB_REG/published" >/dev/null; then
      printf 200
    else
      printf 404
    fi
    ;;
  *)
    echo "stub curl: unexpected URL $url" >&2
    exit 2
    ;;
esac
STUB

cat >"$work/bin/docker" <<'STUB'
#!/usr/bin/env bash
# Answers as real buildx v0.31.0 does: --raw prints the manifest's exact bytes;
# a format that starts with {{.Manifest prints the listing, not the field.
if [ "$1 $2 $3" != "buildx imagetools inspect" ]; then
  echo "stub docker: unexpected $*" >&2
  exit 2
fi
ref="$4"
if [ -e "$STUB_REG/inspect-denied" ]; then
  echo "ERROR: failed to authorize: 403 Forbidden" >&2
  exit 1
fi
file="$STUB_REG/manifests/${ref##*:}"
if [ ! -e "$file" ]; then
  echo "ERROR: $ref: not found" >&2
  exit 1
fi
hash="$(sha256sum "$file")"
digest="sha256:${hash%% *}"
case "$5 $6" in
  "--raw ") cat "$file" ;;
  "--format {{json .Manifest.Digest}}") printf '"%s"\n' "$digest" ;;
  *) printf 'Name:      %s\nMediaType: application/vnd.oci.image.index.v1+json\nDigest:    %s\n' "$ref" "$digest" ;;
esac
STUB

cat >"$work/bin/gh" <<'STUB'
#!/usr/bin/env bash
echo "gh $*" >>"$STUB_REG/calls"
case "$1 $2" in
  "release view") exit 1 ;;
  "release create") exit 0 ;;
esac
echo "stub gh: unexpected $*" >&2
exit 2
STUB
chmod +x "$work/bin/curl" "$work/bin/docker" "$work/bin/gh"
export STUB_REG="$reg"

published() { # published VERSION...: the registry now has these images
  printf '%s\n' "$@" >>"$reg/published"
}
unpublished() { # unpublished VERSION: the registry no longer has this image
  grep -Fxv -e "$1" "$reg/published" >"$reg/published.new" || true
  mv "$reg/published.new" "$reg/published"
}

# run_case NAME VERSION REF SHA -> sets $out, $err, $rc
run_case() {
  rc=0
  out="$(cd "$work/clone" && PATH="$work/bin:$PATH" VERSION="$2" GITHUB_REF="$3" GITHUB_SHA="$4" \
    IMAGE_NAME="$image" VERSION_FILE=pom.xml bash "$script" 2>"$work/err")" || rc=$?
  err="$(cat "$work/err")"
}

field() { # field KEY -> value of KEY in $out
  printf '%s\n' "$out" | sed -n "s/^$1=//p"
}

image_tags() { # the image_tags block of $out, tag names only, sorted, space separated
  printf '%s\n' "$out" |
    sed -n '/^image_tags<<EOF_IMAGE_TAGS$/,/^EOF_IMAGE_TAGS$/p' |
    sed '1d;$d' | sed "s#^$image:##" | sort | tr '\n' ' ' | sed 's/ $//'
}

expect_ok() { # expect_ok NAME KIND CHANNEL MOVE_MINOR MOVE_LATEST "TAGS"
  local name
  name="$1"
  if [ "$rc" != 0 ]; then
    bad "$name: exit $rc: $err"
    return
  fi
  local got
  got="kind=$(field kind) channel=$(field channel) move_minor=$(field move_minor) move_latest=$(field move_latest) tags=[$(image_tags)]"
  local want
  want="kind=$2 channel=$3 move_minor=$4 move_latest=$5 tags=[$6]"
  if [ "$got" = "$want" ]; then
    ok "$name"
  else
    bad "$name: got $got; want $want"
  fi
}

expect_refused() { # expect_refused NAME TEXT-IN-ERROR
  if [ "$rc" = 0 ]; then
    bad "$1: accepted, want refusal; output: $out"
    return
  fi
  case "$err" in
    *"::error::"*"$2"*) ok "$1" ;;
    *) bad "$1: refused without '$2': $err" ;;
  esac
}

s12() { printf '%s' "${1:0:12}"; }

# --- the required cases ------------------------------------------------------
# A signed stable tag is an annotated tag object; GITHUB_SHA may name it.
g tag -a -m 'annotated' v0.4.1-object "$r41"
run_case "annotated tag object" 0.4.1 refs/tags/v0.4.1 "$(g rev-parse v0.4.1-object)"
expect_ok "an annotated tag object is peeled to its commit" release stable true true \
  "0.4 0.4.1 latest sha-$(s12 "$r41")"
g tag -d v0.4.1-object >/dev/null

run_case "not a commit" 0.4.1 refs/tags/v0.4.1 "$(printf '%040d' 0)"
expect_refused "an unknown GITHUB_SHA is refused" "is not a commit in this checkout"

run_case "beta tag on main" 0.5.0-beta.1 refs/tags/v0.5.0-beta.1 "$m6"
expect_ok "beta tag on main -> :X.Y.Z-beta.N + :beta, no :X.Y/:latest" release beta false false \
  "0.5.0-beta.1 beta sha-$(s12 "$m6")"

run_case "stable, newest line" 0.4.1 refs/tags/v0.4.1 "$r41"
expect_ok "stable on release/0.4, newest line -> :X.Y.Z + :X.Y + :latest" release stable true true \
  "0.4 0.4.1 latest sha-$(s12 "$r41")"

run_case "stable, older-line patch" 0.3.2 refs/tags/v0.3.2 "$r32"
expect_ok "stable older-line patch on release/0.3 -> :X.Y moves, :latest does not" release stable true false \
  "0.3 0.3.2 sha-$(s12 "$r32")"

run_case "stable tag on main" 0.5.0 refs/tags/v0.5.0 "$m6"
expect_refused "stable tag on a main commit (no release/0.5) is refused" "needs branch release/0.5"
run_case "stable tag on main, line branch exists" 0.4.2 refs/tags/v0.4.2 "$m6"
expect_refused "stable tag on a main commit that release/0.4 lacks is refused" "is not on release/0.4"

run_case "beta tag on a release branch" 0.3.3-beta.1 refs/tags/v0.3.3-beta.1 "$r3b"
expect_refused "beta tag on a release/X.Y-only commit is refused" "is not on main"

# --- more stable-line rules --------------------------------------------------
run_case "first stable of a line, newest" 0.10.0 refs/tags/v0.10.0 "$r100"
expect_ok "sort -V: 0.10.0 is newer than 0.9.x and 0.4.x" release stable true true \
  "0.10 0.10.0 latest sha-$(s12 "$r100")"

# Pretend v0.10.0 is published, then cut 0.9.0: an older line by sort -V.
g tag v0.10.0 "$r100"
g push -q origin v0.10.0
published 0.10.0
run_case "older line by sort -V" 0.9.0 refs/tags/v0.9.0 "$r90"
expect_ok "sort -V: 0.9.0 is older than 0.10.0 -> no :latest" release stable true false \
  "0.9 0.9.0 sha-$(s12 "$r90")"
g push -q origin :refs/tags/v0.10.0
g tag -d v0.10.0 >/dev/null
unpublished 0.10.0

run_case "rerun of an old patch" 0.3.0 refs/tags/v0.3.0 "$r30"
expect_ok "re-running v0.3.0 after v0.3.1 moves no floating tag" release stable false false \
  "0.3.0 sha-$(s12 "$r30")"

run_case "beta tags ignored for :latest" 0.4.1 refs/tags/v0.4.1 "$r41"
expect_ok "a newer beta tag (v0.5.0-beta.1) does not take :latest from a stable" release stable true true \
  "0.4 0.4.1 latest sha-$(s12 "$r41")"

run_case "stable without its release branch" 0.6.0 refs/tags/v0.6.0 "$m6"
expect_refused "stable tag whose release/X.Y does not exist is refused" "release/0.6"

run_case "stable on the wrong line" 0.3.3 refs/tags/v0.3.3 "$r41"
expect_refused "stable tag on another line's branch is refused" "is not on release/0.3"

run_case "tag does not match version" 0.4.1 refs/tags/v0.4.2 "$r41"
expect_refused "tag must equal v + version" "does not match pom.xml version 0.4.1"

run_case "bad version" 0.4.1-rc.1 refs/tags/v0.4.1-rc.1 "$r41"
expect_refused "only X.Y.Z and X.Y.Z-beta.N are versions" "is not MAJOR.MINOR.PATCH"

# --- branch pushes -----------------------------------------------------------
run_case "push to main" 0.5.0-beta.1 refs/heads/main "$m6"
expect_ok "push to main -> :main + :sha" main none false false "main sha-$(s12 "$m6")"

run_case "push to release/0.3" 0.3.2 refs/heads/release/0.3 "$r32"
expect_ok "push to release/X.Y -> :sha only, no floating tag" branch none false false "sha-$(s12 "$r32")"

run_case "push to release/<not X.Y>" 0.5.0-beta.1 refs/heads/release/attest-something "$m6"
expect_refused "release/<not X.Y> is refused" "a release branch is named release/X.Y"

run_case "release branch with another line's version" 0.4.1 refs/heads/release/0.3 "$r32"
expect_refused "release/0.3 carrying 0.4.1 is refused" "must carry an X.Y.* version"

run_case "other branch" 0.5.0-beta.1 refs/heads/feature/x "$m6"
expect_refused "other branches are refused" "only main, release/X.Y branches and v* tags publish"

(cd "$work/clone" && git remote set-url origin "$work/nowhere.git")
run_case "unreadable remote" 0.4.1 refs/tags/v0.4.1 "$r41"
expect_refused "an unreadable remote fails closed" "could not read branch release/0.4"
(cd "$work/clone" && git remote set-url origin "$work/origin.git")

# --- only a published stable tag holds a floating tag back ---------------------
: >"$reg/calls"
run_case "newest, no newer tag" 0.4.1 refs/tags/v0.4.1 "$r41"
if [ -s "$reg/calls" ]; then
  bad "a stable with no newer tag does not contact the registry: $(cat "$reg/calls")"
else
  ok "a stable with no newer tag does not contact the registry"
fi

run_case "beta" 0.5.0-beta.1 refs/tags/v0.5.0-beta.1 "$m6"
if [ -s "$reg/calls" ]; then
  bad "a beta does not contact the registry: $(cat "$reg/calls")"
else
  ok "a beta does not contact the registry"
fi

# A mistaken stable tag on the remote: its run was refused, so it has no image.
g tag v0.9.9 "$m6"
g tag v0.4.7 "$r41"
g push -q origin v0.9.9 v0.4.7
run_case "mistaken newer tags" 0.4.1 refs/tags/v0.4.1 "$r41"
expect_ok "stable tags that never published do not hold back :X.Y or :latest" release stable true true \
  "0.4 0.4.1 latest sha-$(s12 "$r41")"

published 0.9.9
run_case "newer line now published" 0.4.1 refs/tags/v0.4.1 "$r41"
expect_ok "once the newer line publishes, :latest stays and :X.Y still moves" release stable true false \
  "0.4 0.4.1 sha-$(s12 "$r41")"

published 0.4.7
run_case "newer patch now published" 0.4.1 refs/tags/v0.4.1 "$r41"
expect_ok "once a newer patch publishes, neither :X.Y nor :latest moves" release stable false false \
  "0.4.1 sha-$(s12 "$r41")"
unpublished 0.9.9

touch "$reg/token-denied"
run_case "no pull token" 0.4.1 refs/tags/v0.4.1 "$r41"
expect_refused "a refused pull token fails closed, not 'not published'" "could not get a pull token"
rm "$reg/token-denied"

touch "$reg/manifest-500"
run_case "registry error" 0.4.1 refs/tags/v0.4.1 "$r41"
expect_refused "a registry error fails closed, not 'not published'" "answered HTTP 500"
rm "$reg/manifest-500"

unpublished 0.4.7
g push -q origin :refs/tags/v0.9.9 :refs/tags/v0.4.7
g tag -d v0.9.9 v0.4.7 >/dev/null

# 10.4.1 contains "0.4." but is on another line.
g tag v10.4.1 "$r41"
g push -q origin v10.4.1
published 10.4.1
run_case "a line whose name ends the same" 0.4.1 refs/tags/v0.4.1 "$r41"
expect_ok "a published 10.4.1 is not on the 0.4 line: :0.4 moves, :latest stays" release stable true false \
  "0.4 0.4.1 sha-$(s12 "$r41")"
unpublished 10.4.1
g push -q origin :refs/tags/v10.4.1
g tag -d v10.4.1 >/dev/null

# --- the workflow's steps, run from release.yml --------------------------------
# step_body NAME OUTFILE: writes the run: block of the step called NAME.
step_body() {
  python3 - "$workflow" "$1" "$2" <<'PY'
import sys, textwrap
lines = open(sys.argv[1]).read().split("\n")
start = next(i for i, l in enumerate(lines) if l.strip() == "- name: " + sys.argv[2])
begin = next(i for i in range(start, len(lines)) if lines[i].strip() == "run: |")
indent = len(lines[begin]) - len(lines[begin].lstrip())
end = begin + 1
while end < len(lines) and (not lines[end].strip() or len(lines[end]) - len(lines[end].lstrip()) > indent):
    end += 1
open(sys.argv[3], "w").write(textwrap.dedent("\n".join(lines[begin + 1:end])) + "\n")
PY
}
step_body "Compute tags and labels" "$work/meta.sh"
step_body "Create the GitHub release" "$work/release.sh"
step_body "Check every pushed tag resolves to the signed digest" "$work/digest.sh"

# run_step SCRIPT VERSION REF SHA [VAR=VALUE...] -> $step_rc, $step_out; GitHub's
# default shell. A stale MOVE_LATEST/IMAGE_TAGS, as a re-run's reused outputs
# would be, is set on purpose: nothing may read them.
run_step() {
  local file
  local version
  local ref
  local sha
  file="$1"; version="$2"; ref="$3"; sha="$4"
  shift 4
  : >"$work/gho"
  : >"$reg/calls"
  step_rc=0
  step_out="$(cd "$work/clone" && env PATH="$work/bin:$PATH" VERSION="$version" KIND=release \
    GITHUB_REF="$ref" GITHUB_REF_NAME="${ref##*/}" GITHUB_SHA="$sha" GITHUB_REPOSITORY=hugmesh/test \
    IMAGE_NAME="$image" GITHUB_OUTPUT="$work/gho" MOVE_LATEST=true IMAGE_TAGS="$image:latest" \
    COMMONS_VERSION=2.2.0 "$@" \
    bash --noprofile --norc -e "$file" 2>&1)" || step_rc=$?
}

pushed_tags() { # the tags the Compute step handed to the push, names only
  sed -n '/^tags<<EOF_TAGS$/,/^EOF_TAGS$/p' "$work/gho" | sed '1d;$d' |
    sed "s#^$image:##" | sort | tr '\n' ' ' | sed 's/ $//'
}

expect_meta() { # expect_meta NAME MOVE_LATEST "TAGS"
  local got
  local want
  got="rc=$step_rc move_latest=$(sed -n 's/^move_latest=//p' "$work/gho") tags=[$(pushed_tags)]"
  want="rc=0 move_latest=$2 tags=[$3]"
  if [ "$got" = "$want" ]; then ok "$1"; else bad "$1: got $got; want $want: $step_out"; fi
}

expect_release_flag() { # expect_release_flag NAME FLAG
  local created
  created="$(sed -n 's/^gh release create //p' "$reg/calls")"
  case " $created " in
    *" $2 "*) ok "$1" ;;
    *) bad "$1: rc=$step_rc, gh release create $created: $step_out" ;;
  esac
}

expect_no_release_flag() { # expect_no_release_flag NAME FLAG: gh release create ran without FLAG
  local created
  created="$(sed -n 's/^gh release create //p' "$reg/calls")"
  case " $created " in
    "  ") bad "$1: gh release create did not run: rc=$step_rc: $step_out" ;;
    *" $2 "*) bad "$1: gh release create $created" ;;
    *) ok "$1" ;;
  esac
}

# "Re-run failed jobs": v0.4.1's version job passed while it was the newest, a
# later job failed, then a newer line shipped, then the run was re-run.
run_step "$work/meta.sh" 0.4.1 refs/tags/v0.4.1 "$r41"
expect_meta "image job, first attempt: newest -> :X.Y + :latest" true "0.4 0.4.1 latest sha-$(s12 "$r41")"
run_step "$work/release.sh" 0.4.1 refs/tags/v0.4.1 "$r41"
expect_release_flag "github-release, first attempt: newest -> --latest" "--latest"
expect_no_release_flag "github-release, first attempt: newest is never also --latest=false" "--latest=false"
expect_no_release_flag "github-release, first attempt: a stable is not a prerelease" "--prerelease"

g tag v0.9.0 "$r90"
g push -q origin v0.9.0
published 0.9.0
run_step "$work/meta.sh" 0.4.1 refs/tags/v0.4.1 "$r41"
expect_meta "image job, re-run after a newer line shipped: :latest is not pushed" false "0.4 0.4.1 sha-$(s12 "$r41")"
run_step "$work/release.sh" 0.4.1 refs/tags/v0.4.1 "$r41"
expect_release_flag "github-release, re-run after a newer line shipped: --latest=false" "--latest=false"

g tag v0.4.2 "$r41"
g push -q origin v0.4.2
published 0.4.2
run_step "$work/meta.sh" 0.4.1 refs/tags/v0.4.1 "$r41"
expect_meta "image job, re-run after a newer patch shipped: :X.Y is not pushed either" false "0.4.1 sha-$(s12 "$r41")"
g push -q origin :refs/tags/v0.9.0 :refs/tags/v0.4.2
g tag -d v0.9.0 v0.4.2 >/dev/null
unpublished 0.9.0
unpublished 0.4.2

run_step "$work/meta.sh" 0.5.0-beta.1 refs/tags/v0.5.0-beta.1 "$m6"
expect_meta "image job, beta -> :X.Y.Z-beta.N + :beta + :sha" false "0.5.0-beta.1 beta sha-$(s12 "$m6")"
run_step "$work/release.sh" 0.5.0-beta.1 refs/tags/v0.5.0-beta.1 "$m6"
expect_release_flag "github-release, beta -> --prerelease" "--prerelease"
expect_release_flag "github-release, beta -> --latest=false" "--latest=false"

run_step "$work/meta.sh" 0.5.0-beta.1 refs/heads/main "$m6"
expect_meta "image job, push to main -> :main + :sha" false "main sha-$(s12 "$m6")"
run_step "$work/meta.sh" 0.3.2 refs/heads/release/0.3 "$r32"
expect_meta "image job, push to release/X.Y -> :sha only" false "sha-$(s12 "$r32")"

touch "$reg/manifest-500"
run_step "$work/meta.sh" 0.3.2 refs/tags/v0.3.2 "$r32"
if [ "$step_rc" != 0 ] && [ ! -s "$work/gho" ]; then
  ok "image job: a registry error stops the run before any tag is handed to the push"
else
  bad "image job: a registry error: rc=$step_rc, output: $(cat "$work/gho")"
fi
run_step "$work/release.sh" 0.3.2 refs/tags/v0.3.2 "$r32"
if [ "$step_rc" != 0 ] && [ -z "$(sed -n '/^gh release create /p' "$reg/calls")" ]; then
  ok "github-release: a registry error stops before the release is created"
else
  bad "github-release: a registry error: rc=$step_rc, calls: $(cat "$reg/calls")"
fi
rm "$reg/manifest-500"

# --- the overwrite guard, run as GitHub runs it (bash -e) ----------------------
# Only the immutable :X.Y.Z is inspected. buildx exits 1 for "not found", the
# normal answer for a first publish; under bash -e that must not end the step.
step_body "Refuse to overwrite a published version" "$work/exists.sh"
expect_exists() { # expect_exists NAME WANT-RC "TEXT" [skip]
  local skip
  skip="$(sed -n 's/^skip=//p' "$work/gho")"
  case "$step_rc:$step_out" in
    "$2:"*"$3"*)
      if [ -z "${4:-}" ] || [ "$skip" = "$4" ]; then ok "$1"; else bad "$1: skip=$skip: $step_out"; fi
      ;;
    *) bad "$1: rc=$step_rc: $step_out" ;;
  esac
}
run_step "$work/exists.sh" 0.4.1 refs/tags/v0.4.1 "$r41" GITHUB_EVENT_NAME=push
expect_exists "overwrite guard: an unpublished stable continues under bash -e" 0 "" false
run_step "$work/exists.sh" 0.5.0-beta.1 refs/tags/v0.5.0-beta.1 "$m6" GITHUB_EVENT_NAME=push
expect_exists "overwrite guard: an unpublished beta continues under bash -e" 0 "" false
printf 'published' >"$reg/manifests/0.3.2"
run_step "$work/exists.sh" 0.3.2 refs/tags/v0.3.2 "$r32" GITHUB_EVENT_NAME=push
expect_exists "overwrite guard: a published stable is refused (next patch on release/X.Y)" 1 \
  "$image:0.3.2 is already published. A published version is never overwritten: cut the next patch release from release/0.3"
run_step "$work/exists.sh" 0.3.2 refs/tags/v0.3.2 "$r32" GITHUB_EVENT_NAME=workflow_dispatch
expect_exists "overwrite guard: a manual re-run of a published version builds nothing" 0 "is already published" true
rm "$reg/manifests/0.3.2"
printf 'published' >"$reg/manifests/0.5.0-beta.1"
run_step "$work/exists.sh" 0.5.0-beta.1 refs/tags/v0.5.0-beta.1 "$m6" GITHUB_EVENT_NAME=push
expect_exists "overwrite guard: a published beta is refused (raise the beta number)" 1 "raise the beta number"
rm "$reg/manifests/0.5.0-beta.1"
touch "$reg/inspect-denied"
run_step "$work/exists.sh" 0.4.1 refs/tags/v0.4.1 "$r41" GITHUB_EVENT_NAME=push
expect_exists "overwrite guard: a registry error fails closed, not 'not published'" 1 "could not tell whether $image:0.4.1 exists"
rm "$reg/inspect-denied"
run_step "$work/exists.sh" 0.5.0-beta.1 refs/heads/main "$m6" GITHUB_EVENT_NAME=push KIND=main
expect_exists "overwrite guard: a branch run inspects nothing" 0 "" false

# --- the digest check, against what real buildx prints ------------------------
printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json"}' >"$reg/manifests/0.4.1"
cp "$reg/manifests/0.4.1" "$reg/manifests/latest"
signed_hash="$(sha256sum "$reg/manifests/0.4.1")"
signed="sha256:${signed_hash%% *}"
tag_refs="$image:0.4.1"$'\n'"$image:latest"

run_step "$work/digest.sh" 0.4.1 refs/tags/v0.4.1 "$r41" TAGS="$tag_refs" DIGEST="$signed"
if [ "$step_rc" = 0 ]; then
  ok "digest check passes when every tag resolves to the signed digest"
else
  bad "digest check on the right digest: $step_out"
fi

printf 'a concurrent run moved this tag' >"$reg/manifests/latest"
run_step "$work/digest.sh" 0.4.1 refs/tags/v0.4.1 "$r41" TAGS="$tag_refs" DIGEST="$signed"
case "$step_rc:$step_out" in
  1:*"latest resolves to sha256:"*"not the signed digest"*) ok "digest check fails when a tag resolves elsewhere" ;;
  *) bad "digest check on a moved tag: rc=$step_rc: $step_out" ;;
esac

rm "$reg/manifests/latest"
run_step "$work/digest.sh" 0.4.1 refs/tags/v0.4.1 "$r41" TAGS="$tag_refs" DIGEST="$signed"
case "$step_rc:$step_out" in
  1:*"could not read $image:latest"*) ok "digest check fails when a tag cannot be read" ;;
  *) bad "digest check on a missing tag: rc=$step_rc: $step_out" ;;
esac

# --- the workflow's signref guard agrees with the computed tags ---------------
# Extract the python of the "signref" step from release.yml and run it.
python3 - "$workflow" "$work/signref.py" <<'PY'
import sys, textwrap
lines = open(sys.argv[1]).read().split("\n")
start = next(i for i, l in enumerate(lines) if l.strip() == "id: signref")
begin = next(i for i in range(start, len(lines)) if lines[i].strip() == "python3 - <<'PY'")
end = next(i for i in range(begin + 1, len(lines)) if lines[i].strip() == "PY")
open(sys.argv[2], "w").write(textwrap.dedent("\n".join(lines[begin + 1:end])) + "\n")
PY

signref() { # signref VERSION MOVE_LATEST "pushed tags" "expected tags" -> rc
  local names expected t
  names=""
  for t in $3; do names="$names${names:+,}$image:$t"; done
  expected=""
  for t in $4; do expected="$expected$image:$t"$'\n'; done
  : >"$work/gho"
  VERSION="$1" MOVE_LATEST="$2" EXPECTED_TAGS="$expected" GITHUB_OUTPUT="$work/gho" \
    DIGEST="sha256:$(printf '%064d' 0)" METADATA="{\"image.name\": \"$names\"}" \
    python3 "$work/signref.py" >/dev/null 2>&1
}

expect_signref() { # expect_signref NAME WANT-RC VERSION MOVE_LATEST "pushed" ["expected"]
  local rc
  rc=0
  signref "$3" "$4" "$5" "${6:-$5}" || rc=$?
  if { [ "$2" = 0 ] && [ "$rc" = 0 ]; } || { [ "$2" != 0 ] && [ "$rc" != 0 ]; }; then
    ok "signref: $1"
  else
    bad "signref: $1 (exit $rc)"
  fi
}

expect_signref "stable newest line with :latest is signed" 0 0.4.1 true "0.4.1 0.4 latest sha-abc"
expect_signref "older-line patch without :latest is signed" 0 0.3.2 false "0.3.2 0.3 sha-abc"
expect_signref "beta with :beta is signed" 0 0.5.0-beta.1 false "0.5.0-beta.1 beta sha-abc"
expect_signref "main push is signed" 0 0.5.0-beta.1 false "main sha-abc"
expect_signref "beta with :latest is refused" 1 0.5.0-beta.1 true "0.5.0-beta.1 latest sha-abc"
expect_signref "older-line patch with :latest is refused" 1 0.3.2 false "0.3.2 latest sha-abc"
expect_signref "empty VERSION with :latest is refused" 1 "" true "0.4.1 latest sha-abc"
expect_signref "pushed tags differing from the computed tags are refused" 1 0.4.1 true \
  "0.4.1 0.4 latest sha-abc" "0.4.1 sha-abc"

# --- wiring: release.yml uses the script and keeps the guards -----------------
has() { # has NAME FIXED-STRING: the workflow contains the string
  if grep -F -e "$2" "$workflow" >/dev/null; then ok "workflow: $1"; else bad "workflow: $1 (missing: $2)"; fi
}
lacks() {
  if grep -F -e "$2" "$workflow" >/dev/null; then bad "workflow: $1 (found: $2)"; else ok "workflow: $1"; fi
}
has "push trigger includes release/**" "branches: [main, 'release/**']"
has "tag trigger is v*" "tags: ['v*']"
has "version job runs this self-test" "run: bash scripts/test-release-channel.sh"
has "version job calls release-channel.sh" "bash scripts/release-channel.sh)"
has "version regex still in the version job" "semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'"
has "SNAPSHOT check still in the version job" "is a SNAPSHOT; published versions never are"
has "hugmesh-commons pin check still in the version job" "the net.hugmesh:hugmesh-commons pin in pom.xml"
has "version job reads pom.xml" 'VERSION_FILE=pom.xml bash scripts/release-channel.sh)'
has "the version job still exports the hugmesh-commons pin" 'echo "commons_version=$commons_version"'
has "the org release script's channel marker" "hugmesh-release-channels: beta+stable"
lacks "no job reads the version job's tag list" 'needs.version.outputs.image_tags'
lacks "no job reads the version job's :latest answer" 'needs.version.outputs.move_latest'
lacks "no job reads the version job's :X.Y answer" 'needs.version.outputs.move_minor'
has "signref takes :latest from the check before the push" 'MOVE_LATEST: ${{ steps.meta.outputs.move_latest }}'
lacks "the digest check does not use a format buildx answers with a listing" '"$ref" --format'
has "the digest check hashes the manifest bytes" 'docker buildx imagetools inspect "$ref" --raw | sha256sum'
has "overwrite guard inspects the immutable :X.Y.Z" 'ref="$IMAGE_NAME:$VERSION"'
has "overwrite guard fails closed on an unknown error" 'could not tell whether $ref exists'
has "signref keeps the :latest literal" 'if "latest" in tags and ("-" in (os.environ.get("VERSION") or "-")'
has "signref compares pushed and computed tags" 'EXPECTED_TAGS: ${{ steps.meta.outputs.tags }}'
has "every pushed tag is checked against the signed digest" "Check every pushed tag resolves to the signed digest"
has "beta GitHub release is a prerelease, never Latest" "*-*) args+=(--prerelease --latest=false) ;;"
has "newest stable GitHub release is marked Latest" "args+=(--latest)"
has "older-line stable GitHub release is not Latest" "args+=(--latest=false)"
lacks "no pull_request trigger" "pull_request:"
lacks "no unconditional :latest refusal left" 'if "latest" in tags:'

# The tags are decided after the build and right before the push. The two later
# jobs need the script and its history, so both check out with full history.
python3 - "$workflow" >"$work/order" <<'PY'
import sys
lines = open(sys.argv[1]).read().split("\n")
def at(text, start=0):
    return next(i for i in range(start, len(lines)) if lines[i].strip() == text)
image = at("image:")
release = at("github-release:")
def full_history(start):
    co = at("uses: actions/checkout@v4", start)
    return lines[co + 1].strip() == "with:" and lines[co + 2].strip() == "fetch-depth: 0"
pre = at("- name: Build the image (no push)", image)
meta = at("- name: Compute tags and labels", image)
push = at("- name: Build and push image", image)
create = at("- name: Create the GitHub release", release)
checks = {
    "the image is built before the tags are decided": pre < meta,
    "the tags are decided in the step right before the push":
        meta < push and not any(l.strip().startswith("- name:") for l in lines[meta + 1:push]),
    "the first build pushes nothing": "push: false" in [l.strip() for l in lines[pre:meta]],
    "the image job checks out with full history": full_history(image),
    "github-release checks out with full history": full_history(release),
    "github-release decides again before gh release create":
        any("bash scripts/release-channel.sh" in l for l in lines[create:]),
}
for name, good in checks.items():
    print(("ok " if good else "bad") + " " + name)
PY
while IFS= read -r line; do
  case "$line" in
    "ok "*) ok "workflow: ${line#ok }" ;;
    *) bad "workflow: ${line#bad }" ;;
  esac
done <"$work/order"

echo
echo "release-channel tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
