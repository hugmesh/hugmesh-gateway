#!/usr/bin/env bash
# Live proof that a revocation key can be extended but never shortened
# (RevocationKeepLaterExpiryLiveTest), against a real Cassandra.
#
# Starts a throwaway Cassandra (the digest the cluster pins) on a private Docker
# network, runs that one test class in a Maven container on the same network, and
# removes the container and the network whatever the outcome. Needs only Docker.
# Nothing is published on the host. ~/.m2 is mounted so dependencies are reused.
#
#   scripts/test-revocation-keep-later-expiry-live.sh            # the test class
#   OFFLINE=1 scripts/test-revocation-keep-later-expiry-live.sh  # mvn -o
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
cassandra_image=${CASSANDRA_IMAGE:-cassandra:5.0.9@sha256:ee178b38a2746a8e15a115bd038ad1f864391d04a84162a018cb0dd79511709a}
maven_image=${MAVEN_IMAGE:-maven:3.9-eclipse-temurin-25}
m2=${M2_DIR:-$HOME/.m2}
tag="revocation-live-$$"
net="$tag-net"
cass="$tag-cassandra"

cleanup() {
  docker rm -f "$cass" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "$m2"
docker network create "$net" >/dev/null
docker run -d --name "$cass" --network "$net" \
  -e MAX_HEAP_SIZE=512M -e HEAP_NEWSIZE=128M "$cassandra_image" >/dev/null

echo "==> waiting for Cassandra ($cassandra_image)"
ready=0
for _ in $(seq 1 90); do
  if docker exec "$cass" cqlsh -e 'SELECT release_version FROM system.local' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done
if [ "$ready" -ne 1 ]; then
  echo "FAIL: Cassandra did not accept CQL within 180 s" >&2
  docker logs --tail 40 "$cass" >&2 || true
  exit 1
fi

offline=()
[ "${OFFLINE:-0}" = 1 ] && offline=(-o)

echo "==> RevocationKeepLaterExpiryLiveTest"
docker run --rm --network "$net" \
  --user "$(id -u):$(id -g)" -e HOME=/tmp -e MAVEN_OPTS=-Xmx1g \
  -e REVOCATION_LIVE_CASSANDRA="$cass:9042" \
  -v "$repo":/workspace -v "$m2":/m2 -w /workspace \
  "$maven_image" \
  mvn -B "${offline[@]}" -Dmaven.repo.local=/m2/repository test \
    -Dtest=RevocationKeepLaterExpiryLiveTest -Dsurefire.failIfNoSpecifiedTests=false
