#!/usr/bin/env bash
# Map a Docker container IP to a container, on the Umbrel HOST.
#
# Not run by the recorder. The recorder deliberately has no Docker API access.
#
# Requests only name, image and IP. It does NOT run a bare `docker inspect`:
# a full inspect of an Umbrel app prints its environment, which for several apps
# includes the bitcoind RPC password.
#
# IMPORTANT: this answers a question about the PRESENT. If the app was updated,
# restarted or reinstalled since the observation, the address may now belong to a
# different app - or to nothing. Use tools/install-ip-ledger.sh for historical lookups.

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $(basename "$0") <container-ip>" >&2
  exit 2
fi
TARGET=$1

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker not found; run this on the Umbrel host" >&2
  exit 1
fi

FOUND=0
printf '%-28s  %-45s  %s\n' "CONTAINER" "IMAGE" "ADDRESSES"
printf '%-28s  %-45s  %s\n' "----------------------------" \
  "---------------------------------------------" "---------"

while read -r id; do
  [ -n "$id" ] || continue
  # Explicit field selection only - never the whole config object.
  line=$(docker inspect \
    --format '{{.Name}}|{{.Config.Image}}|{{range $k, $v := .NetworkSettings.Networks}}{{$v.IPAddress}} {{end}}' \
    "$id" 2>/dev/null) || continue

  name=${line%%|*}; rest=${line#*|}
  image=${rest%%|*}; addrs=${rest#*|}
  name=${name#/}

  for a in $addrs; do
    if [ "$a" = "$TARGET" ]; then
      printf '%-28s  %-45s  %s\n' "$name" "$image" "$addrs"
      FOUND=1
    fi
  done
done < <(docker ps -q)

if [ "$FOUND" -eq 0 ]; then
  echo
  echo "No RUNNING container currently holds $TARGET."
  echo
  echo "This does not mean nothing did. Docker reassigns addresses, so a container"
  echo "recreated since the observation may have released it. Check the ledger:"
  echo "  grep -F '$TARGET' /var/lib/umbrel-egress-recorder/ip-ledger.tsv"
fi
