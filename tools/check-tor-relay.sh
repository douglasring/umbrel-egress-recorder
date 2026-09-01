#!/usr/bin/env bash
# Is this address a Tor relay? Checked against the consensus the node ALREADY HAS.
#
# Run on the Umbrel HOST. Deliberately does NOT query onionoo or any online service:
# a third-party lookup tells that service which address you are investigating.

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $(basename "$0") <ip>" >&2
  exit 2
fi
TARGET=$1

# Umbrel runs Tor in a container; the consensus lives in its data volume.
CANDIDATES=(
  /home/umbrel/umbrel/tor/data
  /home/umbrel/umbrel/app-data/tor/data
  /var/lib/tor
)

SEARCHED=0
for dir in "${CANDIDATES[@]}"; do
  [ -d "$dir" ] || continue
  SEARCHED=1
  # cached-microdesc-consensus / cached-consensus / cached-descriptors
  if hits=$(grep -rlF "$TARGET" "$dir" 2>/dev/null); then
    echo "MATCH: $TARGET appears in the local Tor data at:"
    echo "$hits" | sed 's/^/  /'
    echo
    echo "This address is very likely a Tor relay. A reputation alert on a Tor relay"
    echo "is a routine false positive - relays often sit on low-cost hosting."
    echo "Do NOT conclude compromise from the reputation hit alone."
    exit 0
  fi
done

if [ "$SEARCHED" -eq 0 ]; then
  echo "Could not find a local Tor data directory. Checked:" >&2
  printf '  %s\n' "${CANDIDATES[@]}" >&2
  echo >&2
  echo "Point this script at your Tor data directory, or check manually:" >&2
  echo "  docker exec tor grep -l '$TARGET' /var/lib/tor/cached-*" >&2
  exit 3
fi

echo "No match: $TARGET is not in this node's cached Tor consensus."
echo
echo "That is not conclusive. The consensus is a point-in-time snapshot, it covers"
echo "public relays only, and it will not contain bridges. If the flow left via the"
echo "Tor container, the destination is still relay traffic regardless."
exit 1
