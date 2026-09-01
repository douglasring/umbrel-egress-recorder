#!/usr/bin/env bash
# Install a systemd timer that appends a timestamped container-IP ledger.
#
# Solves the time-travel problem: map-container-ip.sh answers about the present,
# but an incident question is about the past.
#
# Runs on the HOST, outside the recorder container. The ledger is written outside
# this repository and must never be committed - it maps your apps to addresses.

set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }

DIR=/var/lib/umbrel-egress-recorder
LEDGER=$DIR/ip-ledger.tsv
install -d -m 0750 "$DIR"

cat > /usr/local/bin/umbrel-ip-ledger <<'INNER'
#!/usr/bin/env bash
set -euo pipefail
LEDGER=/var/lib/umbrel-egress-recorder/ip-ledger.tsv
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
[ -s "$LEDGER" ] || printf 'utc\tcontainer\timage\tip\n' > "$LEDGER"
while read -r id; do
  [ -n "$id" ] || continue
  line=$(docker inspect \
    --format '{{.Name}}|{{.Config.Image}}|{{range $k, $v := .NetworkSettings.Networks}}{{$v.IPAddress}} {{end}}' \
    "$id" 2>/dev/null) || continue
  name=${line%%|*}; rest=${line#*|}
  image=${rest%%|*}; addrs=${rest#*|}
  for a in $addrs; do
    [ -n "$a" ] && printf '%s\t%s\t%s\t%s\n' "$NOW" "${name#/}" "$image" "$a" >> "$LEDGER"
  done
done < <(docker ps -q)
# Bound the file: keep the most recent ~200k records.
if [ "$(wc -l < "$LEDGER")" -gt 200000 ]; then
  tail -n 150000 "$LEDGER" > "$LEDGER.tmp" && mv "$LEDGER.tmp" "$LEDGER"
fi
INNER
chmod 0755 /usr/local/bin/umbrel-ip-ledger

cat > /etc/systemd/system/umbrel-ip-ledger.service <<'INNER'
[Unit]
Description=Append Umbrel container IP ledger
[Service]
Type=oneshot
ExecStart=/usr/local/bin/umbrel-ip-ledger
INNER

cat > /etc/systemd/system/umbrel-ip-ledger.timer <<'INNER'
[Unit]
Description=Append Umbrel container IP ledger every 15 minutes
[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
Persistent=true
[Install]
WantedBy=timers.target
INNER

systemctl daemon-reload
systemctl enable --now umbrel-ip-ledger.timer
/usr/local/bin/umbrel-ip-ledger

echo "Ledger installed. Query a past observation with:"
echo "  grep -F '<ip>' $LEDGER"
