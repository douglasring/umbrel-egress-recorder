#!/usr/bin/env bash
#
# fetch-msp-docs.sh - collect Firewalla MSP API documentation and sample responses
#                     into a redacted bundle that is safe to share.
#
# Run this on a machine that can reach your MSP domain (e.g. your MacBook).
#
#   chmod +x fetch-msp-docs.sh
#   ./fetch-msp-docs.sh
#
# It will prompt for your MSP domain and personal access token, or read them from
# the MSP_DOMAIN / MSP_TOKEN environment variables.
#
# SAFETY
#   - Makes GET requests only. It never creates, modifies or deletes anything.
#     (Firewalla's own examples warn that the MSP API writes directly to your data.)
#   - Your token is never written to the output bundle.
#   - Before writing anything, it redacts IP addresses, MAC addresses, UUIDs and your
#     MSP hostname, replacing each with a stable placeholder (LANIP-1, PUBIP-1, ...).
#     Field names, structure and value shapes are preserved, which is what is needed
#     to build against the API.
#   - Both the raw and redacted forms are kept locally. ONLY the redacted bundle is
#     meant to leave your machine. The script tells you which file that is.
#
# Requires: bash, curl, python3 (macOS: python3 comes with the Xcode Command Line
# Tools - if missing, run `xcode-select --install`).

set -euo pipefail

MSP_DOMAIN="${MSP_DOMAIN:-}"
MSP_TOKEN="${MSP_TOKEN:-}"

if [ -z "$MSP_DOMAIN" ]; then
  printf 'MSP domain (e.g. dn-abc123.firewalla.net): '
  read -r MSP_DOMAIN
fi
MSP_DOMAIN="${MSP_DOMAIN#https://}"
MSP_DOMAIN="${MSP_DOMAIN#http://}"
MSP_DOMAIN="${MSP_DOMAIN%%/*}"

if [ -z "$MSP_TOKEN" ]; then
  printf 'MSP personal access token (input hidden): '
  stty -echo 2>/dev/null || true
  read -r MSP_TOKEN
  stty echo 2>/dev/null || true
  printf '\n'
fi

if [ -z "$MSP_DOMAIN" ] || [ -z "$MSP_TOKEN" ]; then
  echo "error: domain and token are both required" >&2
  exit 2
fi

command -v python3 >/dev/null 2>&1 || {
  echo "error: python3 not found. On macOS run: xcode-select --install" >&2
  exit 1
}

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="msp-bundle-$STAMP"
mkdir -p "$OUT/raw" "$OUT/share"

echo
echo "Collecting from https://$MSP_DOMAIN  ->  $OUT/"
echo

# --- helpers ---------------------------------------------------------------

# get <url> <outfile> [auth]
get() {
  url="$1"; out="$2"; auth="${3:-}"
  if [ -n "$auth" ]; then
    code=$(curl -sS -o "$OUT/raw/$out" -w '%{http_code}' --max-time 45 \
             -H "Authorization: Token $MSP_TOKEN" \
             -H 'Content-Type: application/json' \
             "$url" 2>/dev/null || echo 000)
  else
    code=$(curl -sS -o "$OUT/raw/$out" -w '%{http_code}' --max-time 45 \
             "$url" 2>/dev/null || echo 000)
  fi
  size=$(wc -c < "$OUT/raw/$out" 2>/dev/null | tr -d ' ')
  printf '  %-52s %s  %s bytes\n' "$out" "$code" "$size"
  if [ "$code" != "200" ] || [ "${size:-0}" -lt 20 ]; then
    rm -f "$OUT/raw/$out"
    return 1
  fi
  return 0
}

# --- 1. machine-readable API spec -----------------------------------------
# The docs page is usually Swagger/Redoc, which is generated from a spec. The spec
# is far more useful than the rendered HTML, so try the conventional locations.

echo "[1/4] Looking for an OpenAPI/Swagger spec"
for path in \
  /api/docs/swagger.json \
  /api/docs/openapi.json \
  /api/docs/swagger.yaml \
  /api/docs/openapi.yaml \
  /api/docs/spec.json \
  /api/swagger.json \
  /api/openapi.json \
  /v2/openapi.json \
  /v2/swagger.json \
  /swagger.json \
  /openapi.json
do
  name="spec$(echo "$path" | tr '/.' '__')"
  get "https://$MSP_DOMAIN$path" "$name" auth || true
done

# --- 2. rendered docs ------------------------------------------------------

echo
echo "[2/4] Fetching rendered documentation pages"
get "https://$MSP_DOMAIN/api/docs/" "api-docs-index.html" auth || true
get "https://docs.firewalla.net/" "public-docs-index.html" || true
for p in api-reference/alarm api-reference/flow api-reference/device \
         api-reference/target-lists api-reference/rule data-models/alarm data-models/flow
do
  get "https://docs.firewalla.net/$p/" "public-$(echo "$p" | tr '/' '-').html" || true
done

# --- 3. live sample responses ---------------------------------------------
# Read-only. These reveal the ACTUAL field shapes, which matters because Firewalla's
# own examples note the published docs lag behind the API.

echo
echo "[3/4] Sampling live API responses (GET only)"
get "https://$MSP_DOMAIN/v2/boxes" "v2-boxes.json" auth || true
get "https://$MSP_DOMAIN/v2/alarms?limit=5" "v2-alarms-recent.json" auth || true
get "https://$MSP_DOMAIN/v2/alarms?query=status%3Aactive&limit=5" "v2-alarms-active.json" auth || true
get "https://$MSP_DOMAIN/v2/alarms?query=type%3A1&limit=5" "v2-alarms-type1-security.json" auth || true
get "https://$MSP_DOMAIN/v2/flows?limit=3" "v2-flows.json" auth || true
get "https://$MSP_DOMAIN/v2/devices?limit=5" "v2-devices.json" auth || true
get "https://$MSP_DOMAIN/v2/target-lists?limit=3" "v2-target-lists.json" auth || true

# --- 4. redact -------------------------------------------------------------

echo
echo "[4/4] Redacting"

MSP_DOMAIN="$MSP_DOMAIN" MSP_TOKEN="$MSP_TOKEN" \
python3 - "$OUT" <<'PY'
import ipaddress, json, os, re, sys

out = sys.argv[1]
raw, share = os.path.join(out, "raw"), os.path.join(out, "share")
domain = os.environ.get("MSP_DOMAIN", "")
token = os.environ.get("MSP_TOKEN", "")

counters, mapping = {}, {}

def label(kind, value):
    """Stable placeholder per distinct value, so relationships stay visible."""
    key = (kind, value)
    if key not in mapping:
        counters[kind] = counters.get(kind, 0) + 1
        mapping[key] = "<%s-%d>" % (kind, counters[kind])
    return mapping[key]

IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}(?::|[0-9A-Fa-f]{1,4})(?![\w:])")
MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")

def sub_ip(m):
    v = m.group(0)
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return v
    if ip.is_loopback or ip.is_unspecified:
        return v
    return label("LANIP" if ip.is_private else "PUBIP", v)

def redact(text):
    if token:
        text = text.replace(token, "<MSP-TOKEN-REDACTED>")
    if domain:
        text = text.replace(domain, "<MSP-DOMAIN>")
        text = text.replace(domain.split(".")[0], "<MSP-ID>")
    text = IPV4.sub(sub_ip, text)
    # MAC before IPv6: aa:bb:cc:11:22:33 also matches the IPv6 pattern, and
    # mislabelling a MAC as an address makes the sample misleading.
    text = MAC.sub(lambda m: label("MAC", m.group(0)), text)
    text = IPV6.sub(lambda m: label("PUB6", m.group(0)), text)
    text = UUID.sub(lambda m: label("UUID", m.group(0)), text)
    return text

kept = []
for name in sorted(os.listdir(raw)):
    path = os.path.join(raw, name)
    try:
        body = open(path, "r", encoding="utf-8", errors="replace").read()
    except OSError:
        continue

    # Pretty-print JSON so the structure is readable; leave HTML alone.
    try:
        body = json.dumps(json.loads(body), indent=2, sort_keys=True)
        name = name if name.endswith(".json") else name + ".json"
    except (ValueError, TypeError):
        if name.endswith(".html"):
            # Rendered docs are large and mostly markup. Keep only inlined spec-ish
            # blobs, which is where Swagger/Redoc pages hide the real schema.
            blobs = re.findall(r'\{"openapi".{0,400000}?\}\s*[;<]', body) or \
                    re.findall(r'\{"swagger".{0,400000}?\}\s*[;<]', body)
            if blobs:
                body = "\n\n".join(blobs)
                name = name.replace(".html", ".embedded-spec.txt")
            elif len(body) > 200000:
                continue  # too big and not useful

    open(os.path.join(share, name), "w", encoding="utf-8").write(redact(body))
    kept.append(name)

with open(os.path.join(share, "_README.txt"), "w") as fh:
    fh.write(
        "Firewalla MSP API bundle (REDACTED - safe to share)\n"
        "===================================================\n\n"
        "Every IP address, MAC address, UUID and the MSP hostname has been replaced\n"
        "with a stable placeholder. The same real value always maps to the same\n"
        "placeholder, so relationships between records remain visible while the\n"
        "underlying values do not leave your machine.\n\n"
        "The access token appears nowhere in this bundle.\n\n"
        "Files:\n" + "".join("  %s\n" % n for n in kept) +
        "\nThe unredacted originals are in ../raw/ - do not share that directory.\n"
    )

print("  redacted %d file(s) -> %s/" % (len(kept), share))
print("  distinct values masked: %s" % (
    ", ".join("%s=%d" % (k, v) for k, v in sorted(counters.items())) or "none"))
PY

TAR="$OUT-share.tgz"
tar -czf "$TAR" -C "$OUT" share

echo
echo "==============================================================="
echo "Done."
echo
echo "  SHARE THIS:      $TAR"
echo "                   (also readable as plain files in $OUT/share/)"
echo
echo "  DO NOT SHARE:    $OUT/raw/   - unredacted originals"
echo
echo "Check it yourself before sending - it is plain text:"
echo "    cat $OUT/share/_README.txt"
echo "    ls -l $OUT/share/"
echo "==============================================================="
