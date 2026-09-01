#!/usr/bin/env bash
#
# fetch-msp-docs.sh - mirror the Firewalla MSP API documentation and sample the live
#                     API, into a redacted bundle that is safe to share.
#
# Run on a machine that can reach your MSP domain (e.g. your MacBook):
#
#   chmod +x fetch-msp-docs.sh
#   ./fetch-msp-docs.sh
#
# The documentation is public, so no login is required to mirror it. A personal
# access token is only needed for the optional live API sampling in step 3; leave the
# token prompt blank to skip it and collect documentation alone.
#
# Credentials may also be supplied as MSP_DOMAIN / MSP_TOKEN environment variables.
#
# SAFETY
#   - GET requests only. It never creates, modifies or deletes anything.
#     (Firewalla's own examples warn the MSP API operates directly on live data.)
#   - The token never appears in the output bundle.
#   - IPs, MACs, UUIDs, email addresses and your MSP hostname are replaced with stable
#     placeholders before anything is written to the shareable directory. Field names,
#     structure and value shapes are preserved, which is what is needed to build
#     against the API.
#   - Unredacted originals stay in raw/ and are NOT bundled.
#
# Requires: bash, curl, python3 (macOS: `xcode-select --install` if missing).

set -euo pipefail

MSP_DOMAIN="${MSP_DOMAIN:-}"
MSP_TOKEN="${MSP_TOKEN:-}"

if [ -z "$MSP_DOMAIN" ]; then
  printf 'MSP domain (e.g. dn-abc123.firewalla.net): '
  read -r MSP_DOMAIN
fi
MSP_DOMAIN="${MSP_DOMAIN#https://}"; MSP_DOMAIN="${MSP_DOMAIN#http://}"; MSP_DOMAIN="${MSP_DOMAIN%%/*}"

if [ -z "$MSP_TOKEN" ]; then
  printf 'MSP access token (hidden; blank = docs only, skip live API): '
  stty -echo 2>/dev/null || true; read -r MSP_TOKEN; stty echo 2>/dev/null || true; printf '\n'
fi

[ -n "$MSP_DOMAIN" ] || { echo "error: domain is required" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || {
  echo "error: python3 not found. On macOS run: xcode-select --install" >&2; exit 1; }

# A Retype docs site is static HTML, so curl is normally enough. But a Swagger/Redoc
# page renders from JavaScript and would otherwise come back as an empty shell. If a
# Chromium-family browser is already installed we use it to render those pages. Nothing
# is installed by this script; if no browser is found it simply skips the fallback.
BROWSER_BIN="${BROWSER_BIN:-}"
if [ -z "$BROWSER_BIN" ]; then
  for b in "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
           "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" \
           "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" \
           "/Applications/Chromium.app/Contents/MacOS/Chromium"; do
    if [ -x "$b" ]; then BROWSER_BIN="$b"; break; fi
  done
fi
if [ -z "$BROWSER_BIN" ]; then
  for b in chromium google-chrome chromium-browser; do
    if command -v "$b" >/dev/null 2>&1; then BROWSER_BIN="$(command -v "$b")"; break; fi
  done
fi
if [ -n "$BROWSER_BIN" ]; then
  echo "Browser rendering available: $BROWSER_BIN"
else
  echo "No Chromium-family browser found - fine for a static docs site; JS-only"
  echo "pages fall back to fetching their spec JSON directly."
fi

OUT="msp-bundle-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT/raw" "$OUT/share"
echo
echo "Collecting from https://$MSP_DOMAIN  ->  $OUT/"

# ---------------------------------------------------------------------------
# 1 + 2. Spec hunt, then mirror the whole documentation tree
# ---------------------------------------------------------------------------
# Page paths are NOT guessed. The docs are a Retype site whose navigation tree
# changes; guessing paths produces 404s and silent gaps. URLs are discovered from
# sitemap.xml, then by breadth-first crawling every in-scope link, capped so it
# terminates.

MSP_DOMAIN="$MSP_DOMAIN" MSP_TOKEN="$MSP_TOKEN" OUTDIR="$OUT" BROWSER_BIN="$BROWSER_BIN" \
python3 - <<'PYDOCS'
import html as htmllib, os, re, subprocess, urllib.parse, urllib.request
from collections import deque

raw = os.path.join(os.environ["OUTDIR"], "raw")
domain = os.environ["MSP_DOMAIN"]
token = os.environ.get("MSP_TOKEN", "")
MSP = "https://%s" % domain
MAX_PAGES = 600


def fetch(url, timeout=45):
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) fetch-msp-docs/2.0",
        "Accept": "*/*",
    })
    if token and url.startswith(MSP):
        req.add_header("Authorization", "Token " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except Exception:
        return None


def save(name, body):
    with open(os.path.join(raw, name), "w", encoding="utf-8") as fh:
        fh.write(body)


BROWSER = os.environ.get("BROWSER_BIN", "")
SPA = re.compile(r"redoc|swagger-ui|__NEXT_DATA__|id=[\"']root[\"']|id=[\"']app[\"']", re.I)


def render(url):
    """Rendered DOM via headless Chrome, for pages whose content is built by JS."""
    if not BROWSER:
        return None
    try:
        p = subprocess.run(
            [BROWSER, "--headless=new", "--disable-gpu", "--no-sandbox",
             "--disable-dev-shm-usage", "--virtual-time-budget=8000",
             "--run-all-compositor-stages-before-draw", "--dump-dom", url],
            capture_output=True, timeout=90)
        dom = p.stdout.decode("utf-8", "replace")
        return dom if len(dom) > 200 else None
    except Exception:
        return None


print("\n[1/4] Looking for a machine-readable spec")
for path in ("/api/docs/swagger.json", "/api/docs/openapi.json", "/api/docs/spec.json",
             "/api/docs/swagger.yaml", "/api/docs/openapi.yaml",
             "/api/swagger.json", "/api/openapi.json",
             "/v2/openapi.json", "/v2/swagger.json", "/swagger.json", "/openapi.json"):
    body = fetch(MSP + path)
    if body and len(body) > 200 and ("openapi" in body[:2000] or "swagger" in body[:2000]):
        save("spec%s" % path.replace("/", "_"), body)
        print("  FOUND %s (%d bytes)" % (path, len(body)))

print("\n[2/4] Mirroring documentation")

TAG = re.compile(r"<[^>]+>")
DROP = re.compile(r"<(script|style|svg|head)\b.*?</\1>", re.S | re.I)
ASSET = re.compile(r"\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map|zip|pdf)$", re.I)


def to_text(body):
    body = DROP.sub(" ", body)
    body = re.sub(r"<(br|/p|/div|/h[1-6]|/li|/tr|/pre)\s*/?>", "\n", body, flags=re.I)
    body = htmllib.unescape(TAG.sub("", body))
    body = re.sub(r"[ \t]+", " ", body)
    return re.sub(r"\n\s*\n\s*\n+", "\n\n", body).strip()


def seeds(host):
    urls = set()
    for sm in ("/sitemap.xml", "/sitemap_index.xml"):
        body = fetch(host + sm)
        if body and "<loc>" in body:
            urls.update(u for u in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", body)
                        if u.startswith(host))
            if urls:
                print("  %s%s -> %d urls" % (host, sm, len(urls)))
                break
    urls.add(host + "/")
    return urls


pages, seen = [], set()
for host in ("https://docs.firewalla.net", MSP + "/api/docs"):
    # Some doc sites publish a plain-text dump aimed at LLMs. If it exists it is
    # usually the single most complete artefact available, so it is worth a try.
    for extra in ("/llms.txt", "/llms-full.txt"):
        body = fetch(host + extra)
        if body and len(body) > 200 and "<html" not in body[:300].lower():
            pages.append(("llms%s.txt" % extra.replace("/", "-"), body))
            print("  FOUND %s%s (%d bytes)" % (host, extra, len(body)))

    queue, count = deque(seeds(host)), 0
    while queue and count < MAX_PAGES:
        url = queue.popleft().split("#")[0].rstrip("/") or host
        if url in seen or not url.startswith(host) or ASSET.search(url):
            continue
        seen.add(url)

        # Prefer a Markdown rendering where the site exposes one - a Retype HTML page
        # is mostly markup, and the point of this bundle is readable API reference.
        body, kind = None, "txt"
        for md in (url + ".md", url + "/index.md"):
            cand = fetch(md)
            if cand and "<html" not in cand[:400].lower() and len(cand) > 120:
                body, kind = cand, "md"
                break
        if body is None:
            page = fetch(url)
            if not page:
                continue
            # An app shell with almost no prose means the content is built by JS.
            if len(to_text(page)) < 400 and SPA.search(page[:4000]):
                # Swagger/Redoc name their spec in the shell. Fetching that JSON is
                # better than rendering the DOM: no browser, and it is the actual
                # machine-readable source rather than a scrape of the rendered page.
                for m in re.finditer(
                        r"""(?:spec-?url|data-url|url)\s*[:=]\s*['"]([^'"]+\.(?:json|yaml|yml))['"]""",
                        page, re.I):
                    spec_url = urllib.parse.urljoin(url + "/", m.group(1))
                    spec = fetch(spec_url)
                    if spec and len(spec) > 200:
                        name = "spec-" + re.sub(r"[^A-Za-z0-9._-]", "_",
                                                urllib.parse.urlparse(spec_url).path.strip("/"))
                        save(name, spec)
                        print("      FOUND embedded spec -> %s (%d bytes)" % (name, len(spec)))
                        break
                rendered = render(url)
                if rendered and len(to_text(rendered)) > len(to_text(page)):
                    print("      (rendered with browser)")
                    page = rendered
            # Keep crawling from the HTML even though we store the text rendering.
            for href in re.findall(r'href="([^"]+)"', page):
                if href.startswith(("mailto:", "javascript:", "tel:")):
                    continue
                nxt = urllib.parse.urljoin(url + "/", href).split("#")[0]
                if nxt.startswith(host) and nxt not in seen and not ASSET.search(nxt):
                    queue.append(nxt)
            body = to_text(page)

        if len(body) < 120:
            continue
        slug = urllib.parse.urlparse(url).path.strip("/").replace("/", "-") or "index"
        pages.append(("doc-%s.%s" % (slug, kind), "SOURCE: %s\n\n%s" % (url, body)))
        count += 1
        print("    %-56s %7d bytes (%s)" % (slug[:56], len(body), kind))

for name, body in pages:
    save(name, body)
if pages:
    save("ALL-DOCS.txt", "".join(
        "\n\n%s\n%s\n%s\n\n%s" % ("=" * 78, n, "=" * 78, b) for n, b in pages))
print("  collected %d page(s)" % len(pages))
PYDOCS

# ---------------------------------------------------------------------------
# 3. Live API samples (read-only) - the real field shapes
# ---------------------------------------------------------------------------
# Firewalla's own example code carries the note "doc is out of date now", so live
# responses are the ground truth for anything built against this API.

echo
echo "[3/4] Sampling live API responses (GET only)"
if [ -z "$MSP_TOKEN" ]; then
  echo "  skipped - no token supplied"
else
  api() {
    code=$(curl -sS -o "$OUT/raw/$2" -w '%{http_code}' --max-time 45 \
             -H "Authorization: Token $MSP_TOKEN" -H 'Content-Type: application/json' \
             "https://$MSP_DOMAIN$1" 2>/dev/null || echo 000)
    size=$(wc -c < "$OUT/raw/$2" 2>/dev/null | tr -d ' ')
    printf '  %-46s %s  %s bytes\n' "$2" "$code" "$size"
    [ "$code" = "200" ] || rm -f "$OUT/raw/$2"
  }
  api "/v2/boxes"                                "v2-boxes.json"
  api "/v2/alarms?limit=5"                       "v2-alarms-recent.json"
  api "/v2/alarms?query=status%3Aactive&limit=5" "v2-alarms-active.json"
  api "/v2/alarms?query=type%3A1&limit=5"        "v2-alarms-type1.json"
  api "/v2/flows?limit=3"                        "v2-flows.json"
  api "/v2/devices?limit=5"                      "v2-devices.json"
  api "/v2/target-lists?limit=3"                 "v2-target-lists.json"
  api "/v2/rules?limit=3"                        "v2-rules.json"
fi

# ---------------------------------------------------------------------------
# 4. Redact
# ---------------------------------------------------------------------------

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
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
DOCNETS = [ipaddress.ip_network(n) for n in
           ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]

def sub_ip(m):
    v = m.group(0)
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return v
    if ip.is_loopback or ip.is_unspecified:
        return v
    # Documentation ranges are already safe, and more informative left intact.
    if any(ip in n for n in DOCNETS):
        return v
    return label("LANIP" if ip.is_private else "PUBIP", v)

def redact(text):
    if token and len(token) >= 8:
        text = text.replace(token, "<REDACTED-CREDENTIAL>")
    # Substring replacement, unanchored, corrupts ordinary prose: a two-letter value
    # rewrote every "name" into "<MSP-DOMAIN>me". Require a plausible hostname and
    # match on word boundaries.
    if domain and len(domain) >= 6 and "." in domain:
        text = re.sub(r"\b%s\b" % re.escape(domain), "<MSP-DOMAIN>", text)
        first = domain.split(".")[0]
        if len(first) >= 4:
            text = re.sub(r"\b%s\b" % re.escape(first), "<MSP-ID>", text)
    text = IPV4.sub(sub_ip, text)
    # MAC before IPv6: a MAC also matches the IPv6 pattern and would be mislabelled.
    text = MAC.sub(lambda m: label("MAC", m.group(0)), text)
    text = IPV6.sub(lambda m: label("PUB6", m.group(0)), text)
    text = UUID.sub(lambda m: label("UUID", m.group(0)), text)
    text = EMAIL.sub(lambda m: label("EMAIL", m.group(0)), text)
    return text

kept = []
for name in sorted(os.listdir(raw)):
    try:
        body = open(os.path.join(raw, name), "r", encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    try:  # pretty-print JSON so the structure reads clearly
        body = json.dumps(json.loads(body), indent=2, sort_keys=True)
    except (ValueError, TypeError):
        pass
    open(os.path.join(share, name), "w", encoding="utf-8").write(redact(body))
    kept.append(name)

with open(os.path.join(share, "_README.txt"), "w") as fh:
    fh.write(
        "Firewalla MSP API bundle (REDACTED - safe to share)\n"
        "===================================================\n\n"
        "The access token appears nowhere in this bundle.\n\n"
        "Every IP, MAC, UUID and email address, and the MSP hostname, has been replaced\n"
        "with a stable placeholder: the same real value always maps to the same\n"
        "placeholder, so relationships between records stay visible while the values\n"
        "themselves never leave this machine. RFC 5737 documentation addresses are left\n"
        "intact, being already safe and more informative unmasked.\n\n"
        "Files (%d):\n" % len(kept) + "".join("  %s\n" % n for n in kept) +
        "\nStart with ALL-DOCS.txt - every documentation page concatenated.\n"
        "The unredacted originals are in ../raw/ - do not share that directory.\n"
    )

print("  redacted %d file(s) -> %s/" % (len(kept), share))
print("  masked: %s" % (", ".join("%s=%d" % kv for kv in sorted(counters.items())) or "nothing"))
PY

TAR="$OUT-share.tgz"
tar -czf "$TAR" -C "$OUT" share
SIZE=$(du -h "$TAR" | cut -f1 | tr -d ' ')

echo
echo "==============================================================="
echo "Done."
echo
echo "  UPLOAD THIS:   $TAR   ($SIZE)"
echo "                 or the plain files in $OUT/share/"
echo
echo "  DO NOT SHARE:  $OUT/raw/   - unredacted originals"
echo
echo "Verify it yourself first - it is all plain text:"
echo "    cat $OUT/share/_README.txt"
echo "    less $OUT/share/ALL-DOCS.txt"
echo "==============================================================="
