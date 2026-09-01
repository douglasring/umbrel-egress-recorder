#!/usr/bin/env bash
#
# fetch-msp-docs.sh - mirror the Firewalla MSP API documentation as clean Markdown.
#
#   chmod +x fetch-msp-docs.sh && ./fetch-msp-docs.sh
#
# No prompts, no credentials, no redaction. The documentation is public.
#
# The site publishes llms.txt, which lists a .md URL for every page, so this fetches
# the original Markdown rather than scraping rendered HTML. sitemap.xml is used as a
# backstop for anything llms.txt omits.
#
# Output:
#   msp-docs-<stamp>/ALL-DOCS.md   <- every page in one file; upload this
#   msp-docs-<stamp>/*.md          <- one file per page

set -euo pipefail

BASE="${BASE:-https://docs.firewalla.net}"
OUT="msp-docs-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"

echo "Mirroring $BASE -> $OUT/"

BASE="$BASE" OUT="$OUT" python3 - <<'PY'
import os, re, urllib.parse, urllib.request

base, out = os.environ["BASE"].rstrip("/"), os.environ["OUT"]

def get(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "fetch-msp-docs/3.0"})
        with urllib.request.urlopen(req, timeout=45) as r:
            return r.read().decode("utf-8", "replace")
    except Exception:
        return None

urls = []

# 1. llms.txt lists a .md URL per page - the authoritative, ordered list.
llms = get(base + "/llms.txt")
if llms:
    with open(os.path.join(out, "llms.txt"), "w", encoding="utf-8") as fh:
        fh.write(llms)
    urls += re.findall(r"\((https?://[^)\s]+\.md)\)", llms)
    print("  llms.txt -> %d markdown pages" % len(urls))

# 2. sitemap.xml as a backstop, mapped to their .md equivalents.
sm = get(base + "/sitemap.xml")
if sm:
    for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", sm):
        if not loc.startswith(base):
            continue
        md = loc.rstrip("/") + ".md"
        if md == base + ".md":
            md = base + "/readme.md"
        if md not in urls:
            urls.append(md)
    print("  sitemap.xml -> %d total candidates" % len(urls))

seen, kept = set(), []
for url in urls:
    if url in seen:
        continue
    seen.add(url)
    body = get(url)
    if not body or len(body) < 80 or "<html" in body[:300].lower():
        print("    MISS %s" % url)
        continue
    slug = urllib.parse.urlparse(url).path.strip("/").replace("/", "-") or "index.md"
    with open(os.path.join(out, slug), "w", encoding="utf-8") as fh:
        fh.write(body)
    kept.append((url, slug, body))
    print("    ok   %-44s %7d bytes" % (slug, len(body)))

with open(os.path.join(out, "ALL-DOCS.md"), "w", encoding="utf-8") as fh:
    fh.write("# Firewalla MSP API documentation\n\nMirrored from %s\n" % base)
    for url, slug, body in kept:
        fh.write("\n\n---\n\n<!-- %s -->\n\n%s\n" % (url, body))

print("  %d page(s) -> %s/ALL-DOCS.md" % (len(kept), out))
PY

echo
echo "Upload: $OUT/ALL-DOCS.md"
ls -l "$OUT/ALL-DOCS.md" 2>/dev/null || true
