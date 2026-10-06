#!/bin/bash
# Keeps the always-on GitHub Pages site pointing at the right address.
#
# The app itself lives on a tailnet and is only reachable from your own
# devices; this page is public and always up, which makes it the one
# place worth treating as canonical. A Tailscale hostname is stable, so
# unlike a tunnel URL this rarely changes — but "rarely" is not "never"
# (a renamed machine, a new tailnet), and re-sending a link by hand each
# time does not scale. This re-derives it and commits only when it has
# actually changed.
#
# Run it by hand after setup, or on a schedule. There is no daemon.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

TS="/Applications/Tailscale.app/Contents/MacOS/Tailscale"
[ -x "$TS" ] || TS="$(command -v tailscale || true)"
if [ -z "$TS" ] || [ ! -x "$TS" ]; then
    echo "publish-links: tailscale not found, nothing to do"
    exit 0
fi

HOST=$("$TS" status --json 2>/dev/null | python3 -c "
import json, sys
try:
    print(json.load(sys.stdin).get('Self', {}).get('DNSName', '').rstrip('.'))
except Exception:
    print('')
")

if [ -z "$HOST" ]; then
    echo "publish-links: could not read the tailnet hostname, skipping"
    exit 0
fi

URL="https://${HOST}"
CURRENT=$(grep -o 'https://[a-zA-Z0-9.-]*\.ts\.net' docs/index.html | head -1 || true)

if [ "$URL" = "$CURRENT" ]; then
    echo "publish-links: already correct ($URL)"
    exit 0
fi

echo "publish-links: $CURRENT -> $URL"

python3 - "$URL" <<'PY'
import re, sys
url = sys.argv[1]
for path in ("docs/index.html", "CURRENT_LINKS.md"):
    try:
        s = open(path).read()
    except FileNotFoundError:
        continue
    s = re.sub(r'https://[a-zA-Z0-9.-]*\.ts\.net', url, s)
    open(path, "w").write(s)
PY

git add docs/index.html CURRENT_LINKS.md
git commit -m "Update the published Kosha address" >/dev/null
git push >/dev/null
echo "publish-links: committed and pushed"
