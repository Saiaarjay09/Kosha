#!/bin/bash
# Put Kosha on your tailnet.
#
# Kosha runs on one port and serves both the page and its API from it,
# so there is exactly one thing to expose. Two ways to do that:
#
#   serve   (the default here) — reachable only by devices signed in to
#           YOUR tailnet. Nobody else on the internet can even see that
#           the service exists. For a private data store this is almost
#           always what you want.
#
#   funnel  — reachable by anyone with the URL, over the public
#            internet. Use it only if you genuinely need to open Kosha
#            on a device that cannot join your tailnet. It is still
#            HTTPS and your data is still end-to-end encrypted, but it
#            puts the login page where the whole internet can reach it,
#            which is a meaningfully larger attack surface.
#
# Usage:  ./deploy/setup-tailscale.sh [serve|funnel] [port]

set -euo pipefail

MODE="${1:-serve}"
PORT="${2:-8711}"
TS="/Applications/Tailscale.app/Contents/MacOS/Tailscale"
[ -x "$TS" ] || TS="$(command -v tailscale || true)"

if [ -z "$TS" ] || [ ! -x "$TS" ]; then
    echo "Tailscale was not found."
    echo "Install it from https://tailscale.com/download, sign in, then run this again."
    exit 1
fi

if ! "$TS" status >/dev/null 2>&1; then
    echo "Tailscale is installed but not signed in. Run:  $TS up"
    exit 1
fi

case "$MODE" in
  serve)
    echo "Publishing Kosha to your tailnet only (not the public internet)…"
    "$TS" serve --bg --https=443 "http://127.0.0.1:${PORT}"
    ;;
  funnel)
    echo "Publishing Kosha to the PUBLIC internet over HTTPS…"
    echo "Anyone with the URL will be able to reach the login page. Ctrl-C now if that is not what you want."
    sleep 4
    "$TS" funnel --bg --https=443 "http://127.0.0.1:${PORT}"
    ;;
  *)
    echo "Usage: $0 [serve|funnel] [port]"
    exit 1
    ;;
esac

echo
echo "Done. Your Kosha URL:"
"$TS" status --json | python3 -c "
import json, sys
s = json.load(sys.stdin)
name = s.get('Self', {}).get('DNSName', '').rstrip('.')
print(f'  https://{name}' if name else '  (run: tailscale status  to find your machine name)')
"
echo
echo "To stop publishing:  $TS ${MODE} --https=443 off"
