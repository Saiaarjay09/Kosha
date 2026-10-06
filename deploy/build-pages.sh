#!/bin/bash
# Assemble the GitHub Pages site.
#
# Pages serves static files only — no Python, nothing to run. That is
# fine, because Kosha already does all of its real work in the browser:
# the key derivation, the decryption, the SQL and the conversions are
# all client-side, and the server was never more than a place to put
# bytes it could not read. On Pages, that place becomes the browser's
# own IndexedDB (see static/js/store-local.js), which the app switches
# to by itself when nothing answers `api/health`.
#
# So this script does not build anything. It copies the one and only
# copy of the app into docs/app/, where Pages can serve it, and leaves
# docs/index.html as the landing page. static/ stays the single source
# of truth; docs/app/ is generated and should never be edited by hand.
#
# Usage:  ./deploy/build-pages.sh

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

SRC="static"
DEST="docs/app"

echo "Rebuilding $DEST from $SRC …"
rm -rf "$DEST"
mkdir -p "$DEST"
cp -R "$SRC"/. "$DEST"/

# A marker so it is obvious in the repository and in a browser's
# devtools that these files are generated, not authored.
cat > "$DEST/GENERATED.txt" <<EOF
These files are copied from ../../static by deploy/build-pages.sh.
Edit static/, then run that script. Anything changed here is lost.
Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

# Jekyll is GitHub Pages' default processor and it ignores files and
# directories beginning with an underscore. Nothing here starts with
# one today, but a vendored dependency could, and the failure mode —
# one file silently missing from the deployed site — is miserable to
# diagnose. Turning Jekyll off entirely avoids the whole class of it.
touch docs/.nojekyll

echo
echo "Copied:"
find "$DEST" -type f | wc -l | xargs echo "  files:"
du -sh "$DEST" | awk '{print "  size:  " $1}'
echo
echo "Landing page: docs/index.html"
echo "App:          docs/app/index.html"
echo
echo "Commit docs/ and push. In the repository's Settings > Pages,"
echo "set the source to the main branch and the /docs folder."
