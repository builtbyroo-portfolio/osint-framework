#!/usr/bin/env bash
# Scaffold a new program workspace from _template
set -euo pipefail

usage() {
    echo "Usage: $0 <program-name>"
    echo "  program-name: e.g. \"T-Mobile\" (quotes if spaces)"
    echo ""
    echo "Example: $0 \"T-Mobile\""
    exit 1
}

[[ $# -lt 1 ]] && usage

PROGRAM="$1"
TEMPLATE_DIR="$(dirname "$0")/programs/_template"
DEST="programs/${PROGRAM}"

if [[ -d "$DEST" ]]; then
    echo "Error: $DEST already exists"
    exit 1
fi

cp -r "$TEMPLATE_DIR" "$DEST"
sed -i "s/PROGRAM_NAME/${PROGRAM}/g" "$DEST/README.md" "$DEST/findings.md"

echo "Created: $DEST"
echo ""
echo "Next steps:"
echo "  1. Edit $DEST/README.md  — scope, rewards, scanner rules"
echo "  2. Edit $DEST/domains.txt — paste scope targets from program brief"
echo "  3. python3 scripts/impact_gate.py --check-program \"$PROGRAM\""
echo "  4. ./hunt.sh -t \"$PROGRAM\" -d $DEST/domains.txt"
