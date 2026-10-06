#!/bin/bash
set -e

echo "=== Portable Ops Toolkit Installer ==="

if [ "$EUID" -ne 0 ]; then
	echo "Error: please use root to run thsi script (sudo ./insatll.sh)"
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BIN_DIR="$REPO_DIR/bin"
TARGET_DIR="/usr/local/bin"

if [ -L "TARGET_DIR/security-audit" ]; then 
	echo "Remove old symlink: security-audit"
	rm "$TARGET_DIR/security-audit"
fi 

echo "start connect the scripts to $TARGET_DIR ...  " 

for script in "$BIN_DIR"/*.sh; do 

	[ -e "$script" ] || continue

	chmod +x "$script"

	base_name=$(basename "$script")
        cmd_name="${base_name%.sh}"

        ln -sf "$script" "$TARGET_DIR/$cmd_name"
	echo "   -> connect $cmd_name"
done

echo "install complete"

