# Portable Ops Toolkit Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consolidate VM operational scripts into the central `~/scripts` repository and create a global install script.

**Architecture:** A simple bash repository structure where `bin/` contains executable scripts, and `install.sh` acts as a deployment mechanism linking scripts to `/usr/local/bin` for system-wide access.

**Tech Stack:** Bash, Git, Linux coreutils.

---

### Task 1: Script Consolidation

**Files:**
- Move: `/home/arthur/port-audit.sh` -> `/home/arthur/scripts/bin/port_audit.sh`
- Delete: `/home/arthur/scripts/bin/security-port-audit.sh`

- [ ] **Step 1: Move and rename the English script**

```bash
mv /home/arthur/port-audit.sh /home/arthur/scripts/bin/port_audit.sh
```

- [ ] **Step 2: Ensure it is executable**

```bash
chmod +x /home/arthur/scripts/bin/port_audit.sh
```

- [ ] **Step 3: Remove the old Chinese script**

```bash
rm /home/arthur/scripts/bin/security-port-audit.sh
```

- [ ] **Step 4: Commit changes**

```bash
cd /home/arthur/scripts
git add bin/
git commit -m "chore(scripts): replace security-port-audit.sh with english port_audit.sh"
```

### Task 2: Create Global Install Script

**Files:**
- Create: `/home/arthur/scripts/install.sh`

- [ ] **Step 1: Write install.sh implementation**

Write to `/home/arthur/scripts/install.sh`:
```bash
#!/bin/bash
set -e

echo "=== Portable Ops Toolkit Installer ==="

if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run as root (sudo ./install.sh) to link scripts to /usr/local/bin"
  exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$REPO_DIR/bin"
TARGET_DIR="/usr/local/bin"

# 1. Clean up old dangling link
if [ -L "$TARGET_DIR/security-audit" ]; then
    echo "Removing old symlink: security-audit"
    rm "$TARGET_DIR/security-audit"
fi

# 2. Link all .sh files in bin/ to /usr/local/bin/ without the .sh extension
echo "Linking scripts to $TARGET_DIR..."
for script in "$BIN_DIR"/*.sh; do
    [ -e "$script" ] || continue
    
    # Ensure it is executable
    chmod +x "$script"
    
    base_name=$(basename "$script")
    cmd_name="${base_name%.sh}"
    
    ln -sf "$script" "$TARGET_DIR/$cmd_name"
    echo "  -> Linked $cmd_name"
done

echo "Installation complete!"
```

- [ ] **Step 2: Make install script executable**

```bash
chmod +x /home/arthur/scripts/install.sh
```

- [ ] **Step 3: Verify the install script works (Dry Run / Inspect)**

```bash
/home/arthur/scripts/install.sh || true
```
Expected: FAIL with "Error: Please run as root..." (since we aren't using sudo in the test step, we just verify the basic sanity check).

- [ ] **Step 4: Commit install.sh**

```bash
cd /home/arthur/scripts
git add install.sh
git commit -m "feat(installer): add global symlink install script"
```
