#!/bin/bash
chmod +x /usr/local/bin/srl-eigrpd

# Auto-provision CPM filter entry for protocol 88 safely if 'cpm' filter is present
if command -v sr_cli >/dev/null 2>&1; then
    for i in {1..15}; do
        if sr_cli "show version" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    python3 - << 'EOF' || true
import subprocess
import re

def ensure_cpm(filter_type, match_lines, match_regex):
    try:
        res = subprocess.run(
            ["sr_cli", f"info flat acl acl-filter cpm type {filter_type}"],
            capture_output=True, text=True, check=False
        )
        if res.returncode != 0:
            return

        lines = res.stdout.splitlines()
        existing_entries = set()
        has_rule = False

        for line in lines:
            m = re.search(r"acl-filter cpm type \S+ entry (\d+)", line)
            if m:
                existing_entries.add(int(m.group(1)))
            if match_regex.search(line):
                has_rule = True

        if has_rule:
            return  # Already configured!

        # Find available entry number. Prefer 88 if not taken.
        target_seq = 88
        if target_seq in existing_entries:
            target_seq = None
            for seq in range(89, 1000):
                if seq not in existing_entries:
                    target_seq = seq
                    break
            if target_seq is None:
                for seq in range(1, 88):
                    if seq not in existing_entries:
                        target_seq = seq
                        break

        if target_seq is None:
            return

        cmds = [
            "enter candidate",
            f"/ acl acl-filter cpm type {filter_type} entry {target_seq} description \"Accept EIGRP\"",
        ]
        for mline in match_lines:
            cmds.append(f"/ acl acl-filter cpm type {filter_type} entry {target_seq} {mline}")
        cmds.append(f"/ acl acl-filter cpm type {filter_type} entry {target_seq} action accept")
        cmds.append("commit now")

        subprocess.run(
            ["sr_cli"],
            input="\n".join(cmds) + "\n",
            capture_output=True, text=True, check=False
        )
    except Exception:
        pass

ensure_cpm("ipv4", ["match ipv4 protocol 88"], re.compile(r"match.*protocol.*88"))
ensure_cpm("ipv6", ["match ipv6 next-header 88"], re.compile(r"match.*next-header.*88"))
EOF
fi

# Reload application manager so YANG schemas and new binary are picked up
sr_cli "tools system app-management application app_mgr reload" >/dev/null 2>&1 || true

# Wait until YANG reload has completed and candidate mode is available
if command -v sr_cli >/dev/null 2>&1; then
    for i in {1..20}; do
        if sr_cli -e "quit" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
fi
