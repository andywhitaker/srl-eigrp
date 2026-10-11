#!/bin/bash
action="${1:-remove}"

if [ "$action" = "purge" ] || [ "$action" = "remove" ]; then
    # Remove CPM filter entries on package purge/removal
    if command -v sr_cli >/dev/null 2>&1; then
        python3 - << 'EOF' || true
import subprocess
import re

def remove_cpm(filter_type, match_regex):
    try:
        res = subprocess.run(
            ["sr_cli", f"info flat acl acl-filter cpm type {filter_type}"],
            capture_output=True, text=True, check=False
        )
        if res.returncode != 0:
            return

        lines = res.stdout.splitlines()
        entries_to_delete = set()

        for line in lines:
            if match_regex.search(line) or "Accept EIGRP" in line:
                m = re.search(r"acl-filter cpm type \S+ entry (\d+)", line)
                if m:
                    entries_to_delete.add(int(m.group(1)))

        if not entries_to_delete:
            return

        cmds = ["enter candidate"]
        for seq in entries_to_delete:
            cmds.append(f"/ acl acl-filter cpm type {filter_type} entry {seq} delete")
        cmds.append("commit now")

        subprocess.run(
            ["sr_cli"],
            input="\n".join(cmds) + "\n",
            capture_output=True, text=True, check=False
        )
    except Exception:
        pass

remove_cpm("ipv4", re.compile(r"match.*protocol.*88"))
remove_cpm("ipv6", re.compile(r"match.*next-header.*88"))
EOF

        # Reload AppMgr so unlinked application is deregistered
        sr_cli "tools system app-management application app_mgr reload" >/dev/null 2>&1 || true
    fi
fi
exit 0
