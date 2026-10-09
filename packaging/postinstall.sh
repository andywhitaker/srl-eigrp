#!/bin/bash
chmod +x /usr/local/bin/srl-eigrpd

# Auto-provision CPM filter entry for protocol 88 if 'cpm' filter is present
if command -v sr_cli >/dev/null 2>&1; then
    sr_cli -ec "enter candidate; acl acl-filter cpm type ipv4 entry 88 action accept match protocol 88; commit now" >/dev/null 2>&1 || true
    sr_cli -ec "enter candidate; acl acl-filter cpm type ipv6 entry 88 action accept match ipv6 next-header 88; commit now" >/dev/null 2>&1 || true
fi

# Reload application manager so YANG schemas and new binary are picked up
sr_cli "tools system app-management application app_mgr reload" >/dev/null 2>&1 || true
