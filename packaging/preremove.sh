#!/bin/bash
action="${1:-remove}"

if [ "$action" = "remove" ] || [ "$action" = "purge" ]; then
    if command -v sr_cli >/dev/null 2>&1; then
        eigrp_cfg=$(sr_cli "info flat / network-instance * protocols eigrp" 2>/dev/null | grep "protocols eigrp" || true)
        if [ -n "$eigrp_cfg" ]; then
            echo "ERROR: Cannot remove srl-eigrpd while EIGRP is configured under / network-instance * protocols eigrp." >&2
            echo "Please delete all EIGRP network-instance protocol configurations prior to package removal." >&2
            exit 1
        fi
        sr_cli "tools system app-management application srl_eigrpd stop" >/dev/null 2>&1 || true
    fi
fi
exit 0
