#!/bin/bash
sr_cli "tools system app-management application srl_eigrpd stop" >/dev/null 2>&1 || true
