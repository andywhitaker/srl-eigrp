# Upstream OpenEIGRP (`rel-0.5.0`) Issues & Library Workarounds

**Upstream Repository:** `https://github.com/diivious/eigrp.git`  
**Current Submodule Release / Commit:** `rel-0.5.0` (`a41789b52671f81e5b3e21f02942cf7e3e4121db`)  
**Upstream Maintainer Technical Gist (`openeigrp rel-0.5.0`):** [`5c1fd44c26b933ca70f22079980f5b63`](https://gist.github.com/andywhitaker/5c1fd44c26b933ca70f22079980f5b63)  
**Prior Release Technical Gist (`openeigrp 0.3.0 test re-run`):** [`7104d5892c7ee620c567ec203a440ecc`](https://gist.github.com/andywhitaker/7104d5892c7ee620c567ec203a440ecc)  

---

## Overview

`srl-eigrpd` embeds the upstream OpenEIGRP engine (`src/upstream/eigrp`) as an unmodified Git submodule. When protocol defects are identified in upstream `eigrp/code/`, we keep the submodule working tree clean (`git status` unmodified) and implement targeted workarounds in our C host shim ([`src/cshim/srl_cshim_overrides.c`](../src/cshim/srl_cshim_overrides.c)) using GNU ld symbol wrapping (`-Wl,--wrap=...` in [`src/cmd/srl-eigrpd/bridge.go`](../src/cmd/srl-eigrpd/bridge.go)).

This document outlines each active upstream issue in `rel-0.5.0`, explains why it occurs, and describes how our library works around it. Deeper technical details intended for the OpenEIGRP maintainers—including exact upstream source listings, step-by-step reproducibility descriptions, debug state outputs, and proposed upstream patches—are maintained in the [`openeigrp rel-0.5.0` GitHub Gist (`5c1fd44c26b933ca70f22079980f5b63`)](https://gist.github.com/andywhitaker/5c1fd44c26b933ca70f22079980f5b63).

---

## Summary of Upstream Issues (`rel-0.5.0`)

### Active Issues Worked Around in `srl_cshim_overrides.c`

| Issue | Upstream Component | Summary of Issue | Library Workaround (`src/cshim/srl_cshim_overrides.c`) |
| :--- | :--- | :--- | :--- |
| **Issue 1** | `eigrp_topology.c`<br>`eigrp_pfxlimits.c` | `eigrp_topology_prefix_count()` counts unreachable `QUERY`-retained and `ACTIVE` withdrawing prefixes toward `maximum-prefix`, `eigrp_topology_prefix_admit()` admits any existing `topology_table` entry without checking reachability, and hard limit rejection tears down all AF neighbors. | `__wrap_eigrp_topology_prefix_admit()`<br>`srl_prefix_has_active_route()`<br>`srl_active_topology_prefix_count()` |
| **Issue 2** | `eigrp_query.c`<br>`eigrp_update.c`<br>`eigrp_topology.c` | Un-elected `QUERY`-retained `PASSIVE` routes (`flags == 0`) created by unknown `QUERY` packets are not cleaned up on poisoned `QUERY`, unreachable `UPDATE`, competing neighbor `UPDATE`, or neighbor-down events, allowing them to be falsely promoted into RIB-installed successors. | `__wrap_eigrp_update_receive()`<br>`__wrap_eigrp_query_receive()`<br>`__wrap_eigrp_topology_neighbor_down()`<br>`__wrap_eigrp_nbr_prefix_admit()` |
| **Issue 3** | `eigrp_hello.c`<br>`eigrp_neighbor.c` | Peer `metric-version` renegotiation in `eigrp_sw_version_decode()` updates `nbr->tlv_version` on an already-`UP` neighbor without updating the interface `ei->tlv1_peer_count` / `ei->tlv2_peer_count` counters. | `__wrap_eigrp_nbr_codec_select()`<br>`__wrap_eigrp_nbr_codec_update()` |

### Issues Resolved Upstream in `rel-0.5.0` (Workarounds Removed)

| Prior `rel-0.3.0` Issue | Upstream Resolution in `rel-0.5.0` | Removed C-Shim Workaround |
| :--- | :--- | :--- |
| Manual summary route component loss fails to withdraw Null0/peer summary when other summary interfaces remain up (`eigrp_summary.c`) | Fixed in `31484cf` (`eigrp_summary_Null0_active()`): withdraws the summary when `active_interfaces == 0`. | Removed `__wrap_eigrp_summary_*` wrappers |
| `eigrp_fsm_event_lr()` (`ACTIVE_1`/`ACTIVE_3` → `PASSIVE`) leaves `prefix->fdistance = prefix->distance = EIGRP_MAX_METRIC` (`eigrp_fsm.c`) | Fixed in `4e5dd9c`: restores `distance`, `fdistance`, `reported_metric`, and `rdistance` from `best_route` and calls `eigrp_topology_update_node_flags()`. | Removed `__wrap_eigrp_fsm_event_lr()` |
| `eigrp_route_descriptor_delete()` leaves stale `prefix->req_action` bits referencing freed `prefix->Best_route` (`eigrp_topology.c`) | Fixed in `794df31` / `20a3011`: packetizer queue entries hold explicit route/prefix references. | Removed stale `Best_route` cleanup |
| `eigrp_nbr_delete()` frees `nbr` while poisoned routes remain queued for packetizer withdrawal (`eigrp_neighbor.c`, `eigrp_topology.c`) | Fixed in `20a3011`: reference-counted `nbr->topo_refs` via `eigrp_topology_nbr_hold()` / `eigrp_topology_nbr_release()`. | Removed `route->adv_router = NULL` detachment in neighbor-down wrapper |

---

## Active Issue Details & Library Workarounds

### Issue 1: `maximum-prefix` Accounting, Admission of `QUERY`-Retained Prefixes, and Unconditional AF Neighbor Teardown

- **Upstream Location:** `eigrp/code/eigrp_topology.c` (`eigrp_topology_prefix_count`, `eigrp_topology_prefix_admit`) and `eigrp/code/eigrp_pfxlimits.c` (`eigrp_pfxlimits_prefix_exceeded`)
- **Upstream Technical Gist Section:** [Issue 1 in Gist `5c1fd44c26b933ca70f22079980f5b63`](https://gist.github.com/andywhitaker/5c1fd44c26b933ca70f22079980f5b63)

#### Explanation of the Issue
1. **Non-active prefixes consume `maximum-prefix` capacity**: Upstream `eigrp_topology_prefix_count()` returns `runtime->topology_table->size`, counting every entry in `topology_table` regardless of reachability. When a prefix loses its successor and enters `ACTIVE_1` or `ACTIVE_3` (with its successor route poisoned at `EIGRP_MAX_METRIC` while awaiting neighbor `REPLY`s), or when an unknown `QUERY` creates an unreachable `QUERY`-retained `PASSIVE` descriptor (`distance == EIGRP_MAX_METRIC`), that entry still consumes a slot toward `maximum-prefix`. During route replacement at the `maximum-prefix` boundary, withdrawing prefixes cause legitimate replacement routes to be rejected.
2. **Unconditional admission of existing `topology_table` entries**: At the start of `eigrp_topology_prefix_admit()`, upstream checks `if (eigrp_topology_table_lookup(runtime->topology_table, prefix)) return true;`. Because an unknown `QUERY` inserts a `QUERY`-retained `PASSIVE` descriptor into `topology_table` via `eigrp_nbr_route_admit()` without checking the topology-level `maximum-prefix`, a subsequent finite `UPDATE` for that same prefix matches the lookup and bypasses `maximum-prefix` enforcement.
3. **Unconditional AF-wide neighbor teardown on hard limit rejection**: When `!limit->warning_only && count >= limit->maximum`, `eigrp_topology_prefix_admit()` unconditionally invokes `eigrp_pfxlimits_prefix_exceeded(runtime, limit)`, which sends Graceful Shutdown Hellos and tears down all neighbors in the address family even when no process restart, reset-time, or dampening policy was configured.

#### How We Worked Around the Issue in Our Library
In [`src/cmd/srl-eigrpd/bridge.go`](../src/cmd/srl-eigrpd/bridge.go) and [`src/cshim/srl_cshim_overrides.c`](../src/cshim/srl_cshim_overrides.c), we wrap `eigrp_topology_prefix_admit()` with `-Wl,--wrap=eigrp_topology_prefix_admit`:
- **`srl_prefix_has_active_route()` (`srl_cshim_overrides.c:37-46`)**: Checks that a prefix descriptor has finite `pfx->distance` and `pfx->fdistance`, and that its best route (`eigrp_topology_route_read(pfx)`) has a finite metric and carries either `EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG` or `EIGRP_ROUTE_DESCRIPTOR_FSUCCESSOR_FLAG`. This excludes both `QUERY`-retained `PASSIVE` placeholders and `ACTIVE` withdrawing prefixes (even when an `ACTIVE` prefix still holds a non-feasible `flags == 0` candidate).
- **`srl_active_topology_prefix_count()` (`srl_cshim_overrides.c:48-61`)**: Iterates `runtime->topology_table` and counts only prefixes that satisfy `srl_prefix_has_active_route()`.
- **`__wrap_eigrp_topology_prefix_admit()` (`srl_cshim_overrides.c:80-114`)**:
  - Only fast-paths existing `topology_table` descriptors when `srl_prefix_has_active_route(existing)` is `true`.
  - Evaluates threshold warnings and hard limits against `srl_active_topology_prefix_count(runtime)`.
  - When a hard limit is reached (`!limit->warning_only && count >= limit->maximum`), prunes any cached `QUERY`-retained routes on `existing` (`srl_prune_other_query_retained_routes()` and `eigrp_update_topology_table_prefix()`), logs `EIGRP_EVENTLOG_OPCODE_PREFIX_LIMIT_REJECT`, and returns `false` without calling `eigrp_pfxlimits_prefix_exceeded()`, preserving established neighbor adjacencies.

---

### Issue 2: `QUERY`-Retained `PASSIVE` Routes Leak Across Unreachable `UPDATE`s, Poisoned `QUERY`s, Competing Neighbor `UPDATE`s, and Neighbor-Down Events

- **Upstream Location:** `eigrp/code/eigrp_query.c` (`eigrp_query_unknown_route_record`, `eigrp_query_receive`), `eigrp/code/eigrp_update.c` (`eigrp_update_receive`), and `eigrp/code/eigrp_topology.c` (`eigrp_topology_neighbor_down`)
- **Upstream Technical Gist Section:** [Issue 2 in Gist `5c1fd44c26b933ca70f22079980f5b63`](https://gist.github.com/andywhitaker/5c1fd44c26b933ca70f22079980f5b63)

#### Explanation of the Issue
When an EIGRP router receives a finite-metric `QUERY` for an unknown destination, `eigrp_query_unknown_route_record()` creates a `PASSIVE` prefix descriptor with `distance = fdistance = reported_metric.delay = EIGRP_MAX_METRIC` and stores a route descriptor (`flags == 0`) recording the querying neighbor's finite metric. Upstream `rel-0.5.0` fails to clean up these un-elected `QUERY`-retained route descriptors across four transitions:
1. **Poisoned or inbound-filtered `QUERY`**: If a neighbor that previously sent a finite `QUERY` sends a subsequent poisoned `QUERY` (`delay == EIGRP_MAX_METRIC` or `EIGRP_METRIC_MAX`) or is denied by an inbound filter while the prefix is still in the `QUERY`-retained `PASSIVE` state, `eigrp_query_unknown_route_record()` returns `false` at its entry guard without deleting the neighbor's previously stored finite route descriptor.
2. **Unreachable `UPDATE` on a `QUERY`-retained prefix**: If two neighbors (`nbr1` and `nbr2`) both have cached `QUERY`-retained routes under an unknown `PASSIVE` prefix and `nbr2` later sends an unreachable `UPDATE` (`delay == EIGRP_MAX_METRIC`), `eigrp_update_receive()` sees `topology_route != NULL` and dispatches the withdrawal into `eigrp_fsm_event()`. Inside `eigrp_fsm_event_keep_state()`, `eigrp_topology_route_select()` promotes `nbr1`'s un-elected `QUERY`-retained route into a RIB-installed `SUCCESSOR` even though `nbr1` never sent an `UPDATE`.
3. **Reachable `UPDATE` from a competing neighbor**: In the same two-neighbor scenario, if `nbr2` sends a reachable `UPDATE` whose metric is higher than `nbr1`'s cached `QUERY` metric, `eigrp_topology_route_select()` compares both routes and elects `nbr1`'s un-elected `QUERY` route as successor instead of `nbr2`'s `UPDATE`.
4. **Neighbor-down on a `QUERY`-retained prefix**: When `nbr2` goes down while a `QUERY`-retained `PASSIVE` prefix holds cached `QUERY` routes from both `nbr1` and `nbr2`, `eigrp_topology_neighbor_down()` dispatches a synthetic poisoned `UPDATE` into `eigrp_fsm_event()`, again causing `eigrp_topology_route_select()` to elect `nbr1`'s un-elected `QUERY` route into the RIB.

#### How We Worked Around the Issue in Our Library
Because `eigrp_query_unknown_route_record()` is `static` inside `eigrp_query.c` and per-TLV processing happens inside the loops of `eigrp_update_receive()` and `eigrp_query_receive()`, [`src/cshim/srl_cshim_overrides.c`](../src/cshim/srl_cshim_overrides.c) combines symbol wrappers (`-Wl,--wrap=eigrp_update_receive`, `-Wl,--wrap=eigrp_query_receive`, `-Wl,--wrap=eigrp_topology_neighbor_down`, and `-Wl,--wrap=eigrp_nbr_prefix_admit`) with temporary thread-local `nbr->decoder` interception:
- **`srl_prefix_is_query_retained_passive()` (`srl_cshim_overrides.c:28-35`)**: Identifies `PASSIVE` prefix descriptors with `distance == EIGRP_MAX_METRIC`, `fdistance == EIGRP_MAX_METRIC`, and `reported_metric.delay == EIGRP_MAX_METRIC`.
- **`__wrap_eigrp_update_receive()` & `srl_update_tlv_decoder_intercept()` (`srl_cshim_overrides.c:128-189`)**:
  - Temporarily interposes `srl_update_tlv_decoder_intercept()` on `nbr->decoder` while `__real_eigrp_update_receive()` decodes TLVs from the packet stream.
  - If a decoded `UPDATE` TLV is unreachable (`eigrp_metric_calculate(eigrp, route->metric) == EIGRP_MAX_METRIC`) and targets a `QUERY`-retained `PASSIVE` prefix, the interceptor deletes `nbr`'s cached route descriptor via `eigrp_route_descriptor_delete()`, cleans up the prefix via `eigrp_update_topology_table_prefix()`, frees the decoded route, and returns `NULL` so `eigrp_update_receive()` skips `eigrp_fsm_event()`. (While processing an unreachable `UPDATE`, `srl_in_unreachable_update` also ensures `__wrap_eigrp_nbr_prefix_admit()` always permits withdrawals.)
  - If a decoded `UPDATE` TLV is reachable and targets a `QUERY`-retained `PASSIVE` prefix, the interceptor calls `srl_prune_other_query_retained_routes(eigrp, prefix, nbr)` (`srl_cshim_overrides.c:63-78`) to delete any `flags == 0` routes cached from other neighbors before `eigrp_update_receive()` invokes `eigrp_fsm_event()`.
- **`__wrap_eigrp_query_receive()` & `srl_query_tlv_decoder_intercept()` (`srl_cshim_overrides.c:191-238`)**:
  - Temporarily interposes `srl_query_tlv_decoder_intercept()` on `nbr->decoder` while `__real_eigrp_query_receive()` runs.
  - When a decoded `QUERY` TLV targets a `QUERY`-retained `PASSIVE` prefix and is poisoned (`delay == EIGRP_MAX_METRIC` or `EIGRP_METRIC_MAX`) or denied by an inbound filter (`eigrp_filter_prefix_update()`), the interceptor deletes `nbr`'s previously cached route descriptor and updates the prefix before `eigrp_query_unknown_route_record()` returns `false`.
- **`__wrap_eigrp_topology_neighbor_down()` (`srl_cshim_overrides.c:242-260`)**:
  - Before invoking `__real_eigrp_topology_neighbor_down()`, iterates `eigrp->topology_table` and removes `nbr`'s route descriptor from any `QUERY`-retained `PASSIVE` prefix directly (`eigrp_route_descriptor_delete()` + `eigrp_update_topology_table_prefix()`), preventing `__real_eigrp_topology_neighbor_down()` from running `eigrp_fsm_event()` on `QUERY`-retained prefixes.

---

### Issue 3: Peer Metric-Version Renegotiation in `eigrp_sw_version_decode()` Does Not Update Interface `tlv1_peer_count` / `tlv2_peer_count`

- **Upstream Location:** `eigrp/code/eigrp_hello.c` (`eigrp_sw_version_decode`) and `eigrp/code/eigrp_neighbor.c` (`eigrp_nbr_codec_update`)
- **Upstream Technical Gist Section:** [Issue 3 in Gist `5c1fd44c26b933ca70f22079980f5b63`](https://gist.github.com/andywhitaker/5c1fd44c26b933ca70f22079980f5b63)

#### Explanation of the Issue
Each EIGRP interface maintains `ei->tlv1_peer_count` (32-bit classic TLV peers) and `ei->tlv2_peer_count` (64-bit wide TLV peers) across its `UP` neighbors to select the TLV encoding for outbound multicast `UPDATE` and `QUERY` packets. While upstream commit `77e976a` updated `eigrp_nbr_codec_update()` so that local `metric-version` changes adjust `ei->tlv1_peer_count` and `ei->tlv2_peer_count` for `UP` neighbors, `eigrp_sw_version_decode()` (`eigrp_hello.c:198-218`) still calls `eigrp_nbr_codec_select()` directly without adjusting the interface peer counters. If an already-`UP` peer changes its advertised `eigrp_major` version in a `HELLO` packet before its hold timer expires, `nbr->tlv_version` is overwritten while `ei->tlv1_peer_count` and `ei->tlv2_peer_count` retain the old version count, causing multicast TLV encoding mismatches and counter underflow when the neighbor later goes down.

#### How We Worked Around the Issue in Our Library
Because `eigrp_sw_version_decode()` is `static` in `eigrp_hello.c`, we wrap `eigrp_nbr_codec_select()` and `eigrp_nbr_codec_update()` in [`src/cshim/srl_cshim_overrides.c`](../src/cshim/srl_cshim_overrides.c) (`-Wl,--wrap=eigrp_nbr_codec_select -Wl,--wrap=eigrp_nbr_codec_update`):
- **`__wrap_eigrp_nbr_codec_update()` (`srl_cshim_overrides.c:278-283`)**: Sets a thread-local flag `srl_in_codec_update = true` around `__real_eigrp_nbr_codec_update(eigrp)` so that counter updates already performed by `eigrp_nbr_codec_update()` are not duplicated.
- **`__wrap_eigrp_nbr_codec_select()` (`srl_cshim_overrides.c:267-276`)**: Records `old_version = nbr->tlv_version` before calling `__real_eigrp_nbr_codec_select(nbr, tlv_version)`. If `!srl_in_codec_update`, `nbr->state == EIGRP_NEIGHBOR_UP`, and `old_version != nbr->tlv_version`, it calls `eigrp_intf_encoder_peer_remove(nbr->ei, old_version)` and `eigrp_intf_encoder_peer_add(nbr->ei, nbr->tlv_version)` to keep the interface encoder peer counts accurate.

---

## Verification of Library Workarounds

All three C-shim workarounds are exercised by the built-in unit test harness `srlTestRel030OverridesCheck()` (`src/cshim/srl_cshim_overrides.c:301-534`), invoked via `go test` (`TestRel030OverridesCheck` in `src/cmd/srl-eigrpd/config_test.go`), as well as the 5-node Nokia SR Linux Containerlab integration suite (`tests/test_5node_lab.py`).
