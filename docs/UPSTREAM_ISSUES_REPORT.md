# Upstream OpenEIGRP (`diivious/eigrp`) Bug Report & Patch Set

**Upstream Repository**: `https://github.com/diivious/eigrp`  
**Evaluated Commit**: `951d7549beb447b8f9c42b4f253638b392729491`  
**Test Environment**: 5-Node Nokia SR Linux Containerlab Diamond/Mesh Topology (`srl1`–`srl5`) & Upstream `eigrp-uut-node` Test Harness (`eigrp/test/uut`)

---

## Executive Summary

During live multi-router integration and protocol verification of `diivious/eigrp` across a 5-node Nokia SR Linux topology (covering DUAL Feasible Successor failover, active query/reply convergence, peer process restarts, dual-stack IPv4/IPv6, manual and auto summarization with `leak-map`, multi-protocol redistribution, `maximum-prefix`, and K-value/interface metric updates), **four upstream defects** (spanning 4 files in `eigrp/code/`) were identified in portable core EIGRP code (`eigrp/code/`).

To keep the `src/upstream/eigrp` git submodule completely unmodified (`git status` clean), all four defects are currently mitigated in our host build via linker symbol wrapping (`-Wl,--wrap=...`) in [`src/cshim/srl_cshim_overrides.c`](file:///home/awhitaker/dev/srl-eigrp/src/cshim/srl_cshim_overrides.c). Once the fixes below are merged upstream into `diivious/eigrp`, `srl_cshim_overrides.c` and the corresponding `--wrap` flags in [`src/cmd/srl-eigrpd/bridge.go`](file:///home/awhitaker/dev/srl-eigrp/src/cmd/srl-eigrpd/bridge.go) can be removed in their entirety.

| # | Upstream File(s) | Function(s) | Summary of Defect | Severity |
| :- | :--- | :--- | :--- | :--- |
| **1** | `eigrp/code/eigrp_update.c` | `eigrp_update_receive()` | `nbr->peer_init_sequence_number` is never cleared/advanced after the initial `INIT`/`EOT` exchange completes, causing a restarted neighbor whose new `INIT` uses `sequence = 1` to be misclassified as a duplicate retransmission and ignored instead of triggering the `peer restarted` handler. In addition, the `peer restarted` handler cancels `nbr->t_holddown` via `EIGRP_NEIGHBOR_DOWN` without re-arming `eigrp_nbr_holddown_update(nbr)`. | **High** |
| **2** | `eigrp/code/eigrp_topology.c` | `eigrp_topology_metric_update()` | Recalculating topology metrics (on K-value, metric-version, or interface metric change) overwrites `route->reported_distance` (must remain `0`) on self-originated connected/redistributed routes (`RD == FD`, stripping `SUCCESSOR` flag), double-adds interface delay and increments `hop_count` on connected routes, fails to scale `delay` on self-originated redistributed routes, and sets `prefix->rdistance` / `prefix->reported_metric` to the predecessor's metric instead of `best->distance` / `best->total_metric`. | **High** |
| **3** | `eigrp/code/eigrp_topology.c`<br>`eigrp/code/eigrp_update.c` | `eigrp_topology_prefix_count()`<br>`eigrp_topology_prefix_admit()`<br>`eigrp_update_receive()` | `eigrp_update_topology_table_prefix()` intentionally retains empty PASSIVE `eigrp_prefix_descriptor_t` shells in `eigrp->topology_table` after all RDBs are withdrawn/retired. `eigrp_topology_prefix_count()` counts those retired/poisoned shells toward `topology_maximum_prefix` (causing premature limit exhaustion after route churn), while `eigrp_update_receive()` (in its `if (prefix != NULL)` branch) omits `eigrp_topology_prefix_admit()` and `eigrp_topology_prefix_admit()` unconditionally returns `true` for any existing shell in `topology_table`. | **Medium-High** |
| **4** | `eigrp/code/eigrp_summary.c`<br>`eigrp/code/eigrp_query.c` | `eigrp_summary_route_build()`<br>`eigrp_summary_query_route_build()`<br>`eigrp_query_receive()` | Synthesized summary routes copy `best_route->metric` (predecessor's reported vector) instead of `best_route->total_metric` (local accumulated vector), inherit `best_route->ei` (causing split-horizon poison reverse to poison the summary with `EIGRP_MAX_METRIC` whenever `best_route->ei == ei`), inherit `best_route->type` (advertising an External TLV if the best component is redistributed), and leak suppressed component routes when a neighbor sends a `QUERY` for a covered component prefix. | **High** |

---

## Detailed Defect Analysis & Proposed Upstream Patches

---

### Defect 1: `eigrp_update.c` — Peer Restart Ignored When Restarted Neighbor Reuses `INIT` Sequence `1`, and `t_holddown` Left Disarmed After Peer Restart

- **Affected File**: `eigrp/code/eigrp_update.c`
- **Affected Function**: `eigrp_update_receive()` (lines 159–168 and 251–266)
- **Wrapper Workaround**: `__wrap_eigrp_update_receive()` in [`src/cshim/srl_cshim_overrides.c`](file:///home/awhitaker/dev/srl-eigrp/src/cshim/srl_cshim_overrides.c#L334-L352)

#### Root Cause
1. **Stale `nbr->peer_init_sequence_number` blocks peer restart detection**:
   - In commit `4288e52`, `nbr->peer_init_sequence_number` was added to `eigrp_update_receive()` (`eigrp_update.c:159–167`) to handle a retransmitted `INIT` UPDATE after a lost ACK (`eigrp/test/rtp/lost-ack.yaml`), because `eigrp_packet_ack()` (`eigrp_packet.c:391`) overwrites `nbr->recv_sequence_number = ntohl(eigrph->sequence)` (`0` on a Hello ACK):
     ```c
     if (flags == EIGRP_INIT_FLAG
         && ntohl(eigrph->sequence) != 0
         && nbr->peer_init_sequence_number == ntohl(eigrph->sequence)) {
         eigrp_hello_send_ack_sequence(nbr, ntohl(eigrph->sequence));
         return;
     }
     peer_init_previously_seen = nbr->peer_init_sequence_number != 0;
     if (flags == EIGRP_INIT_FLAG && !peer_init_previously_seen)
         nbr->peer_init_sequence_number = ntohl(eigrph->sequence);
     ```
   - Every new or restarted OpenEIGRP instance initializes `eigrp->sequence_number = 1` (`eigrp_instance.c:262`), so its first reliable packet (`INIT` UPDATE) is always transmitted with `sequence = 1` (`eigrp_packet_sequence_reserve()`).
   - Because `nbr->peer_init_sequence_number` remains `1` for the entire lifetime of the `UP` adjacency and is never cleared or advanced after the initial `INIT`/`EOT` exchange completes, if the peer daemon restarts before the local hold timer expires and sends a fresh `INIT` UPDATE with `sequence = 1`, `nbr->peer_init_sequence_number == ntohl(eigrph->sequence)` evaluates to `true`.
   - The surviving router ACKs `sequence = 1` (`eigrp_hello_send_ack_sequence(nbr, 1)`) and returns early at line 163—never reaching the `peer restarted` state-reset block at lines 251–266! Because the surviving router neither resets the neighbor nor sends its own `INIT` UPDATE, the restarted peer never receives the surviving router's `INIT`/`EOT` topology table and stale routes from the restarted peer's prior incarnation remain installed.
   - Once the surviving router receives any reliable non-`INIT` UPDATE (`!(flags & EIGRP_INIT_FLAG) && ntohl(eigrph->sequence) != 0`) from the peer, the peer has already received our ACK for its `INIT` UPDATE and exited `EIGRP_NEIGHBOR_PENDING` (`eigrp_packet.c:378–392`), so it will never retransmit that `INIT`. Advancing `nbr->peer_init_sequence_number` to a non-zero sentinel (`UINT32_MAX`) at that point preserves `peer_init_previously_seen == true` while allowing a subsequent `INIT` with `sequence = 1` from a restarted peer to reach line 251.

2. **Disarmed `nbr->t_holddown` after `peer restarted` state transition**:
   - In the `peer restarted` block (`eigrp_update.c:251–266`):
     ```c
     if (nbr->state == EIGRP_NEIGHBOR_UP && peer_init_previously_seen) {
         eigrp_debug_nsf_event(eigrp, nbr, flags, "peer restarted");
         eigrp_update_nsf_eventlog(eigrp, nbr, 4, flags,
             ntohl(eigrph->sequence));
         eigrp_nbr_state_update_reason(EIGRP_SET, nbr, EIGRP_NEIGHBOR_DOWN,
             EIGRP_EVENTLOG_NEIGHBOR_REASON_PEER_RESTART);
         eigrp_topology_neighbor_down(nbr->ei->eigrp, nbr);
         nbr->peer_init_sequence_number = ntohl(eigrph->sequence);
         nbr->recv_sequence_number = ntohl(eigrph->sequence);
         if (eigrp->log_neighbor_changes)
             eigrp_log(EIGRP_LOG_INFO, "Neighbor %s (%s) is down: peer restarted",
                       eigrp_print_addr(&nbr->src),
                       nbr->ei->name);
         eigrp_nbr_state_update(EIGRP_SET, nbr, EIGRP_NEIGHBOR_PENDING);
         eigrp_update_send_init(eigrp, nbr);
     }
     ```
   - Calling `eigrp_nbr_state_update_reason(EIGRP_SET, nbr, EIGRP_NEIGHBOR_DOWN, ...)` at line 255 cancels `nbr->t_holddown` (`eigrp_neighbor.c:1047`).
   - Because commit `4288e52` moved `eigrp_nbr_holddown_update(nbr)` out of `eigrp_update_receive()` into `eigrp_packet_ingress_authenticate()` (`eigrp_packet.c:2117`, which runs before `eigrp_update_receive()`), transitioning `nbr` to `EIGRP_NEIGHBOR_PENDING` at line 264 leaves `nbr->t_holddown == NULL` unless `eigrp_nbr_holddown_update(nbr)` is called after resetting the state.

#### Proposed Upstream Patch
```diff
--- a/eigrp/code/eigrp_update.c
+++ b/eigrp/code/eigrp_update.c
@@ -165,6 +165,9 @@ void eigrp_update_receive(eigrp_instance_t *eigrp, eigrp_nbr_t *nbr,
 	peer_init_previously_seen = nbr->peer_init_sequence_number != 0;
 	if (flags == EIGRP_INIT_FLAG && !peer_init_previously_seen)
 		nbr->peer_init_sequence_number = ntohl(eigrph->sequence);
+	else if (!(flags & EIGRP_INIT_FLAG) && ntohl(eigrph->sequence) != 0
+		 && peer_init_previously_seen)
+		nbr->peer_init_sequence_number = UINT32_MAX;
 
 	same = 0;
 	graceful_restart = 0;
@@ -262,6 +265,7 @@ void eigrp_update_receive(eigrp_instance_t *eigrp, eigrp_nbr_t *nbr,
 					  eigrp_print_addr(&nbr->src),
 					  nbr->ei->name);
 			eigrp_nbr_state_update(EIGRP_SET, nbr, EIGRP_NEIGHBOR_PENDING);
+			eigrp_nbr_holddown_update(nbr);
 			eigrp_update_send_init(eigrp, nbr);
 		}
 	}
```

---

### Defect 2: `eigrp_topology.c` — `eigrp_topology_metric_update()` Corrupts Self-Originated Connected/Redistributed Routes and Advertised Metric State

- **Affected File**: `eigrp/code/eigrp_topology.c`
- **Affected Function**: `eigrp_topology_metric_update()` (lines 1245–1283)
- **Wrapper Workaround**: `__wrap_eigrp_topology_metric_update()` in [`src/cshim/srl_cshim_overrides.c`](file:///home/awhitaker/dev/srl-eigrp/src/cshim/srl_cshim_overrides.c#L46-L112)

#### Root Cause
Whenever metric weights (`K1`–`K6` via `eigrp_metric_weights_update()`), metric version (`eigrp_metric_version_update()`), or interface metrics are updated at runtime, `eigrp_topology_metric_update(eigrp)` walks all `PASSIVE` prefixes in `eigrp->topology_table` (`eigrp_topology.c:1259–1276`):

```c
		for (route = eigrp_topology_route_iterator_first(prefix, &iterator); route;
		     route = eigrp_topology_route_iterator_next(&iterator)) {
			route->reported_distance = eigrp_metric_calculate(eigrp, route->reported_metric);
			if (route->ei)
				route->distance = eigrp_metric_total_calculate(eigrp, route);
			else
				route->distance = eigrp_metric_calculate(eigrp, route->total_metric);
		}
		eigrp_topology_route_queue_resort(prefix->internal_routes);
		eigrp_topology_route_queue_resort(prefix->external_routes);
		best = eigrp_topology_route_read(prefix);
		if (best) {
			prefix->distance = best->distance;
			prefix->fdistance = best->distance;
			prefix->rdistance = best->reported_distance;
			prefix->reported_metric = best->reported_metric;
		}
		eigrp_topology_update_node_flags(eigrp, prefix);
```

This loop has four bugs:

1. **Self-originated routes have `reported_distance` overwritten (`RD == FD`), stripping their `SUCCESSOR` flag**:
   - When connected routes (`eigrp_interface.c:1510`) and locally redistributed routes (`eigrp_topology.c:767, 1065`) are created, they set `route->adv_router = eigrp->neighbor_self` and `route->reported_distance = 0`.
   - `eigrp_topology_metric_update()` unconditionally overwrites `route->reported_distance = eigrp_metric_calculate(eigrp, route->reported_metric);`.
   - Because `prefix->fdistance` is then set to `best->distance`, `route->reported_distance < prefix->fdistance` becomes `false` (`RD == FD`) for the self-originated route!
   - Immediately afterward, `eigrp_topology_update_node_flags(eigrp, prefix)` (`eigrp_topology.c:1151`) checks `bool feasible = route->reported_distance < dest->fdistance;`—which evaluates to `false`—and clears `EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG` on the router's own connected and redistributed routes (`0 successors`)!

2. **Connected routes (`route->adv_router == eigrp->neighbor_self && route->ei != NULL`) double-add interface delay and increment `hop_count`**:
   - For a connected route, `route->reported_metric` already holds the interface's scaled delay (`eigrp_interface.c:1477, 1506–1508`) and `hop_count = 0`.
   - Calling `eigrp_metric_total_calculate(eigrp, route)` (`eigrp_metric.c:139–174`) adds `eigrp_delay_to_scaled(ei->params.delay)` onto `route->reported_metric.delay` a second time and increments `route->total_metric.hop_count` from `0` to `1`.

3. **Locally redistributed routes (`route->adv_router == eigrp->neighbor_self && route->ei == NULL`) fail to scale `delay`**:
   - Locally redistributed routes store the unscaled seed delay (in tens of microseconds) in `route->metric.delay` / `route->total_metric.delay` and compute their distance via `eigrp_topology_redistributed_distance(eigrp, &route->metric)` (`eigrp_topology.c:147–166`, which scales `delay` via `eigrp_delay_to_scaled()`).
   - Calling `eigrp_metric_calculate(eigrp, route->total_metric)` directly at line 1265 uses the unscaled `delay` (off by $256\times$) instead of `eigrp_topology_redistributed_distance(eigrp, &route->metric)`.

4. **`prefix->rdistance` and `prefix->reported_metric` are set to the predecessor's metric instead of `best->distance` / `best->total_metric`**:
   - Setting `prefix->rdistance = best->reported_distance` and `prefix->reported_metric = best->reported_metric` at lines 1273–1274 contradicts `eigrp_update.c:389–391` and `eigrp_fsm.c:774–777, 807–809, 924–925`, which set `prefix->rdistance = best->distance` and `prefix->reported_metric = best->total_metric`.

#### Proposed Upstream Patch
```diff
--- a/eigrp/code/eigrp_topology.c
+++ b/eigrp/code/eigrp_topology.c
@@ -1258,11 +1258,36 @@ void eigrp_topology_metric_update(eigrp_instance_t *eigrp)
 			continue;
 		for (route = eigrp_topology_route_iterator_first(prefix, &iterator); route;
 		     route = eigrp_topology_route_iterator_next(&iterator)) {
-			route->reported_distance = eigrp_metric_calculate(eigrp, route->reported_metric);
-			if (route->ei)
-				route->distance = eigrp_metric_total_calculate(eigrp, route);
-			else
-				route->distance = eigrp_metric_calculate(eigrp, route->total_metric);
+			if (route->adv_router == eigrp->neighbor_self) {
+				route->reported_distance = 0;
+				if (route->metric.delay == EIGRP_MAX_METRIC) {
+					route->distance = EIGRP_MAX_METRIC;
+				} else if (route->ei) {
+					eigrp_metrics_t metric = route->metric;
+
+					metric.bandwidth = eigrp_bandwidth_to_scaled(
+						route->ei->params.bandwidth);
+					metric.delay = eigrp_delay_to_scaled(
+						route->ei->params.delay);
+					metric.load = route->ei->params.load;
+					metric.reliability = route->ei->params.reliability;
+					metric.hop_count = 0;
+					route->metric = metric;
+					route->reported_metric = metric;
+					route->total_metric = metric;
+					route->distance = eigrp_metric_calculate(eigrp, metric);
+				} else {
+					route->distance = eigrp_topology_redistributed_distance(
+						eigrp, &route->metric);
+				}
+			} else {
+				route->reported_distance =
+					eigrp_metric_calculate(eigrp, route->reported_metric);
+				if (route->ei)
+					route->distance = eigrp_metric_total_calculate(eigrp, route);
+				else
+					route->distance = eigrp_metric_calculate(eigrp, route->total_metric);
+			}
 		}
 		eigrp_topology_route_queue_resort(prefix->internal_routes);
 		eigrp_topology_route_queue_resort(prefix->external_routes);
@@ -1270,8 +1295,8 @@ void eigrp_topology_metric_update(eigrp_instance_t *eigrp)
 		if (best) {
 			prefix->distance = best->distance;
 			prefix->fdistance = best->distance;
-			prefix->rdistance = best->reported_distance;
-			prefix->reported_metric = best->reported_metric;
+			prefix->rdistance = best->distance;
+			prefix->reported_metric = best->total_metric;
 		}
 		eigrp_topology_update_node_flags(eigrp, prefix);
 		eigrp_update_routing_table(eigrp, prefix);
```

---

### Defect 3: `eigrp_topology.c` & `eigrp_update.c` — Topology `maximum-prefix` Counts Retired/Poisoned Descriptors and Bypasses Admission on Re-Advertised Prefixes

- **Affected Files**:
  - `eigrp/code/eigrp_topology.c` (`eigrp_topology_prefix_count()`, lines 2273–2285; `eigrp_topology_prefix_admit()`, lines 2287–2315)
  - `eigrp/code/eigrp_update.c` (`eigrp_update_receive()`, lines 286–303)
- **Wrapper Workaround**: `__wrap_eigrp_topology_prefix_admit()` and `__wrap_eigrp_nbr_prefix_admit()` in [`src/cshim/srl_cshim_overrides.c`](file:///home/awhitaker/dev/srl-eigrp/src/cshim/srl_cshim_overrides.c#L270-L330)

#### Root Cause
1. **Empty/retired `eigrp_prefix_descriptor_t` shells remain in `eigrp->topology_table` by design**:
   - In `eigrp_update_topology_table_prefix()` (`eigrp_topology.c:1495–1505`), when all unreachable route descriptors (`RDB`s) for a destination are retired and removed from `prefix->internal_routes` / `prefix->external_routes`, upstream intentionally keeps the `eigrp_prefix_descriptor_t` (`rn->info != NULL`) in `eigrp->topology_table`:
     ```c
     /* Keep the PASSIVE destination descriptor after its unreachable RDBs
      * have been retired. A later UPDATE can repopulate the same DUAL
      * destination without manufacturing stale route ownership. */
     ```
   - Additionally, when a neighbor sends a poison-reverse `UPDATE` (`delay == EIGRP_MAX_METRIC`) during initial convergence or withdrawal, `eigrp_update_receive()` (`eigrp_update.c:348–396`) creates a `prefix` descriptor in `eigrp->topology_table` whose RDB is then retired.

2. **`eigrp_topology_prefix_count()` counts retired and poisoned prefix descriptors**:
   - Unlike `eigrp_nbr_prefix_count()` (`eigrp_neighbor.c:563`, which checks `eigrp_prefix_descriptor_lookup(prefix, neighbor)`) and `eigrp_redist_prefix_count()` (`eigrp_redistribute.c:327`, which walks `prefix->external_routes`), `eigrp_topology_prefix_count()` (`eigrp_topology.c:2273–2285`) increments `count` for every `if (node->info)` in `runtime->topology_table`:
     ```c
     for (node = eigrp_table_first(runtime->topology_table); node;
          node = eigrp_table_next(node))
         if (node->info)
             count++;
     ```
   - Because retired prefix descriptors (`eigrp_topology_route_read(pfx) == NULL`) and poisoned descriptors (`best->distance == EIGRP_MAX_METRIC || best->metric.delay == EIGRP_MAX_METRIC`) remain in `runtime->topology_table`, every withdrawn prefix permanently consumes a slot against `topology_maximum_prefix`.

3. **Re-advertising a previously retired prefix bypasses `eigrp_topology_prefix_admit()`**:
   - When a prefix that was previously withdrawn (leaving a retired `eigrp_prefix_descriptor_t` shell in `eigrp->topology_table`) is later re-advertised:
     - In `eigrp_update_receive()` (`eigrp_update.c:286–303`), `prefix = eigrp_topology_table_lookup(eigrp->topology_table, &route->dest)` is non-NULL, so execution takes the `if (prefix != NULL)` branch at line 286.
     - At lines 298–302, it checks `if (!topology_route && !eigrp_nbr_prefix_admit(eigrp, nbr, &received_route->dest))` but **omits `|| !eigrp_topology_prefix_admit(eigrp, &received_route->dest)`** (which is only called in the `else` branch at line 344).
     - Furthermore, in `eigrp_topology_prefix_admit()` (`eigrp_topology.c:2295–2296`), `if (eigrp_topology_table_lookup(runtime->topology_table, prefix)) return true;` returns `true` for any retired `eigrp_prefix_descriptor_t` shell even when `eigrp_topology_route_read(existing)` is `NULL` or poisoned!

#### Proposed Upstream Patch
```diff
--- a/eigrp/code/eigrp_topology.c
+++ b/eigrp/code/eigrp_topology.c
@@ -2278,9 +2278,17 @@ static uint32_t eigrp_topology_prefix_count(eigrp_instance_t *runtime)
 	if (!runtime || !runtime->topology_table)
 		return 0;
 	for (node = eigrp_table_first(runtime->topology_table); node;
-	     node = eigrp_table_next(node))
-		if (node->info)
+	     node = eigrp_table_next(node)) {
+		eigrp_prefix_descriptor_t *pfx = node->info;
+		eigrp_route_descriptor_t *best;
+
+		if (!pfx)
+			continue;
+		best = eigrp_topology_route_read(pfx);
+		if (best && best->distance != EIGRP_MAX_METRIC
+		    && best->metric.delay != EIGRP_MAX_METRIC)
 			count++;
+	}
 	return count;
 }
 
@@ -2289,11 +2297,17 @@ bool eigrp_topology_prefix_admit(eigrp_instance_t *runtime,
 {
 	eigrp_af_config_t *af;
 	const eigrp_prefix_limit_t *limit;
+	eigrp_prefix_descriptor_t *existing;
 
 	if (!runtime || !prefix)
 		return false;
-	if (eigrp_topology_table_lookup(runtime->topology_table, prefix))
-		return true;
+	existing = eigrp_topology_table_lookup(runtime->topology_table, prefix);
+	if (existing) {
+		eigrp_route_descriptor_t *best = eigrp_topology_route_read(existing);
+		if (best && best->distance != EIGRP_MAX_METRIC
+		    && best->metric.delay != EIGRP_MAX_METRIC)
+			return true;
+	}
 	af = eigrp_af_config_runtime_read(runtime);
 	if (!af || !af->topology_maximum_prefix_configured)
 		return true;
--- a/eigrp/code/eigrp_update.c
+++ b/eigrp/code/eigrp_update.c
@@ -296,7 +296,8 @@ void eigrp_update_receive(eigrp_instance_t *eigrp, eigrp_nbr_t *nbr,
 				bool free_received_route = false;
 
 				if (!topology_route
-				    && !eigrp_nbr_prefix_admit(eigrp, nbr, &received_route->dest)) {
+				    && (!eigrp_nbr_prefix_admit(eigrp, nbr, &received_route->dest)
+					|| !eigrp_topology_prefix_admit(eigrp, &received_route->dest))) {
 					eigrp_topology_route_free(received_route);
 					continue;
 				}
```

---

### Defect 4: `eigrp_summary.c` & `eigrp_query.c` — Summary Route Advertises Predecessor Metric Instead of Local Distance, Self-Poisons via Split Horizon, Inherits External TLV Type, and Leaks Suppressed Components on `QUERY`

- **Affected Files**:
  - `eigrp/code/eigrp_summary.c` (`eigrp_summary_route_build()`, lines 221–294; `eigrp_summary_query_route_build()`, lines 297–330)
  - `eigrp/code/eigrp_query.c` (`eigrp_query_receive()`, lines 137–148)
- **Wrapper Workaround**: `__wrap_eigrp_summary_route_build()` and `__wrap_eigrp_summary_query_route_build()` in [`src/cshim/srl_cshim_overrides.c`](file:///home/awhitaker/dev/srl-eigrp/src/cshim/srl_cshim_overrides.c#L125-L265)

#### Root Cause
1. **Summary route advertises predecessor's reported vector (`best_route->metric`) instead of the summarizing router's accumulated vector (`best_route->total_metric`)**:
   - As documented in `eigrp_packetizer.c:119–123`:
     ```c
     /* A learned route keeps the neighbor-advertised vector in metric and
      * our accumulated vector in total_metric. EIGRP advertises our
      * distance, not the predecessor's reported distance, so never put the
      * learned metric back on the wire for normal UPDATE/QUERY/REPLY work.
      */
     ```
   - However, in `eigrp_summary_route_build()` (`eigrp_summary.c:270–275`), when no static summary metric is configured on `summary_prefix->destination`, `*summary_route = *best_route;` leaves `summary_route->metric` set to `best_route->metric` (the upstream neighbor's reported vector) instead of `best_route->total_metric` (the summarizing router's own accumulated vector). And in `eigrp_update_send_EOT()` (`eigrp_update.c:583–584`), `if (!summarized) wire_route.metric = selected_route->total_metric;` explicitly skips summarized routes!
   - **Observable in upstream UUT**: In `eigrp/test/uut/summary-topology/scenario-summary-metric-selection.yaml` (lines 38–39), R2 selects component `10.30.2.0/24` with R2's distance `13762560` (`Summary component: 10.30.2.0/24 metric 13762560`), yet on the very next line logs `Summary metric: 10.30.0.0/16 13107200` (R3's reported distance, missing R2's `eth23` ingress link delay of `655,360`). Consequently, R1 (one hop further away from R3 across `eth12`) learns `10.30.0.0/16` with the exact same metric (`7,864,320` initially, `13,762,560` after failover) as R2's own FD instead of `8,519,680` / `14,417,920`!

2. **Summary route self-poisons (`delay = EIGRP_MAX_METRIC`) on the outgoing interface when `best_route->ei == ei`**:
   - Because `*summary_route = *best_route;` copies `best_route->ei` into `summary_route->ei`, whenever the lowest-distance component covered by the summary on `ei` has `best_route->ei == ei` (for instance, when `ei`'s own connected subnet is covered by a broader summary configured on `ei`, such as `10.1.2.0/24` on `ei` covered by `10.0.0.0/8` or `10.1.0.0/16`), `eigrp_packetizer_poison_reverse()` (`eigrp_packetizer.c:390, 548`) and `eigrp_update_send_EOT()` (`eigrp_update.c:585`) see `eigrp_nbr_split_horizon(wire_route, ei) == true` (`erd->ei == ei`) and **poison the entire summary route (`delay = EIGRP_MAX_METRIC`) out `ei`**!
   - Furthermore, the component-selection loop in `eigrp_summary_route_build()` (`eigrp_summary.c:251–269`) must skip poisoned candidates (`candidate->distance == EIGRP_MAX_METRIC || candidate_route->metric.delay == EIGRP_MAX_METRIC`) and components learned from a neighbor on `ei` (`ei && candidate_route->ei == ei && candidate_route->adv_router != eigrp->neighbor_self`), and the synthesized summary route descriptor must be marked locally originated (`summary_route->ei = NULL; summary_route->adv_router = eigrp->neighbor_self; memset(&summary_route->nexthop, 0, sizeof(summary_route->nexthop));`).

3. **Summary route inherits External TLV type when best component is redistributed**:
   - If the lowest-metric component under the summary is a redistributed route (`best_route->type == classic_external_tlv_type`), `*summary_route = *best_route;` leaves `summary_route->type` as an External TLV instead of `eigrp->af_vectors.classic_internal_tlv_type`.

4. **Suppressed component routes leak to neighbors when queried (`eigrp_query_receive()`)**:
   - In `eigrp_query_receive()` (`eigrp_query.c:137–148`), `eigrp_summary_query_route_build()` only intercepts a `QUERY` if `destination` is an exact match for a configured summary prefix (`eigrp_summary.c:311–315`).
   - If a neighbor on `ei` sends a `QUERY` for a specific component prefix that is covered by an active summary on `ei` and is not leaked (`eigrp_summary_covers(eigrp, ei, destination) && !eigrp_summary_specific_leak(eigrp, ei, destination)`), `eigrp_summary_query_route_build()` returns `false`. `eigrp_query_receive()` then passes the `QUERY` to `eigrp_fsm_event(&msg)`, which sends a reachable `REPLY` for the suppressed specific component back to the neighbor on `ei`!

#### Proposed Upstream Patch
```diff
--- a/eigrp/code/eigrp_summary.c
+++ b/eigrp/code/eigrp_summary.c
@@ -259,20 +259,41 @@ bool eigrp_summary_route_build(eigrp_instance_t *eigrp, eigrp_intf_t *ei,
 						   &candidate->destination.address))
 				continue;
 			candidate_route = eigrp_topology_route_read(candidate);
-			if (!candidate_route)
+			if (!candidate_route || candidate->distance == EIGRP_MAX_METRIC
+			    || candidate_route->metric.delay == EIGRP_MAX_METRIC)
 				continue;
-			if (!best_route || candidate->distance < selected_distance) {
+			if (ei && candidate_route->ei == ei
+			    && candidate_route->adv_router != eigrp->neighbor_self)
+				continue;
+			if (!best_route || candidate->distance < selected_distance
+			    || (ei && best_route->ei == ei && candidate_route->ei != ei
+				&& candidate->distance == selected_distance)) {
 				best_route = candidate_route;
 				best_component = candidate->destination;
 				selected_distance = candidate->distance;
 			}
 		}
-		if (best_route)
+		if (best_route && selected_distance != EIGRP_MAX_METRIC) {
 			*summary_route = *best_route;
-		else
+			summary_route->metric = best_route->total_metric;
+			summary_route->reported_metric = summary_route->metric;
+			summary_route->total_metric = summary_route->metric;
+			summary_route->distance = selected_distance;
+			summary_route->reported_distance = 0;
+		} else {
 			summary_route->metric.delay = EIGRP_MAX_METRIC;
+			summary_route->reported_metric.delay = EIGRP_MAX_METRIC;
+			summary_route->total_metric.delay = EIGRP_MAX_METRIC;
+			summary_route->distance = EIGRP_MAX_METRIC;
+		}
 	}
+	summary_route->ei = NULL;
+	summary_route->adv_router = eigrp->neighbor_self;
+	summary_route->type = eigrp->af_vectors.classic_internal_tlv_type;
+	memset(&summary_route->nexthop, 0, sizeof(summary_route->nexthop));
 	summary_prefix->reported_metric = summary_route->metric;
+	summary_prefix->distance = selected_distance;
+	summary_prefix->fdistance = selected_distance;
 	summary_prefix->state = EIGRP_FSM_STATE_PASSIVE;
 	summary_route->prefix = summary_prefix;
 	summary_route->dest = summary_prefix->destination;
@@ -311,20 +332,40 @@ bool eigrp_summary_query_route_build(eigrp_instance_t *eigrp, eigrp_intf_t *ei,
     for (configured = config->summaries; configured; configured = configured->next)
         if (eigrp_summary_prefix_match(&configured->prefix, destination))
             break;
-    if (!configured)
+    if (configured) {
+        for (rn = eigrp_table_first(eigrp->topology_table); rn; rn = eigrp_table_next(rn)) {
+            eigrp_prefix_descriptor_t *component = rn->info;
+            eigrp_route_descriptor_t *route;
+            if (!component || component->distance == EIGRP_MAX_METRIC
+                || component->destination.prefix_length <= destination->prefix_length
+                || !eigrp_prefix_address_match(destination, &component->destination.address))
+                continue;
+            route = eigrp_topology_route_read(component);
+            if (route && eigrp_summary_route_build(eigrp, ei, component, route,
+                                                   summary_prefix, summary_route))
+                return true;
+        }
         return false;
-
-    for (rn = eigrp_table_first(eigrp->topology_table); rn; rn = eigrp_table_next(rn)) {
-        eigrp_prefix_descriptor_t *component = rn->info;
-        eigrp_route_descriptor_t *route;
-        if (!component || component->distance == EIGRP_MAX_METRIC
-            || component->destination.prefix_length <= destination->prefix_length
-            || !eigrp_prefix_address_match(destination, &component->destination.address))
-            continue;
-        route = eigrp_topology_route_read(component);
-        if (route && eigrp_summary_route_build(eigrp, ei, component, route,
-                                               summary_prefix, summary_route))
-            return true;
+    }
+    if (eigrp_summary_covers(eigrp, ei, destination)
+        && !eigrp_summary_specific_leak(eigrp, ei, destination)) {
+        if (ei->address.address.afi == destination->address.afi
+            && ei->address.prefix_length == destination->prefix_length
+            && eigrp_prefix_address_match(&ei->address, &destination->address))
+            return false;
+        memset(summary_prefix, 0, sizeof(*summary_prefix));
+        summary_prefix->destination = *destination;
+        summary_prefix->state = EIGRP_FSM_STATE_PASSIVE;
+        summary_prefix->reported_metric.delay = EIGRP_MAX_METRIC;
+        memset(summary_route, 0, sizeof(*summary_route));
+        summary_route->prefix = summary_prefix;
+        summary_route->dest = *destination;
+        summary_route->type = eigrp->af_vectors.classic_internal_tlv_type;
+        summary_route->metric.delay = EIGRP_MAX_METRIC;
+        summary_route->reported_metric.delay = EIGRP_MAX_METRIC;
+        summary_route->total_metric.delay = EIGRP_MAX_METRIC;
+        summary_route->distance = EIGRP_MAX_METRIC;
+        return true;
     }
     return false;
 }
--- a/eigrp/test/uut/summary-topology/scenario-summary-metric-selection.yaml
+++ b/eigrp/test/uut/summary-topology/scenario-summary-metric-selection.yaml
@@ -8,7 +8,7 @@ steps:
   - validate-convergence:
       timeout: 7
       expect:
-        - route: {uut: r1, prefix: 10.30.0.0/16, table: rib, metric: 7864320}
+        - route: {uut: r1, prefix: 10.30.0.0/16, table: rib, metric: 8519680}
         - route: {uut: r2, prefix: 10.30.1.0/24, table: topology, active: false, fd: 7864320, successors: 1}
         - route: {uut: r2, prefix: 10.30.2.0/24, table: topology, active: false, fd: 13762560, successors: 1}
   - validate-event: {uut: r2, contains: "Summary component: 10.30.1.0/24 metric 7864320"}
@@ -17,7 +17,7 @@ steps:
   - validate-convergence:
       timeout: 7
       expect:
-        - route: {uut: r1, prefix: 10.30.0.0/16, table: rib, metric: 7864320}
+        - route: {uut: r1, prefix: 10.30.0.0/16, table: rib, metric: 8519680}
         - route: {uut: r2, prefix: 10.30.1.0/24, table: topology, active: false, successors: 1}
         - route: {uut: r2, prefix: 10.30.2.0/24, table: topology, active: false, successors: 0, fd: 4294967295}
   - validate-packet: {opcode: query, prefix: 10.30.2.0/24, source_uut: r2, destination_uut: r1, since: nonbest-down, min: 0, max: 0, timeout: 1, event: any}
@@ -25,25 +25,25 @@ steps:
   - validate-convergence:
       timeout: 7
       expect:
-        - route: {uut: r1, prefix: 10.30.0.0/16, table: rib, metric: 7864320}
+        - route: {uut: r1, prefix: 10.30.0.0/16, table: rib, metric: 8519680}
         - route: {uut: r2, prefix: 10.30.2.0/24, table: topology, active: false, successors: 1}
   - packet-mark: best-down
   - link-down: {uut: r3, interface: n1}
   - validate-convergence:
       timeout: 10
       expect:
-        - route: {uut: r1, prefix: 10.30.0.0/16, table: rib, metric: 13762560}
+        - route: {uut: r1, prefix: 10.30.0.0/16, table: rib, metric: 14417920}
         - route: {uut: r2, prefix: 10.30.1.0/24, table: topology, active: false, successors: 0, fd: 4294967295}
         - route: {uut: r2, prefix: 10.30.2.0/24, table: topology, active: false, successors: 1}
   - validate-event: {uut: r2, contains: "Summary component: 10.30.2.0/24 metric 13762560"}
-  - validate-event: {uut: r2, contains: "Summary metric: 10.30.0.0/16 13107200"}
+  - validate-event: {uut: r2, contains: "Summary metric: 10.30.0.0/16 13762560"}
   - validate-packet: {opcode: query, prefix: 10.30.1.0/24, source_uut: r2, destination_uut: r1, since: best-down, min: 0, max: 0, timeout: 1, event: any}
   - packet-mark: best-up
   - link-up: {uut: r3, interface: n1}
   - validate-convergence:
       timeout: 10
       expect:
-        - route: {uut: r1, prefix: 10.30.0.0/16, table: rib, metric: 7864320}
+        - route: {uut: r1, prefix: 10.30.0.0/16, table: rib, metric: 8519680}
         - route: {uut: r2, prefix: 10.30.1.0/24, table: topology, active: false, successors: 1}
         - route: {uut: r2, prefix: 10.30.2.0/24, table: topology, active: false, successors: 1}
   - validate-event: {uut: r2, contains: "Summary component: 10.30.1.0/24 metric 7864320"}
@@ -51,7 +51,7 @@ steps:
   - validate-convergence:
       timeout: 10
       expect:
-        - route: {uut: r1, prefix: 10.30.0.0/16, table: rib, metric: 13762560}
+        - route: {uut: r1, prefix: 10.30.0.0/16, table: rib, metric: 14417920}
   - packet-mark: last-down
   - link-down: {uut: r3, interface: n2}
   - validate-convergence:
```
