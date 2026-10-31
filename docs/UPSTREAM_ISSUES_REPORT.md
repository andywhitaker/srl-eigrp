# OpenEIGRP (`rel-0.5.0`) Upstream Protocol Defect Report

**Upstream Repository:** `https://github.com/diivious/eigrp.git`  
**Evaluated Release / Commit:** `rel-0.5.0` (`a41789b52671f81e5b3e21f02942cf7e3e4121db`)  
**Previous Evaluated Release / Commit:** `rel-0.3.0` (`b9b52af04133df47c90cb00516dd3a36d25a9573`)  
**Reference Gist Re-Verified:** `7104d5892c7ee620c567ec203a440ecc` (*"openeigrp 0.3.0 test re-run"*)  
**Test Environment:** 5-Node Nokia SR Linux 25.10.1 Containerlab Topology (`srl1`–`srl5`, dual-stack IPv4/IPv6 EIGRP AS 100) + C-Shim Unit Test Harness (`srlTestRel030OverridesCheck`)

---

## Executive Summary & `rel-0.3.0` → `rel-0.5.0` Resolution Matrix

All issues documented in the `rel-0.3.0` upstream defect report and the `openeigrp 0.3.0 test re-run` gist (`7104d5892c7ee620c567ec203a440ecc`) were re-evaluated against `rel-0.5.0` (`a41789b52671f81e5b3e21f02942cf7e3e4121db`) in the live 5-node Containerlab testbed:

| Prior Reference (`rel-0.3.0` Report & Gist `7104d5892c7ee620c567ec203a440ecc`) | Summary | Status in `rel-0.5.0` (`a41789b`) | Upstream Resolution / Remaining Gap |
| :--- | :--- | :--- | :--- |
| **Gist Defect 2** | Manual summary component loss fails to withdraw RIB/peer route when other summary interfaces remain up (`eigrp_summary.c`) | **RESOLVED** | Fixed in `31484cf` (`eigrp_summary_Null0_active()` in `eigrp_summary.c:56-71` and `eigrp_summary.c:663-674`): Null0 sink is withdrawn as soon as `active_interfaces == 0`, even when other interfaces still carry the summary configuration. All `__wrap_eigrp_summary_*` overrides have been removed. |
| **Gist Defect 1 (Part A)** | `eigrp_fsm_event_lr()` (`ACTIVE_1` / `ACTIVE_3` → `PASSIVE`) leaves `prefix->fdistance = prefix->distance = EIGRP_MAX_METRIC` instead of calling `eigrp_topology_update_node_flags()` (`eigrp_fsm.c`) | **RESOLVED** | Fixed in `4e5dd9c` (`eigrp_fsm.c:838-868`): `eigrp_fsm_event_lr()` now restores `prefix->distance`, `prefix->fdistance`, `prefix->reported_metric`, and `prefix->rdistance` from `best_route` and invokes `eigrp_topology_update_node_flags()`. `__wrap_eigrp_fsm_event_lr` has been removed. |
| **Gist Defect 1 (Part B)** | `eigrp_route_descriptor_delete()` leaves stale `prefix->req_action` bits pointing at freed `prefix->Best_route` (`eigrp_topology.c`) | **RESOLVED** | Fixed in `794df31` / `20a3011` (`eigrp_topology.c`): packetizer work items now hold explicit route/prefix references rather than dereferencing a stale `prefix->Best_route` pointer. |
| **Gist Neighbor-Down `adv_router` Lifetime Hazard** | `eigrp_nbr_delete()` frees `nbr` while poisoned routes remain in `topology_table` awaiting packetizer retirement, causing use-after-free on `route->adv_router` | **RESOLVED** | Fixed in `20a3011` (`eigrp_neighbor.c:725-753` and `eigrp_topology.c:553-577`): `eigrp_topology_nbr_hold()` / `eigrp_topology_nbr_release()` reference-count `nbr->topo_refs` and defer `eigrp_nbr_free()` until all topology descriptors release `adv_router`. |
| **Gist Defect 3** | `eigrp_topology_prefix_admit()` counts `QUERY`-retained / `ACTIVE` withdrawing prefixes (`topology_table->size`), admits any existing `topology_table` entry without checking reachability, and tears down all AF neighbors on hard limit rejection (`eigrp_topology.c`, `eigrp_pfxlimits.c`) | **OPEN (Issue 1 below)** | Commit `243c647` switched `eigrp_topology_prefix_count()` to `runtime->topology_table->size`, which still counts unreachable `QUERY`-retained `PASSIVE` entries and withdrawing `ACTIVE` entries, and `eigrp_pfxlimits_prefix_exceeded()` still suspends all neighbors in the AF on a hard limit rejection. |
| **Gist Defect 1 (Part C)** | `eigrp_query_unknown_route_record()` retains un-elected `flags == 0` routes in `PASSIVE` prefixes that are never cleaned up on unreachable `UPDATE`, poisoned `QUERY`, competing neighbor `UPDATE`, or neighbor-down (`eigrp_query.c`, `eigrp_update.c`, `eigrp_topology.c`) | **OPEN (Issue 2 below)** | Commit `8489c3b` kept `prefix->distance = EIGRP_MAX_METRIC` on initial unknown `QUERY` creation, but un-elected `QUERY`-retained RDBs still promote into false RIB-installed successors when another neighbor withdraws or goes down, or when a competing neighbor sends a higher-metric `UPDATE`. |
| **Gist Defect 4** | Peer `metric-version` change in `eigrp_sw_version_decode()` (`eigrp_hello.c`) updates `nbr->tlv_version` without updating `ei->tlv1_peer_count` / `ei->tlv2_peer_count` | **OPEN (Issue 3 below)** | Commit `77e976a` fixed local CLI metric-version updates in `eigrp_nbr_codec_update()`, but `eigrp_sw_version_decode()` (`eigrp_hello.c:198-218`) still calls `eigrp_nbr_codec_select()` without updating interface peer encoder counts when a peer changes its advertised software TLV version while `UP`. |

---

## Issue 1: `eigrp_topology_prefix_admit()` Counts Unreachable `QUERY`-Retained and `ACTIVE` Withdrawing Prefixes and Tears Down All Neighbors on Hard Limit Rejection

### Component & Location
- **Files:**
  - `eigrp/code/eigrp_topology.c:2692-2743` (`eigrp_topology_prefix_count`, `eigrp_topology_prefix_admit`)
  - `eigrp/code/eigrp_pfxlimits.c:66-156` (`eigrp_pfxlimits_nbr_update`, `eigrp_pfxlimits_state_cleanup`, `eigrp_pfxlimits_prefix_exceeded`)
- **Severity:** High (Rejects legitimate replacement routes during route churn at the `maximum-prefix` boundary, admits `QUERY`-retained prefixes past `maximum-prefix`, and tears down all neighbors in the address family when `maximum-prefix` is exceeded)

### Exact Upstream Code (`rel-0.5.0`)
In `eigrp/code/eigrp_topology.c:2692-2743`:
```c
/* Every destination still present in the topology database counts, even
 * if QUERY-retained, poisoned, or awaiting deferred retirement. */
static uint32_t eigrp_topology_prefix_count(eigrp_instance_t *runtime)
{
	if (!runtime || !runtime->topology_table)
		return 0;
	/* Topology publication sets node->info with node creation, and
	 * retirement removes the node. The indexed table size is O(1). */
	if (runtime->topology_table->size > UINT32_MAX)
		return UINT32_MAX;
	return (uint32_t)runtime->topology_table->size;
}

bool eigrp_topology_prefix_admit(eigrp_instance_t *runtime,
				 const eigrp_prefix_t *prefix)
{
	eigrp_af_config_t *af;
	const eigrp_prefix_limit_t *limit;

	if (!runtime || !prefix)
		return false;
	if (runtime->eigrp_pfxlimits_af_state)
		return false;
	/* Every retained topology destination consumes one prefix slot. */
	if (eigrp_topology_table_lookup(runtime->topology_table, prefix))
		return true;
	af = eigrp_af_config_runtime_read(runtime);
	if (!af || !af->topology_maximum_prefix_configured)
		return true;
	limit = &af->topology_maximum_prefix;
	{
		uint32_t count = eigrp_topology_prefix_count(runtime);
		if (eigrp_prefix_limit_threshold_crossed(limit, count))
			eigrp_log(
				EIGRP_LOG_WARNING,
				"EIGRP topology maximum-prefix threshold reached (%u/%u)",
				count + 1U, limit->maximum);
		/* Process admission supports restart/reset/dampening policies.
		 * The legacy basic-only admission helper would bypass hard
		 * limits whenever any of those options was configured. */
		if (!limit->warning_only && count >= limit->maximum) {
			(void)eigrp_eventlog_msg_add(
				runtime,
				EIGRP_EVENTLOG_OPCODE_PREFIX_LIMIT_REJECT,
				prefix, EIGRP_EVENTLOG_PREFIX_LIMIT_TOPOLOGY,
				count + 1U, limit->maximum, 0);
			eigrp_pfxlimits_prefix_exceeded(runtime, limit);
			return false;
		}
		return true;
	}
}
```

### Root Cause Analysis
1. **Unreachable `QUERY`-retained and `ACTIVE` withdrawing prefixes consume `maximum-prefix` slots**:
   - `eigrp_topology_prefix_count()` returns `runtime->topology_table->size`.
   - When an unknown `QUERY` creates a `QUERY`-retained `PASSIVE` prefix (`prefix->distance == EIGRP_MAX_METRIC`, `prefix->fdistance == EIGRP_MAX_METRIC`), or when an existing prefix loses its successor and enters `ACTIVE_1` / `ACTIVE_3` while waiting for `REPLY`s from neighbors, the prefix descriptor remains in `runtime->topology_table`.
   - Note also that when a prefix transitions to `ACTIVE` in `eigrp_fsm_event_q_fcn()` / `eigrp_fsm_event_nq_fcn()` (`eigrp_fsm.c:723-765`), `prefix->distance` and `prefix->fdistance` remain frozen at their pre-`ACTIVE` finite values while the poisoned successor route has `distance == EIGRP_MAX_METRIC`. If a non-feasible route (`flags == 0`) with finite metric also exists on that `ACTIVE` prefix, `eigrp_topology_route_read(prefix)` returns that `flags == 0` route. Only prefixes with a finite route carrying `EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG` or `EIGRP_ROUTE_DESCRIPTOR_FSUCCESSOR_FLAG` represent active reachable prefixes.
2. **`eigrp_topology_prefix_admit()` unconditionally admits any prefix already in `topology_table`**:
   - Line 2716 (`if (eigrp_topology_table_lookup(runtime->topology_table, prefix)) return true;`) returns `true` even when the existing `eigrp_prefix_descriptor_t` is an unreachable `QUERY`-retained `PASSIVE` placeholder (`distance == EIGRP_MAX_METRIC`).
   - When a subsequent finite `UPDATE` arrives from the same neighbor (`topology_route != NULL`), `eigrp_update.c:480-489` calls `eigrp_topology_prefix_admit(eigrp, &received_route->dest)`, which immediately returns `true` at line 2716 without checking `limit->maximum`.
3. **Unconditional AF-wide neighbor teardown on hard `maximum-prefix` rejection**:
   - Line 2738 calls `eigrp_pfxlimits_prefix_exceeded(runtime, limit)` (`eigrp_pfxlimits.c:220-262`), which sets `runtime->eigrp_pfxlimits_af_state = 1` (or `2`), transmits `EIGRP_HELLO_GRACEFUL_SHUTDOWN` on all active interfaces, and calls `eigrp_pfxlimits_nbr_update(runtime, false)` to tear down every neighbor in the address family even when no `restart` / `reset-time` / `dampened` process teardown policy was configured.

### Steps to Reproduce
1. Configure `maximum-prefix 5` (hard limit, `warning-only false`) on `srl2` in the 5-node topology (`srl1`, `srl2`, `srl3`, `srl4`, `srl5`) where `srl2` has 5 reachable prefixes in `topology_table`.
2. Withdraw 1 prefix on `srl5` while advertising 1 new replacement prefix on `srl1`.
3. Because `srl2` places the withdrawn prefix into `ACTIVE` while waiting for `REPLY`s from its peers, `runtime->topology_table->size` remains `5`. When the replacement `UPDATE` arrives from `srl1`, `eigrp_topology_prefix_admit()` sees `count == 5 >= limit->maximum`, rejects the replacement prefix, and invokes `eigrp_pfxlimits_prefix_exceeded()`, tearing down all of `srl2`'s EIGRP neighbors!

### Live Debug Output / Verification
With the C-shim override (`__wrap_eigrp_topology_prefix_admit` in `src/cshim/srl_cshim_overrides.c:83-124`), `srlTestRel030OverridesCheck` steps 6–7 and `tests/test_5node_lab.py::test_5node_timers_maxprefix_bwpercent_ribscale_and_tools` verify:
```text
tests/test_5node_lab.py::test_5node_timers_maxprefix_bwpercent_ribscale_and_tools PASSED
=== RUN   TestRel030OverridesCheck
--- PASS: TestRel030OverridesCheck (0.00s)
```

### Proposed Upstream Fix
```diff
diff --git a/eigrp/code/eigrp_topology.c b/eigrp/code/eigrp_topology.c
index a07f2cd..6721edb 100644
--- a/eigrp/code/eigrp_topology.c
+++ b/eigrp/code/eigrp_topology.c
@@ -2689,17 +2689,37 @@ static eigrp_result_t eigrp_topology_message_process(eigrp_instance_t *eigrp,
 	return EIGRP_RESULT_INVALID_ARGUMENT;
 }
 
-/* Every destination still present in the topology database counts, even
- * if QUERY-retained, poisoned, or awaiting deferred retirement. */
+static bool
+eigrp_topology_prefix_has_active_route(eigrp_prefix_descriptor_t *pfx)
+{
+	eigrp_route_descriptor_t *best;
+
+	if (!pfx || pfx->distance == EIGRP_MAX_METRIC
+	    || pfx->fdistance == EIGRP_MAX_METRIC)
+		return false;
+	best = eigrp_topology_route_read(pfx);
+	if (!best || best->distance == EIGRP_MAX_METRIC
+	    || best->metric.delay == EIGRP_MAX_METRIC)
+		return false;
+	return (best->flags
+		& (EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG
+		   | EIGRP_ROUTE_DESCRIPTOR_FSUCCESSOR_FLAG))
+	       != 0;
+}
+
 static uint32_t eigrp_topology_prefix_count(eigrp_instance_t *runtime)
 {
+	eigrp_table_node_t *node;
+	uint32_t count = 0;
+
 	if (!runtime || !runtime->topology_table)
 		return 0;
-	/* Topology publication sets node->info with node creation, and
-	 * retirement removes the node. The indexed table size is O(1). */
-	if (runtime->topology_table->size > UINT32_MAX)
-		return UINT32_MAX;
-	return (uint32_t)runtime->topology_table->size;
+	for (node = eigrp_table_first(runtime->topology_table); node;
+	     node = eigrp_table_next(node)) {
+		if (eigrp_topology_prefix_has_active_route(node->info))
+			count++;
+	}
+	return count;
 }
 
 bool eigrp_topology_prefix_admit(eigrp_instance_t *runtime,
@@ -2707,13 +2727,14 @@ bool eigrp_topology_prefix_admit(eigrp_instance_t *runtime,
 {
 	eigrp_af_config_t *af;
 	const eigrp_prefix_limit_t *limit;
+	eigrp_prefix_descriptor_t *existing;
 
 	if (!runtime || !prefix)
 		return false;
 	if (runtime->eigrp_pfxlimits_af_state)
 		return false;
-	/* Every retained topology destination consumes one prefix slot. */
-	if (eigrp_topology_table_lookup(runtime->topology_table, prefix))
+	existing = eigrp_topology_table_lookup(runtime->topology_table, prefix);
+	if (eigrp_topology_prefix_has_active_route(existing))
 		return true;
 	af = eigrp_af_config_runtime_read(runtime);
 	if (!af || !af->topology_maximum_prefix_configured)
@@ -2735,7 +2756,10 @@ bool eigrp_topology_prefix_admit(eigrp_instance_t *runtime,
 				EIGRP_EVENTLOG_OPCODE_PREFIX_LIMIT_REJECT,
 				prefix, EIGRP_EVENTLOG_PREFIX_LIMIT_TOPOLOGY,
 				count + 1U, limit->maximum, 0);
-			eigrp_pfxlimits_prefix_exceeded(runtime, limit);
+			if (limit->dampened || limit->restart_minutes
+			    || limit->reset_time_minutes
+			    || limit->restart_count)
+				eigrp_pfxlimits_prefix_exceeded(runtime, limit);
 			return false;
 		}
 		return true;
```

---

## Issue 2: `QUERY`-Retained `PASSIVE` Routes Leak Across Unreachable `UPDATE`s, Poisoned `QUERY`s, Competing Neighbor `UPDATE`s, and Neighbor-Down Events

### Component & Location
- **Files:**
  - `eigrp/code/eigrp_query.c:72-147` (`eigrp_query_unknown_route_record`, `eigrp_query_receive`)
  - `eigrp/code/eigrp_update.c:459-535` (`eigrp_update_receive`)
  - `eigrp/code/eigrp_topology.c:1806-1851` (`eigrp_topology_neighbor_down`)
- **Severity:** High (Promotes un-elected `QUERY`-retained routes into false RIB-installed successors and retains stale RDBs after poison `QUERY` / unreachable `UPDATE` / neighbor-down)

### Exact Upstream Code (`rel-0.5.0`)
In `eigrp/code/eigrp_query.c:72-147`:
```c
static bool eigrp_query_unknown_route_record(eigrp_instance_t *eigrp,
					     eigrp_nbr_t *nbr,
					     eigrp_route_descriptor_t *route,
					     eigrp_prefix_descriptor_t *prefix)
{
	eigrp_route_descriptor_t *previous;
	bool new_prefix = prefix == NULL;

	if (!eigrp || !nbr || !route || !nbr->ei || !eigrp->topology_table
	    || route->metric.delay == EIGRP_MAX_METRIC
	    || route->metric.delay == EIGRP_METRIC_MAX
	    || eigrp_filter_prefix_update(eigrp, nbr->ei, EIGRP_FILTER_IN,
					  &route->dest))
		return false;
	if (!eigrp_nbr_route_admit(eigrp, nbr, &route->dest, &route->metric))
		return false;
...
	route->adv_router = nbr;
	route->prefix = prefix;
	route->reported_metric = route->metric;
	route->reported_distance =
		eigrp_metric_calculate(eigrp, route->reported_metric);
	route->distance = eigrp_metric_total_calculate(eigrp, route);
	if (!eigrp_topology_route_insert(eigrp, prefix, route, true)) {
		if (new_prefix)
			eigrp_topology_prefix_free(prefix);
		return false;
	}
	/* Route storage is intentionally separate from route_descriptor_add(),
	 * which can install the first path into the host RIB. */
	if (new_prefix)
		eigrp_prefix_descriptor_add(eigrp->topology_table, prefix);
	return true;
}
```
And in `eigrp/code/eigrp_update.c:464-532`:
```c
				/* A new unreachable path is a withdrawal
				 * without a route to withdraw. Do not admit a
				 * poisoned descriptor. */
				if (!topology_route && unreachable) {
					eigrp_topology_route_free(
						received_route);
					continue;
				}
...
				msg.packet_type = EIGRP_OPC_UPDATE;
				msg.eigrp = eigrp;
				msg.data_type =
					(received_route->type
						 == eigrp->af_vectors
							    .classic_external_tlv_type
					 || received_route->type
						    == EIGRP_TLV_MP_EXT)
						? EIGRP_EXT
						: EIGRP_INT;
				msg.adv_router = nbr;
				msg.metrics = ingress_metric;
				msg.route = route;
				msg.prefix = prefix;
				/* Rejected new paths do not enter DUAL. An
				 * already owned path still processes an
				 * inbound-filter withdrawal. */
				msg.transient_route =
					!topology_route
					&& eigrp_metric_calculate(eigrp,
								  msg.metrics)
						   == EIGRP_MAX_METRIC;
				eigrp_fsm_event(&msg);
```

### Root Cause Analysis
When a `QUERY` with a finite metric arrives for an unknown prefix `P`, `eigrp_query_unknown_route_record()` creates a `PASSIVE` prefix descriptor (`prefix->state == EIGRP_FSM_STATE_PASSIVE`, `prefix->distance == EIGRP_MAX_METRIC`, `prefix->fdistance == EIGRP_MAX_METRIC`, `prefix->reported_metric.delay == EIGRP_MAX_METRIC`) and inserts a route descriptor with `flags == 0` and finite `route->distance` into `prefix->internal_routes` / `prefix->external_routes`. Four state transitions fail to account for this `QUERY`-retained `PASSIVE` state:

1. **Poisoned `QUERY` from the same neighbor leaves the stale finite RDB in `prefix`**:
   - When `prefix` is already in the `QUERY`-retained `PASSIVE` state, `eigrp_query_receive()` (`eigrp_query.c:254-276`) takes the unknown/retained branch and calls `eigrp_query_unknown_route_record()`.
   - If the neighbor sends a poisoned `QUERY` (`route->metric.delay == EIGRP_MAX_METRIC` or `EIGRP_METRIC_MAX`) or the prefix is denied by an inbound filter, `eigrp_query_unknown_route_record()` returns `false` at lines 80–85 **without deleting `previous = eigrp_prefix_descriptor_lookup(prefix, nbr)`**. The neighbor's old finite `QUERY` metric stays cached in `prefix`.
2. **Unreachable (`EIGRP_MAX_METRIC`) `UPDATE` on a `QUERY`-retained `PASSIVE` prefix promotes another neighbor's `QUERY`-retained route into a RIB-installed successor**:
   - Suppose `nbr1` and `nbr2` both sent finite-metric `QUERY`s for unknown prefix `P`, creating `r1` (`nbr1`, `flags == 0`) and `r2` (`nbr2`, `flags == 0`) under `P`.
   - When `nbr2` sends an unreachable `UPDATE` (`unreachable == true`) for `P`, `topology_route` (`r2`) is non-NULL, so `eigrp_update_receive()` does not take the `if (!topology_route && unreachable)` guard at line 467 and instead calls `eigrp_fsm_event(&msg)` (line 531).
   - Inside `eigrp_fsm_event_keep_state()`, `eigrp_topology_route_select(prefix)` selects `r1` (`nbr1`'s un-elected `QUERY`-retained route) and installs `r1` into the RIB as successor even though `nbr1` never sent an `UPDATE`!
3. **Reachable `UPDATE` from one neighbor elects a competing neighbor's lower-metric `QUERY`-retained route**:
   - In the same two-neighbor scenario, if `nbr2` sends a reachable `UPDATE` with `distance = 30720` while `nbr1`'s un-elected `QUERY`-retained route `r1` has `distance = 28160`, `eigrp_fsm_event_keep_state()` calls `eigrp_topology_route_select(prefix)` and elects `r1` (`nbr1`) instead of `r2` (`nbr2`) unless un-elected `QUERY`-retained routes from other neighbors are pruned before DUAL processes the `UPDATE`.
4. **Neighbor-down on a `QUERY`-retained `PASSIVE` prefix promotes another neighbor's `QUERY`-retained route**:
   - In `eigrp_topology_neighbor_down()` (`eigrp_topology.c:1826-1842`), if `nbr2` goes down while `P` is a `QUERY`-retained `PASSIVE` prefix holding `r1` and `r2`, `eigrp_topology_neighbor_down()` dispatches a synthetic poisoned `EIGRP_OPC_UPDATE` into `eigrp_fsm_event(&msg)`, which again elects `r1` (`nbr1`'s `QUERY`-retained route) into the RIB.

### Steps to Reproduce
1. Have `nbr1` (`10.0.0.1`) and `nbr2` (`10.0.0.2`) both send a finite-metric `QUERY` for an unknown destination `10.99.1.0/24` to `srl2`. `srl2` creates a `QUERY`-retained `PASSIVE` prefix `10.99.1.0/24` (`distance == EIGRP_MAX_METRIC`, `fdistance == EIGRP_MAX_METRIC`) containing `r1` (`nbr1`, `flags == 0`, `delay = 10`) and `r2` (`nbr2`, `flags == 0`, `delay = 20`).
2. Have `nbr2` send an unreachable `UPDATE` (`delay = EIGRP_MAX_METRIC`) for `10.99.1.0/24` (or bring `nbr2` down).
3. Without the fix, `srl2` runs `eigrp_fsm_event_keep_state()` on `10.99.1.0/24` and promotes `r1` (`nbr1`'s `QUERY`-retained route) into a RIB-installed `SUCCESSOR` route!

### Live Debug Output / Verification
Verified in `srlTestRel030OverridesCheck` (steps 1–4 in `src/cshim/srl_cshim_overrides.c:340-440`):
```text
=== RUN   TestRel030OverridesCheck
--- PASS: TestRel030OverridesCheck (0.00s)
```

### Proposed Upstream Fix
```diff
diff --git a/eigrp/code/eigrp_query.c b/eigrp/code/eigrp_query.c
index 1e1cf17..f702a3e 100644
--- a/eigrp/code/eigrp_query.c
+++ b/eigrp/code/eigrp_query.c
@@ -77,12 +77,28 @@ static bool eigrp_query_unknown_route_record(eigrp_instance_t *eigrp,
 	eigrp_route_descriptor_t *previous;
 	bool new_prefix = prefix == NULL;
 
-	if (!eigrp || !nbr || !route || !nbr->ei || !eigrp->topology_table
-	    || route->metric.delay == EIGRP_MAX_METRIC
+	if (!eigrp || !nbr || !route || !nbr->ei || !eigrp->topology_table)
+		return false;
+	previous = prefix ? eigrp_prefix_descriptor_lookup(prefix, nbr) : NULL;
+	if (route->metric.delay == EIGRP_MAX_METRIC
 	    || route->metric.delay == EIGRP_METRIC_MAX
 	    || eigrp_filter_prefix_update(eigrp, nbr->ei, EIGRP_FILTER_IN,
-					  &route->dest))
+					  &route->dest)) {
+		if (previous) {
+			unsigned int q;
+
+			for (q = 0; q < 2; q++)
+				eigrp_list_delete_data(
+					eigrp_topology_route_queue(prefix, q),
+					previous);
+			if (nbr->limit_prefix_count_valid
+			    && nbr->limit_prefix_count
+			    && !eigrp_prefix_descriptor_lookup(prefix, nbr))
+				nbr->limit_prefix_count--;
+			eigrp_topology_route_free(previous);
+		}
 		return false;
+	}
 	if (!eigrp_nbr_route_admit(eigrp, nbr, &route->dest, &route->metric))
 		return false;
 
@@ -106,7 +122,6 @@ static bool eigrp_query_unknown_route_record(eigrp_instance_t *eigrp,
 		prefix->reported_metric.delay = EIGRP_MAX_METRIC;
 	}
 
-	previous = eigrp_prefix_descriptor_lookup(prefix, nbr);
 	if (previous) {
 		eigrp_fsm_action_message_t msg = {0};
 
diff --git a/eigrp/code/eigrp_topology.c b/eigrp/code/eigrp_topology.c
index a07f2cd..af3b1bb 100644
--- a/eigrp/code/eigrp_topology.c
+++ b/eigrp/code/eigrp_topology.c
@@ -1825,6 +1825,15 @@ void eigrp_topology_neighbor_down(eigrp_instance_t *eigrp, eigrp_nbr_t *nbr)
 
 		route = eigrp_prefix_descriptor_lookup(pe, nbr);
 		if (route) {
+			if (pe->state == EIGRP_FSM_STATE_PASSIVE
+			    && pe->distance == EIGRP_MAX_METRIC
+			    && pe->fdistance == EIGRP_MAX_METRIC
+			    && pe->reported_metric.delay == EIGRP_MAX_METRIC) {
+				eigrp_route_descriptor_delete(eigrp, pe, route);
+				eigrp_update_topology_table_prefix(
+					eigrp, eigrp->topology_table, pe);
+				continue;
+			}
 			eigrp_fsm_action_message_t msg = {0};
 
 			msg.metrics.delay = EIGRP_MAX_METRIC;
diff --git a/eigrp/code/eigrp_update.c b/eigrp/code/eigrp_update.c
index 2c7fb2f..f9fe73e 100644
--- a/eigrp/code/eigrp_update.c
+++ b/eigrp/code/eigrp_update.c
@@ -460,10 +460,30 @@ void eigrp_update_receive(eigrp_instance_t *eigrp, eigrp_nbr_t *nbr,
 					eigrp_metric_calculate(eigrp,
 							       ingress_metric)
 					== EIGRP_MAX_METRIC;
+				bool query_retained_passive =
+					prefix
+					&& prefix->state
+						   == EIGRP_FSM_STATE_PASSIVE
+					&& prefix->distance == EIGRP_MAX_METRIC
+					&& prefix->fdistance == EIGRP_MAX_METRIC
+					&& prefix->reported_metric.delay
+						   == EIGRP_MAX_METRIC;
 
 				/* A new unreachable path is a withdrawal
 				 * without a route to withdraw. Do not admit a
 				 * poisoned descriptor. */
+				if (query_retained_passive && unreachable) {
+					if (topology_route)
+						eigrp_route_descriptor_delete(
+							eigrp, prefix,
+							topology_route);
+					eigrp_update_topology_table_prefix(
+						eigrp, eigrp->topology_table,
+						prefix);
+					eigrp_topology_route_free(
+						received_route);
+					continue;
+				}
 				if (!topology_route && unreachable) {
 					eigrp_topology_route_free(
 						received_route);
@@ -491,6 +511,29 @@ void eigrp_update_receive(eigrp_instance_t *eigrp, eigrp_nbr_t *nbr,
 						received_route);
 					continue;
 				}
+				if (query_retained_passive) {
+					unsigned int q;
+					for (q = 0; q < 2; q++) {
+						eigrp_list_t *routes =
+							eigrp_topology_route_queue(
+								prefix, q);
+						eigrp_list_item_t *rnode,
+							*rnnode;
+						eigrp_route_descriptor_t *r;
+						for (EIGRP_LIST_ITERATE(
+							     routes, rnode,
+							     rnnode, r)) {
+							if (r
+							    && r->adv_router
+								       != nbr
+							    && r->flags == 0)
+								eigrp_route_descriptor_delete(
+									eigrp,
+									prefix,
+									r);
+						}
+					}
+				}
 
 				if (topology_route) {
 					topology_route->type =
```

---

## Issue 3: Peer Metric-Version Renegotiation in `eigrp_sw_version_decode()` Does Not Update Interface `tlv1_peer_count` / `tlv2_peer_count`

### Component & Location
- **Files:**
  - `eigrp/code/eigrp_hello.c:198-218` (`eigrp_sw_version_decode`)
  - `eigrp/code/eigrp_neighbor.c:755-784` (`eigrp_nbr_codec_update`)
- **Severity:** Medium (Causes multicast `UPDATE`/`QUERY` encoding mismatch when an already-`UP` neighbor renegotiates `tlv_version` via a `Software_Version` TLV in a subsequent `HELLO`)

### Exact Upstream Code (`rel-0.5.0`)
In `eigrp/code/eigrp_hello.c:198-218`:
```c
static void eigrp_sw_version_decode(eigrp_nbr_t *nbr, eigrp_intf_t *ei,
				    struct eigrp_tlv_hdr_type *tlv, bool new)
{
	struct TLV_Software_Type *version = (struct TLV_Software_Type *)tlv;

	(void)new;

	nbr->os_rel_major = version->vender_major;
	nbr->os_rel_minor = version->vender_minor;
	nbr->tlv_rel_major = version->eigrp_major;
	nbr->tlv_rel_minor = version->eigrp_minor;

	/*
	 * The software TLV advertises the peer's highest TLV format, not the
	 * format it must use with this neighbor.  Version 2 peers retain TLV1
	 * compatibility and use it when talking to a Version 1 peer.  Bind the
	 * codec to the highest route TLV format supported by both sides.
	 */
	eigrp_nbr_codec_select(nbr, eigrp_metric_version_select(
					    ei->eigrp, nbr->tlv_rel_major));
}
```
Compare with `eigrp/code/eigrp_neighbor.c:768-783` (`eigrp_nbr_codec_update()`):
```c
		for (EIGRP_LIST_ITERATE_RO(ei->nbrs, nbr_node, nbr)) {
			if (!nbr || !nbr->tlv_rel_major)
				continue;
			selected = eigrp_metric_version_select(
				eigrp, nbr->tlv_rel_major);
			if (selected == nbr->tlv_version)
				continue;
			if (nbr->state == EIGRP_NEIGHBOR_UP)
				eigrp_intf_encoder_peer_remove(
					ei, nbr->tlv_version);
			eigrp_nbr_codec_select(nbr, selected);
			if (nbr->state == EIGRP_NEIGHBOR_UP)
				eigrp_intf_encoder_peer_add(ei,
							    nbr->tlv_version);
		}
```

### Root Cause Analysis
- Upstream commit `77e976a` updated `eigrp_nbr_codec_update()` (`eigrp_neighbor.c:775-781`) so that when the **local** router changes its `metric-version`, `eigrp_intf_encoder_peer_remove(ei, nbr->tlv_version)` and `eigrp_intf_encoder_peer_add(ei, nbr->tlv_version)` adjust `ei->tlv1_peer_count` and `ei->tlv2_peer_count` for every `UP` neighbor.
- However, in `eigrp_sw_version_decode()` (`eigrp_hello.c:198-218`), when an already-`UP` **peer** changes its advertised `eigrp_major` (`tlv_rel_major`) in a `HELLO` packet (e.g. changing from `64bit` TLV2 `eigrp_major = 2` to `32bit` TLV1 `eigrp_major = 1` before its hold timer expires), `eigrp_sw_version_decode()` calls `eigrp_nbr_codec_select()` directly, overwriting `nbr->tlv_version` without removing `old_version` from `ei` and adding the new `nbr->tlv_version` to `ei`.
- As a result, `ei->tlv2_peer_count` remains non-zero (and `ei->tlv1_peer_count` remains `0`) while the neighbor is `UP`, causing multicast `UPDATE` and `QUERY` packets on `ei` to be encoded in the wrong TLV format, and causing `eigrp_nbr_state_update()` to decrement the wrong peer counter when the neighbor later goes down.

### Steps to Reproduce
1. Establish an `UP` EIGRP adjacency between `srl1` (`metric-version 64bit`) and `srl2` (`metric-version 64bit`). On `srl1`, `ei->tlv2_peer_count == 1` and `ei->tlv1_peer_count == 0`.
2. Reconfigure `srl2` to `metric-version 32bit` so `srl2` sends a `HELLO` advertising `eigrp_major = 1` while `nbr->state == EIGRP_NEIGHBOR_UP` on `srl1`.
3. `eigrp_sw_version_decode()` on `srl1` updates `nbr->tlv_version` from `EIGRP_TLV_64B_VERSION` (`2`) to `EIGRP_TLV_32B_VERSION` (`1`), but leaves `ei->tlv2_peer_count == 1` and `ei->tlv1_peer_count == 0`.

### Live Debug Output / Verification
Verified in `srlTestRel030OverridesCheck` (step 5 in `src/cshim/srl_cshim_overrides.c:430-443`, using `__wrap_eigrp_nbr_codec_select` / `__wrap_eigrp_nbr_codec_update` at `src/cshim/srl_cshim_overrides.c:267-288`):
```text
=== RUN   TestRel030OverridesCheck
--- PASS: TestRel030OverridesCheck (0.00s)
```

### Proposed Upstream Fix
```diff
diff --git a/eigrp/code/eigrp_hello.c b/eigrp/code/eigrp_hello.c
index 54e7192..463d9f7 100644
--- a/eigrp/code/eigrp_hello.c
+++ b/eigrp/code/eigrp_hello.c
@@ -199,6 +199,7 @@ static void eigrp_sw_version_decode(eigrp_nbr_t *nbr, eigrp_intf_t *ei,
 				    struct eigrp_tlv_hdr_type *tlv, bool new)
 {
 	struct TLV_Software_Type *version = (struct TLV_Software_Type *)tlv;
+	uint8_t selected;
 
 	(void)new;
 
@@ -213,8 +214,14 @@ static void eigrp_sw_version_decode(eigrp_nbr_t *nbr, eigrp_intf_t *ei,
 	 * compatibility and use it when talking to a Version 1 peer.  Bind the
 	 * codec to the highest route TLV format supported by both sides.
 	 */
-	eigrp_nbr_codec_select(nbr, eigrp_metric_version_select(
-					    ei->eigrp, nbr->tlv_rel_major));
+	selected = eigrp_metric_version_select(ei->eigrp, nbr->tlv_rel_major);
+	if (nbr->state == EIGRP_NEIGHBOR_UP && selected != nbr->tlv_version) {
+		eigrp_intf_encoder_peer_remove(ei, nbr->tlv_version);
+		eigrp_nbr_codec_select(nbr, selected);
+		eigrp_intf_encoder_peer_add(ei, nbr->tlv_version);
+		return;
+	}
+	eigrp_nbr_codec_select(nbr, selected);
 }
 
 /**
```
