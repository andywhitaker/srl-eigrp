# Technical Defect Report: OpenEIGRP Core Routing Engine

**Target Subsystem:** OpenEIGRP C Core Library (`src/upstream/eigrp/eigrp/code/`)  
**Target Repository:** Donnie V. Savage's OpenEIGRP Core (`https://github.com/diivious/eigrp`)  
**Evaluated Upstream Commit:** [`951d7549beb447b8f9c42b4f253638b392729491`](https://github.com/diivious/eigrp/commit/951d7549beb447b8f9c42b4f253638b392729491) (*origin/master*)  
**Author / Contributor:** Andy Whitaker (`32944047+andywhitaker@users.noreply.github.com`)  
**Applicable Standards:** RFC 7868 (*Cisco's Enhanced Interior Gateway Routing Protocol*)  
**Affected Address Families:** `ipv4-unicast`, `ipv6-unicast`

---

## 1. Executive Summary

During end-to-end 2-node, FRR-interop, and 5-node Containerlab validation of `srl-eigrp` against unmodified upstream OpenEIGRP (`diivious/eigrp` commit [`951d754`](https://github.com/diivious/eigrp/commit/951d7549beb447b8f9c42b4f253638b392729491)), previously reported defects that were resolved upstream were verified and removed from this report:
- **Resolved Upstream in [`5f43feb`](https://github.com/diivious/eigrp/commit/5f43feb):** Throughput bottleneck bandwidth comparison in [`eigrp_metric_total_calculate()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_metric.c#L168-L171).
- **Resolved Upstream in [`366e29b`](https://github.com/diivious/eigrp/commit/366e29b):** DUAL FSM `ACTIVE_1` / `ACTIVE_3` `EIGRP_OPC_REPLY` handling on route withdrawal and metric increase in [`eigrp_fsm.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_fsm.c#L524-L605).

Six remaining upstream defects in `diivious/eigrp` (`951d754`) were identified during comprehensive feature testing. In `srl-eigrp`, we currently work around these without modifying the upstream submodule by using GCC linker `--wrap` overrides in [`src/cshim/srl_cshim_overrides.c`](file:///home/awhitaker/dev/srl-eigrp/src/cshim/srl_cshim_overrides.c):

1. **Peer Restart Ignored When Restarted Neighbor Reuses `INIT` Sequence `1`** ([`eigrp_update.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_update.c#L159-L168))
2. **Dual-Stack (`ipv4-unicast` + `ipv6-unicast`) Interface State Updates Clobber `ei->address` Across Address Families** ([`eigrp_network.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_network.c#L323-L343), [`eigrp_interface.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_interface.c#L1200-L1207))
3. **Self-Originated Route Feasibility Collapse ($RD == FD$) and Metric Miscalculation in `eigrp_topology_metric_update()`** ([`eigrp_topology.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L1245-L1283))
4. **Topology-Level `maximum-prefix` Admission (`eigrp_topology_prefix_admit`) Never Called by TLV Decoders and Counts Poisoned Nodes** ([`eigrp_topology.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L2273-L2315), [`eigrp_tlv1.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_tlv1.c), [`eigrp_tlv2.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_tlv2.c))
5. **Summary Route Component Selection (Split-Horizon, Metric, and Origin) & Suppressed-Component Query Handling** ([`eigrp_summary.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_summary.c#L221-L330))
6. **Query Origin Added to Reply-Status Table (`prefix->rij`) When `split-horizon` Is Disabled or on Shared Segments** ([`eigrp_packetizer.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_packetizer.c#L332-L346))

---

## 2. Defect 1: Peer Restart Ignored When Restarted Neighbor Reuses `INIT` Sequence `1`

### 2.1 Affected Source Location
* **File:** [`src/upstream/eigrp/eigrp/code/eigrp_update.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_update.c#L159-L267)
* **Function:** [`eigrp_update_receive()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_update.c#L136)
* **Upstream Line Numbers:** Lines 159–168 and Lines 251–266

### 2.2 RFC Standard Requirement
* **RFC 7868 §5.3.4 (INIT Flag)**:
  * When a router receives an `UPDATE` with the `INIT` flag set from a neighbor that is already in the `UP` state, it indicates that the neighbor has restarted before its hold timer expired and is establishing a new adjacency.
  * The receiving router must tear down/resynchronize stale topology state learned from that neighbor, transition the neighbor through `PENDING`, and send its own `INIT` `UPDATE` so both peers resynchronize their topology tables.

### 2.3 Flawed Behavior & Event Sequence
In [`eigrp_update.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_update.c#L159-L168), lines 159–168 check whether an incoming `INIT` `UPDATE` is a retransmission of the neighbor's initial `INIT`:

```c
/* Upstream eigrp_update.c lines 159-168 */
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

#### Failure Cascade:
1. Every newly created OpenEIGRP instance initializes `eigrp->sequence_number = 1` ([`eigrp_instance.c:262`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_instance.c#L262)).
2. When Neighbor B first forms an adjacency with Router A, Neighbor B's initial `INIT` `UPDATE` carries `sequence = 1`. Router A records `nbr->peer_init_sequence_number = 1`.
3. The adjacency reaches `EIGRP_NEIGHBOR_UP`, and Neighbor B sends subsequent non-`INIT` Updates (`sequence = 2, 3, ...`), proving that the initial `INIT` handshake has completed. However, `nbr->peer_init_sequence_number` remains `1`.
4. Neighbor B's EIGRP process restarts while Router A's hold timer for Neighbor B is still active.
5. Upon restart, Neighbor B initializes a fresh instance with `eigrp->sequence_number = 1` and sends a new `INIT` `UPDATE` carrying `sequence = 1`.
6. Router A receives `flags == EIGRP_INIT_FLAG` with `ntohl(eigrph->sequence) == 1`. Because `nbr->peer_init_sequence_number == 1`, lines 159–164 treat the restarted peer's `INIT` as a duplicate retransmission of the original `INIT`, send an ACK, and **return early** without ever executing the `peer restarted` resynchronization block at lines 251–266!
7. **Outcome:** Neighbor B waits for Router A's `INIT` `UPDATE` (which is never sent), leaving the restarted neighbor wedged in `PENDING` state or missing Router A's routes until hold timers expire.

### 2.4 Proposed Upstream Patch
Once a neighbor sends any non-`INIT` `UPDATE` (`!(flags & EIGRP_INIT_FLAG)` with `sequence != 0`), its initial `INIT` exchange is complete. Advancing `nbr->peer_init_sequence_number` to a non-zero sentinel (`UINT32_MAX`) preserves `peer_init_previously_seen == true` while ensuring that a subsequent restart reusing `sequence = 1` triggers the `peer restarted` resynchronization path:

```diff
--- a/eigrp/code/eigrp_update.c
+++ b/eigrp/code/eigrp_update.c
@@ -156,6 +156,9 @@ void eigrp_update_receive(eigrp_instance_t *eigrp, eigrp_nbr_t *nbr,
 	 * that field tracks the most recently processed packet, not the INIT
 	 * for this adjacency.  An already accepted INIT must be ACKed, not
 	 * interpreted as a fresh peer restart or delivered to DUAL again. */
+	if (!(flags & EIGRP_INIT_FLAG) && ntohl(eigrph->sequence) != 0
+	    && nbr->peer_init_sequence_number != 0)
+		nbr->peer_init_sequence_number = UINT32_MAX;
 	if (flags == EIGRP_INIT_FLAG
 	    && ntohl(eigrph->sequence) != 0
 	    && nbr->peer_init_sequence_number == ntohl(eigrph->sequence)) {
```

---

## 3. Defect 2: Dual-Stack (`ipv4-unicast` + `ipv6-unicast`) Interface State Updates Clobber `ei->address` Across Address Families

### 3.1 Affected Source Location
* **Files & Functions:**
  * [`src/upstream/eigrp/eigrp/code/eigrp_network.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_network.c#L323-L343) — [`eigrp_sys_intf_update()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_network.c#L323) (Lines 323–343)
  * [`src/upstream/eigrp/eigrp/code/eigrp_interface.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_interface.c#L1200-L1207) — [`eigrp_intf_runtime_state_update()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_interface.c#L1182) (Lines 1200–1207) and [`eigrp_intf_runtime_update()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_interface.c#L1316) (Lines 1339–1345)

### 3.2 Flawed Behavior & Event Sequence
In [`eigrp_network.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_network.c#L323-L343), `eigrp_sys_intf_update()` broadcasts host interface updates to every address-family instance in the VRF without checking whether `state->address.address.afi` matches `eigrp->af_vectors.afi`:

```c
/* Upstream eigrp_network.c lines 334-342 */
pthread_mutex_lock(&eigrp_process.hierarchy_lock);
for (EIGRP_LIST_ITERATE_RO(eigrp_process.virt_router, vr_node, virt_router)) {
    for (EIGRP_LIST_ITERATE_RO(virt_router->af_instance, af_node, eigrp)) {
        if (eigrp->vrf_id != vrf_id || eigrp->shutdown)
            continue;
        (void)eigrp_instance_intf_update_event_enqueue(eigrp, state);
    }
}
pthread_mutex_unlock(&eigrp_process.hierarchy_lock);
```

And if `eigrp_intf_runtime_update()` is invoked when an `eigrp_intf_t *ei` already exists for `state->ifindex` (`eigrp_intf_lookup_by_ifindex(eigrp, state->ifindex)`), [`eigrp_intf_runtime_state_update()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_interface.c#L1200-L1207) unconditionally overwrites `ei->address = state->address` even if `state->address.address.afi != eigrp->af_vectors.afi`.

#### Failure Cascade:
1. A router runs both `ipv4-unicast` and `ipv6-unicast` on the same interface (`ifindex = 5`).
2. When the host shim reports an IPv6 link-local address update (`EIGRP_AFI_IPV6`) via `eigrp_sys_intf_update()`, the event is enqueued to both the IPv4 and IPv6 instances.
3. If `eigrp_intf_runtime_update()` is called directly or via runtime state refresh, the IPv4 instance's `ei->address` is overwritten with the `EIGRP_AFI_IPV6` prefix (or vice versa), breaking source-address validation and connected prefix origination.

### 3.3 Proposed Upstream Patch
Filter `eigrp_sys_intf_update()` by `eigrp->af_vectors.afi == state->address.address.afi` and guard `ei->address` updates in `eigrp_intf_runtime_state_update()`:

```diff
--- a/eigrp/code/eigrp_network.c
+++ b/eigrp/code/eigrp_network.c
@@ -334,7 +334,8 @@ void eigrp_sys_intf_update(
 	pthread_mutex_lock(&eigrp_process.hierarchy_lock);
 	for (EIGRP_LIST_ITERATE_RO(eigrp_process.virt_router, vr_node, virt_router)) {
 		for (EIGRP_LIST_ITERATE_RO(virt_router->af_instance, af_node, eigrp)) {
-			if (eigrp->vrf_id != vrf_id || eigrp->shutdown)
+			if (eigrp->vrf_id != vrf_id || eigrp->shutdown
+			    || eigrp->af_vectors.afi != state->address.address.afi)
 				continue;
 			(void)eigrp_instance_intf_update_event_enqueue(eigrp, state);
 		}
```

---

## 4. Defect 3: Self-Originated Route Feasibility Collapse ($RD == FD$) and Metric Miscalculation in `eigrp_topology_metric_update()`

### 4.1 Affected Source Location
* **File:** [`src/upstream/eigrp/eigrp/code/eigrp_topology.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L1245-L1283)
* **Functions:**
  * [`eigrp_topology_metric_update()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L1245) (Lines 1245–1283)
  * [`eigrp_topology_route_select()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L331) (Lines 350–351)
  * [`eigrp_topology_update_node_flags()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L1125) (Lines 1151–1157)

### 4.2 RFC Standard Requirement
* **RFC 7868 §5.1, §5.5, & §5.6.1**:
  * Locally originated routes (`route->adv_router == eigrp->neighbor_self`, including connected interfaces and redistributed routes) have a Reported Distance of **0** ($RD = 0$) and always satisfy the Feasibility Condition ($RD < FD$).
  * A locally connected subnet (`route->adv_router == eigrp->neighbor_self && route->ei != NULL`) has `hop_count = 0` and its composite metric is derived once from `route->ei->params.{bandwidth, delay, load, reliability}`.
  * When advertising the best route for a prefix to neighbors, the outgoing `prefix->reported_metric` must reflect the local router's `best->total_metric` (which includes the ingress link cost for learned routes).

### 4.3 Flawed Behavior & Event Sequence
In [`eigrp_topology.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L1259-L1275):

```c
/* Upstream eigrp_topology.c lines 1259-1275 */
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
```

When an interface bandwidth/delay or K-value is modified at runtime and `eigrp_topology_metric_update()` executes, four separate bugs occur:
1. **Self-Originated Feasibility Collapse ($RD == FD$)**: Line 1261 overwrites `route->reported_distance` (which was `0` for `neighbor_self`) with `eigrp_metric_calculate(eigrp, route->reported_metric)`. For a local route, `reported_distance` becomes equal to `distance` ($RD == FD$), causing `eigrp_topology_update_node_flags()` (`route->reported_distance < dest->fdistance`) and `eigrp_topology_route_select()` (`route->reported_distance >= prefix->fdistance`) to strip `EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG` from the router's own connected and redistributed routes.
2. **Connected Route Delay Double-Counting & Hop Increment**: For a connected route (`route->adv_router == eigrp->neighbor_self && route->ei != NULL`), line 1263 calls `eigrp_metric_total_calculate(eigrp, route)`. That function starts from `route->reported_metric` (which already contains the interface's initial delay), **adds** `eigrp_delay_to_scaled(ei->params.delay)` a second time, increments `hop_count++` on a local 0-hop subnet, and fails to update `route->reported_metric` if `ei->params.delay` was reduced or `ei->params.bandwidth` was increased.
3. **Redistributed Seed Delay Unscaled During Metric Sweep**: For locally redistributed external routes (`!route->ei && route->adv_router == eigrp->neighbor_self`), `eigrp_topology_redistributed_route_update()` stores `route->total_metric.delay` in raw 10-microsecond units and computes initial distance via `eigrp_topology_redistributed_distance()` (which scales delay via `eigrp_delay_to_scaled()`). However, line 1265 calls `eigrp_metric_calculate(eigrp, route->total_metric)` directly without `eigrp_topology_redistributed_distance()`, causing the redistributed route's distance to drop by $256\times$ on the delay component during any metric sweep.
4. **Outgoing Advertised Metric Missing Ingress Link Cost**: Line 1274 sets `prefix->reported_metric = best->reported_metric` instead of `best->total_metric`, causing outgoing Updates for neighbor-learned routes to advertise the upstream neighbor's reported metric without the local router's ingress link cost.

### 4.4 Proposed Upstream Patch
```diff
--- a/eigrp/code/eigrp_topology.c
+++ b/eigrp/code/eigrp_topology.c
@@ -1257,11 +1257,34 @@ void eigrp_topology_metric_update(eigrp_instance_t *eigrp)
 		if (!prefix || prefix->state != EIGRP_FSM_STATE_PASSIVE)
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
+				} else if (route->ei && route->type == eigrp->af_vectors.classic_internal_tlv_type) {
+					eigrp_metrics_t m = {0};
+					m.bandwidth = eigrp_bandwidth_to_scaled(route->ei->params.bandwidth);
+					m.delay = eigrp_delay_to_scaled(route->ei->params.delay);
+					m.load = route->ei->params.load;
+					m.reliability = route->ei->params.reliability;
+					m.mtu[0] = 0xDC;
+					m.mtu[1] = 0x05;
+					route->metric = m;
+					route->reported_metric = m;
+					route->total_metric = m;
+					route->distance = eigrp_metric_calculate(eigrp, m);
+				} else if (!route->ei && route->type == eigrp->af_vectors.classic_external_tlv_type) {
+					route->distance = eigrp_topology_redistributed_distance(eigrp, &route->metric);
+				} else {
+					route->distance = eigrp_metric_calculate(eigrp, route->total_metric);
+				}
+			} else {
+				route->reported_distance = eigrp_metric_calculate(eigrp, route->reported_metric);
+				if (route->ei)
+					route->distance = eigrp_metric_total_calculate(eigrp, route);
+				else
+					route->distance = eigrp_metric_calculate(eigrp, route->total_metric);
+			}
 		}
 		eigrp_topology_route_queue_resort(prefix->internal_routes);
 		eigrp_topology_route_queue_resort(prefix->external_routes);
@@ -1269,8 +1292,8 @@ void eigrp_topology_metric_update(eigrp_instance_t *eigrp)
 		if (best) {
 			prefix->distance = best->distance;
 			prefix->fdistance = best->distance;
-			prefix->rdistance = best->reported_distance;
-			prefix->reported_metric = best->reported_metric;
+			prefix->rdistance = best->distance;
+			prefix->reported_metric = best->total_metric;
 		}
 		eigrp_topology_update_node_flags(eigrp, prefix);
```

---

## 5. Defect 4: Topology-Level `maximum-prefix` Admission (`eigrp_topology_prefix_admit`) Never Called by TLV Decoders and Counts Poisoned Nodes

### 5.1 Affected Source Location
* **Files & Functions:**
  * [`src/upstream/eigrp/eigrp/code/eigrp_topology.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L2273-L2315) — [`eigrp_topology_prefix_count()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L2273) and [`eigrp_topology_prefix_admit()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L2287) (Lines 2273–2315)
  * [`src/upstream/eigrp/eigrp/code/eigrp_tlv1.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_tlv1.c) & [`src/upstream/eigrp/eigrp/code/eigrp_tlv2.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_tlv2.c)

### 5.2 Flawed Behavior & Event Sequence
1. **Uncalled Admission Function:** Upstream defines `eigrp_topology_prefix_admit(eigrp_instance_t *runtime, const eigrp_prefix_t *prefix)` in `eigrp_topology.c` to enforce the instance/topology-level `maximum-prefix` configuration (`af->topology_maximum_prefix`), log threshold warnings, and emit `EIGRP_EVENTLOG_OPCODE_PREFIX_LIMIT_REJECT`. However, **nothing in `eigrp/code/` ever calls `eigrp_topology_prefix_admit()`**—the TLV1 and TLV2 decoders only call `eigrp_nbr_prefix_admit(eigrp, nbr, &dest)` (which checks per-neighbor `maximum-prefix`).
2. **Poisoned Entries Counted Against Limit:** `eigrp_topology_prefix_count()` counts every non-NULL `node->info` in `runtime->topology_table`, including poisoned/unreachable prefixes (`distance == EIGRP_MAX_METRIC` or `metric.delay == EIGRP_MAX_METRIC`) that are being withdrawn.

### 5.3 Proposed Upstream Patch
Invoke `eigrp_topology_prefix_admit()` from `eigrp_nbr_prefix_admit()` (or directly in the TLV1/TLV2 decoders alongside `eigrp_nbr_prefix_admit()`), and ignore unreachable (`EIGRP_MAX_METRIC`) entries when counting active topology prefixes:

```diff
--- a/eigrp/code/eigrp_topology.c
+++ b/eigrp/code/eigrp_topology.c
@@ -2278,10 +2278,15 @@ static uint32_t eigrp_topology_prefix_count(eigrp_instance_t *runtime)
 	if (!runtime || !runtime->topology_table)
 		return 0;
 	for (node = eigrp_table_first(runtime->topology_table); node;
-	     node = eigrp_table_next(node))
-		if (node->info)
+	     node = eigrp_table_next(node)) {
+		eigrp_prefix_descriptor_t *pfx = node->info;
+		if (!pfx)
+			continue;
+		eigrp_route_descriptor_t *best = eigrp_topology_route_read(pfx);
+		if (best && best->distance != EIGRP_MAX_METRIC
+		    && best->metric.delay != EIGRP_MAX_METRIC)
 			count++;
+	}
 	return count;
 }
```

---

## 6. Defect 5: Summary Route Component Selection (Split-Horizon, Metric, and Origin) & Suppressed-Component Query Handling

### 6.1 Affected Source Location
* **File:** [`src/upstream/eigrp/eigrp/code/eigrp_summary.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_summary.c#L221-L330)
* **Functions:**
  * [`eigrp_summary_route_build()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_summary.c#L221) (Lines 221–294)
  * [`eigrp_summary_query_route_build()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_summary.c#L297) (Lines 297–330)

### 6.2 Flawed Behavior & Event Sequence
1. **Component Route Copied Verbatim into Summary Route (`eigrp_summary_route_build`)**:
   - At lines 261–275, `eigrp_summary_route_build()` finds `best_route` among covered components and executes `*summary_route = *best_route` and `summary_prefix->reported_metric = summary_route->metric`.
   - If `best_route` was learned from an EIGRP neighbor, `best_route->metric` is the neighbor's *reported* metric (without the local router's ingress link cost), whereas `best_route->total_metric` is the local composite metric vector.
   - If `best_route` was redistributed (`type == classic_external_tlv_type`), `summary_route` inherits the external TLV type instead of `classic_internal_tlv_type`, and retains the component's `ei` and `adv_router` instead of `adv_router = eigrp->neighbor_self` and `ei = NULL`.
   - When selecting candidate components for summary advertisement on interface `ei`, lines 251–269 do not skip component routes learned from a neighbor on that same outgoing interface `ei` (`candidate_route->ei == ei && candidate_route->adv_router != eigrp->neighbor_self`), nor do they skip components with `candidate->distance == EIGRP_MAX_METRIC`.
2. **Queries for Suppressed Component Prefixes (`eigrp_summary_query_route_build`)**:
   - In `eigrp_summary_query_route_build()` (lines 311–315), the function only matches when `destination` equals the configured summary aggregate prefix itself (`eigrp_summary_prefix_match(&configured->prefix, destination)`).
   - When a component prefix covered by an active summary on `ei` (and not permitted by a `leak-map`) is queried or transitions state, `eigrp_summary_query_route_build()` returns `false` instead of building an unreachable (`EIGRP_MAX_METRIC`) response for the suppressed component on `ei`.

### 6.3 Proposed Upstream Patch
Normalize `summary_route` fields in `eigrp_summary_route_build()` (excluding same-interface neighbor components and using `best_route->total_metric`, `adv_router = eigrp->neighbor_self`, `type = eigrp->af_vectors.classic_internal_tlv_type`), and in `eigrp_summary_query_route_build()` return a poisoned (`EIGRP_MAX_METRIC`) route when `eigrp_summary_covers(eigrp, ei, destination) && !eigrp_summary_specific_leak(eigrp, ei, destination)` (as implemented in [`src/cshim/srl_cshim_overrides.c:145-256`](file:///home/awhitaker/dev/srl-eigrp/src/cshim/srl_cshim_overrides.c#L145-L256)).

---

## 7. Defect 6: Query Origin Added to Reply-Status Table (`prefix->rij`) When `split-horizon` Is Disabled or on Shared Segments

### 7.1 Affected Source Location
* **File:** [`src/upstream/eigrp/eigrp/code/eigrp_packetizer.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_packetizer.c#L332-L346)
* **Function:** [`eigrp_packetizer_query_rij_add()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_packetizer.c#L332) (Lines 332–346)

### 7.2 RFC Standard Requirement
* **RFC 7868 §3.5 & §5.3.1 (Diffusing Computations)**:
  * When router $i$ enters Active state in response to a `QUERY` from neighbor $k$ (`prefix->query_origin = k`), neighbor $k$ is waiting for a `REPLY` from router $i$ and must never be added to router $i$'s expected reply set (`prefix->rij`).

### 7.3 Flawed Behavior & Event Sequence
While `eigrp_packetizer_query_split_horizon()` (lines 325–330) suppresses sending a `QUERY` on `prefix->query_origin->ei` when `ei->split_horizon == true`, if `split-horizon` is disabled on the interface (`ei->split_horizon == false`) or if multiple EIGRP neighbors share a multi-access broadcast segment and a query is emitted on `ei`, `eigrp_packetizer_query_rij_add()` iterates all `UP` neighbors on `ei` without skipping `prefix->query_origin`:

```c
/* Upstream eigrp_packetizer.c lines 332-346 */
static void eigrp_packetizer_query_rij_add(eigrp_prefix_descriptor_t *prefix,
					    eigrp_intf_t *ei)
{
	eigrp_nbr_t *nbr;
	eigrp_list_item_t *node;

	if (!prefix || !prefix->rij || !ei)
		return;

	for (EIGRP_LIST_ITERATE_RO(ei->nbrs, node, nbr)) {
		if (nbr->state != EIGRP_NEIGHBOR_UP)
			continue;
		eigrp_fsm_reply_status_add(prefix, nbr);
	}
}
```

### 7.4 Proposed Upstream Patch
```diff
--- a/eigrp/code/eigrp_packetizer.c
+++ b/eigrp/code/eigrp_packetizer.c
@@ -341,6 +341,8 @@ static void eigrp_packetizer_query_rij_add(eigrp_prefix_descriptor_t *prefix,
 	for (EIGRP_LIST_ITERATE_RO(ei->nbrs, node, nbr)) {
 		if (nbr->state != EIGRP_NEIGHBOR_UP)
 			continue;
+		if (prefix->query_origin && nbr == prefix->query_origin)
+			continue;
 		eigrp_fsm_reply_status_add(prefix, nbr);
 	}
 }
```
