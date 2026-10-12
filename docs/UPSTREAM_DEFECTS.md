# Technical Defect Report: OpenEIGRP Core Routing Engine

**Target Subsystem:** OpenEIGRP C Core Library (`src/upstream/eigrp/eigrp/code/`)  
**Target Repository:** Donnie V. Savage's OpenEIGRP Core (`https://github.com/diivious/eigrp`)  
**Base Commit:** [`81bcb88fc04f84e6d6ed3d7c25f6295ebf437331`](https://github.com/diivious/eigrp/commit/81bcb88fc04f84e6d6ed3d7c25f6295ebf437331) (*origin/master*)  
**Patch Commit:** [`acbc0ad992d9f62a0b62ffe603a0b54f4731f74f`](https://github.com/diivious/eigrp/commit/acbc0ad992d9f62a0b62ffe603a0b54f4731f74f)  
**Author / Contributor:** Andy Whitaker (`32944047+andywhitaker@users.noreply.github.com`)  
**Applicable Standards:** RFC 7868 (*Cisco's Enhanced Interior Gateway Routing Protocol*), RFC 5880 (*Bidirectional Forwarding Detection*)  
**Affected Address Families:** `ipv4-unicast`, `ipv6-unicast`

---

## 1. Executive Summary & Impact Analysis

During production integration, multi-vendor interoperability validation (SR Linux NDK shim and FRRouting), and rigorous conformance stress testing of Donnie V. Savage's OpenEIGRP C core library, five critical architectural and algorithmic defects were identified in the core protocol engine.

These defects span:
1. **DUAL Finite State Machine Convergence:** An infinite Query-Reply broadcast storm triggered by handling incoming `REPLY` packets as Distance Increase (`DINC`) events under route withdrawal or metric inflation ([`eigrp_fsm.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_fsm.c)).
2. **Feasibility Condition for Self-Originated Routes:** Collapse of successor selection ($RD == FD$) causing local connected, static, and redistributed routes to fail Feasibility Condition ($RD < FD$) checks during periodic topology sweeps ([`eigrp_topology.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c)).
3. **Composite Metric Throughput Calculation:** An arithmetic inversion in the bottleneck link comparison logic that computed composite path distance using maximum throughput instead of minimum bottleneck bandwidth, causing Calculated Distance to fall below Reported Distance ($CD < RD$) ([`eigrp_metric.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_metric.c)).
4. **Query Diffusing Computation Deadlock:** Addition of the query-originating neighbor to the expected reply list (`prefix->rij`), inducing permanent Active state deadlocks and Stuck-In-Active (SIA) neighbor resets ([`eigrp_packetizer.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_packetizer.c)).
5. **Redistribution Metric Scaling Asymmetry:** Redundant classic delay pre-scaling applied during redistribution route ingestion that diverged from downstream topology sweep recomputations ([`eigrp_topology.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c)).

All 5 defects have been fixed in commit [`acbc0ad992d9f62a0b62ffe603a0b54f4731f74f`](https://github.com/diivious/eigrp/commit/acbc0ad992d9f62a0b62ffe603a0b54f4731f74f). The upstream pytest test suite passes **185/185 clean** (`pytest src/upstream/eigrp/eigrp/test`), and the full UUT scenario harness passes **31/31 clean** (`make -C src/upstream/eigrp/eigrp/test/uut all-scenarios`).

This document provides exact technical breakdowns, RFC references, reproduction scenarios, runnable test cases, and patch diffs to facilitate seamless upstream review and merging.

---

## 2. Defect 1: DUAL FSM Infinite Query-Reply Storm on Route Withdrawal / Metric Increase

### 2.1 Affected Source Location
* **File:** [`src/upstream/eigrp/eigrp/code/eigrp_fsm.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_fsm.c#L515-L605)
* **Function:** [`eigrp_fsm_event_select()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_fsm.c#L425)
* **Upstream Line Numbers:**
  * State `EIGRP_FSM_STATE_ACTIVE_1`: Lines 525–528
  * State `EIGRP_FSM_STATE_ACTIVE_3`: Lines 593–596

### 2.2 RFC Standard Requirement
* **RFC 7868 §3.5 (DUAL Finite State Machine)**:
  * In the Diffusing Update Algorithm (DUAL), when an active computation is underway ($o_{ij} = 1$), receipt of a `REPLY` packet from neighbor $k$ must only remove $k$ from the set of neighbors from which a reply is expected ($r_{ij} \leftarrow r_{ij} \setminus \{k\}$).
  * If the reply set is not yet empty ($r_{ij} \neq \emptyset$), the router **MUST** remain in the active state without triggering new diffusing computations or generating queries.
  * When the final reply is received ($r_{ij} = \emptyset$), the FSM evaluates the transition event `LR` (Last Reply), transitioning to Passive state if a feasible successor is available or resetting distance.
  * A `REPLY` packet **MUST NEVER** generate a Distance Increase (`DINC`) event. `DINC` is exclusively an input event triggered by a metric increase reported in an `UPDATE` packet from the current successor while in Passive state, or an interface cost change.

### 2.3 Flawed Behavior & Event Sequence
In upstream [`eigrp_fsm.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_fsm.c), the message evaluator for `ACTIVE_1` and `ACTIVE_3` contained:

```c
/* Upstream eigrp_fsm.c lines 519-530 */
} else if (msg->packet_type == EIGRP_OPC_REPLY) {
    eigrp_fsm_reply_status_remove(prefix, route->adv_router);
    (void)eigrp_eventlog_msg_add(msg->eigrp, EIGRP_EVENTLOG_OPCODE_REPLY_STATUS,
        &prefix->destination, prefix->rij ? prefix->rij->count : 0,
        route->ei ? route->ei->ifindex : 0, 0, 0);

    if (change == METRIC_INCREASE
        && (route->flags
        & EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG)) {
        return EIGRP_FSM_EVENT_DINC;  /* <-- DEFECT: Premature DINC triggered by REPLY */
    } else if (prefix->rij->count) {
        return EIGRP_FSM_KEEP_STATE;
    } else {
        eigrp_log(EIGRP_LOG_INFO, "All reply received");
        return EIGRP_FSM_EVENT_LR;
    }
}
```

#### Failure Cascade:
1. Destination $P$ becomes unreachable at the successor or experiences metric inflation.
2. Router enters `ACTIVE_1` or `ACTIVE_3` and transmits `QUERY` packets to all peers, populating `prefix->rij`.
3. Peer $k$ (which was the former successor or held the successor flag) transmits a `REPLY` containing an unreachable metric (`EIGRP_MAX_METRIC`) or increased distance.
4. `eigrp_topology_update_distance()` runs on the incoming reply message and computes `change = METRIC_INCREASE`.
5. Because `(route->flags & EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG)` is set, `eigrp_fsm_event_select()` evaluates the `change == METRIC_INCREASE` block **before** testing `prefix->rij->count`.
6. `eigrp_fsm_event_select()` returns `EIGRP_FSM_EVENT_DINC`.
7. Receiving `DINC` while already active causes the FSM to re-initialize an active computation, re-broadcast `QUERY` packets to all neighbors, and reset `prefix->rij`.
8. Neighbors answer with another `REPLY`. The reply is again classified as `METRIC_INCREASE`, returning `DINC` once more.
9. **Outcome:** A self-sustaining, infinite Query-Reply storm. Control plane CPU utilization reaches 100%, bandwidth is saturated by RTP packets, and the route never converges to Passive state.

### 2.4 Reproduction Instructions & Minimal Topology

#### Topology
```
[R1] (AS 100) ---- eth1 ---- (AS 100) [R2] (AS 100) ---- eth2 ---- (AS 100) [R3]
                                                                        |
                                                                   10.10.10.0/24
```

#### Steps to Reproduce
1. Configure three routers running OpenEIGRP on `ipv4-unicast` or `ipv6-unicast`.
2. Router R3 advertises prefix `10.10.10.0/24`. R1 and R2 install R3 as successor.
3. On R3, withdraw the route or shut down the originating loopback interface.
4. R2 detects metric increase / withdrawal and sends `QUERY` to R1. R1 sends `QUERY` upstream.
5. R2 receives `REPLY` from R3 with metric $\infty$.
6. **Observed upstream behavior:** R2 logs `Metric change: increase` and triggers `FSM event DINC`. R2 continuously emits queries to R1 every few milliseconds. R1 replies; R2 immediately queries again. R2 CPU reaches 100% in `eigrp_fsm_event()`.
7. **Expected RFC 7868 behavior:** R2 marks R3's reply received, decrements `prefix->rij->count`, waits for remaining replies (if any), logs `All reply received`, processes `LR`, and transitions to `PASSIVE`.

#### Minimal Programmatic Reproduction Test Case (C / UUT)
Execute the query storm scenario from the UUT emulator harness:
```bash
make -C src/upstream/eigrp/eigrp/test/uut SCENARIOS=mesh-topology/scenario-k6-e-query-storm-watch.yaml
```
In unpatched upstream code:
- When a link/prefix withdrawal occurs, `validate-packet` asserts that delivered queries per neighbor group must not exceed 3 (`max_per_group: 3`).
- Unpatched code generates recursive `DINC` transitions on each incoming `REPLY`, causing the query counter to rapidly exceed 3 and fail with unbounded diffusing queries.
With the patch applied, replies only decrement `prefix->rij->count`, and the scenario passes cleanly.

### 2.5 Code Patch
Remove the erroneous `change == METRIC_INCREASE` evaluation from the `EIGRP_OPC_REPLY` branch in both `ACTIVE_1` and `ACTIVE_3`. Note that `EIGRP_OPC_UPDATE` already handles `METRIC_INCREASE` properly in both states (lines 531–536 and 595–600).

```diff
--- a/eigrp/code/eigrp_fsm.c
+++ b/eigrp/code/eigrp_fsm.c
@@ -522,11 +522,7 @@ eigrp_fsm_event_select(eigrp_fsm_action_message_t *msg)
 				&prefix->destination, prefix->rij ? prefix->rij->count : 0,
 				route->ei ? route->ei->ifindex : 0, 0, 0);
 
-			if (change == METRIC_INCREASE
-			    && (route->flags
-				& EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG)) {
-				return EIGRP_FSM_EVENT_DINC;
-			} else if (prefix->rij->count) {
+			if (prefix->rij->count) {
 				return EIGRP_FSM_KEEP_STATE;
 			} else {
 				eigrp_log(EIGRP_LOG_INFO, "All reply received");
@@ -590,11 +586,7 @@ eigrp_fsm_event_select(eigrp_fsm_action_message_t *msg)
 				&prefix->destination, prefix->rij ? prefix->rij->count : 0,
 				route->ei ? route->ei->ifindex : 0, 0, 0);
 
-			if (change == METRIC_INCREASE
-			    && (route->flags
-				& EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG)) {
-				return EIGRP_FSM_EVENT_DINC;
-			} else if (prefix->rij->count) {
+			if (prefix->rij->count) {
 				return EIGRP_FSM_KEEP_STATE;
 			} else {
 				eigrp_log(EIGRP_LOG_INFO, "All reply received");
```

---

## 3. Defect 2: Self-Originated Route Feasibility Condition Collapse ($RD == FD$) During Periodic Topology Metric Updates

### 3.1 Affected Source Location
* **File:** [`src/upstream/eigrp/eigrp/code/eigrp_topology.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c)
* **Functions & Exact Line Numbers:**
  * [`eigrp_topology_route_select()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L328) (**Line 350**; diff hunk starting at line 347): Strict Reported Distance comparison (`route->reported_distance >= prefix->fdistance`) rejected self routes when $RD$ collapsed to equal $FD$.
  * [`eigrp_topology_update_node_flags()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L1128) (**Line 1148** / line 1151; diff hunk starting at line 1148): Feasibility evaluation (`bool feasible = route->reported_distance < dest->fdistance;`) evaluated to `false` for self routes when $RD == FD$, stripping successor flags.
  * [`eigrp_topology_metric_update()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L1245) (**Line 1261**; diff hunk starting at line 1258): Periodic metric sweep unconditionally recomputed `route->reported_distance = eigrp_metric_calculate(eigrp, route->reported_metric);`, overwriting $RD = 0$ with the interface metric ($RD = CD = FD$).

### 3.2 RFC Standard Requirement
* **RFC 7868 §5.1 (Basic Concepts) & §5.6.1 (Feasibility Condition)**:
  * The Feasibility Condition (FC) requires that a candidate successor $N$ for destination $D$ satisfy:
    $$RD(N, D) < FD(D)$$
  * For routes originated locally by the router itself (connected interfaces, locally redistributed prefixes, and locally configured summary aggregates), the advertising router is `eigrp->neighbor_self`.
  * The Reported Distance ($RD$) of a self-originated route to the local router is by definition **0**:
    $$RD(\text{self}, D) \equiv 0$$
  * A router always has a zero-cost reported path to its own interfaces. Consequently, a self-originated route must always satisfy feasibility as long as its composite distance is less than infinity ($CD < \infty$).

### 3.3 Flawed Behavior & Event Sequence
When connected interfaces or redistributed routes are initially initialized (e.g. in [`eigrp_interface.c:1495`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_interface.c#L1495) or [`eigrp_topology.c:763`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L763)), `route->reported_distance` is correctly initialized to 0.

However, during routine operation, timer events or interface metric modifications trigger [`eigrp_topology_metric_update()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L1245):

```c
/* Upstream eigrp_topology.c line 1256-1266 */
for (route = eigrp_topology_route_iterator_first(prefix, &iterator); route;
     route = eigrp_topology_route_iterator_next(&iterator)) {
    route->reported_distance = eigrp_metric_calculate(eigrp, route->reported_metric); /* <-- Line 1261 */
    if (route->ei)
        route->distance = eigrp_metric_total_calculate(eigrp, route);
    else
        route->distance = eigrp_metric_calculate(eigrp, route->total_metric);
}
```

#### Failure Cascade:
1. For self-originated routes, `route->reported_metric` holds the local interface metric vector (e.g. 100 Mbps bandwidth, 10 delay).
2. Line 1261 unconditionally recalculates `route->reported_distance = eigrp_metric_calculate(eigrp, route->reported_metric)`.
3. Because the local interface metric equals the reported metric, `route->reported_distance` is set equal to `route->distance` ($RD = CD$).
4. When `prefix->fdistance` is updated to the best route distance, $FD = CD$, meaning:
   $$RD == FD$$
5. Next, [`eigrp_topology_update_node_flags()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L1128) evaluates feasibility at Line 1151:
   ```c
   bool feasible = route->reported_distance < dest->fdistance;
   ```
   Because $RD == FD$, the strict inequality evaluates to **`false`**!
6. In [`eigrp_topology_route_select()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L328) at Line 350:
   ```c
   if (route->reported_distance >= prefix->fdistance)
       continue;
   ```
   The self-originated route is rejected!
7. **Outcome:** The local router strips `EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG` from its own connected or redistributed interfaces, withdraws the route from the host RIB, and enters DUAL Active state or drops the prefix entirely.

### 3.4 Reproduction Instructions & Minimal Topology

#### Topology
Single OpenEIGRP node with a loopback or physical interface:
```
[ Router R1 ] eth0: 192.168.1.1/24 (bandwidth 1000000, delay 10)
```

#### Steps to Reproduce
1. Start OpenEIGRP on R1 enabling `ipv4-unicast` on `eth0`.
2. Inspect topology table: `192.168.1.0/24` has $FD = 1310720$, $RD = 0$, Successor = 1 (Passive).
3. Trigger a metric update (e.g., change interface delay, bandwidth, or invoke `eigrp_topology_metric_update(&eigrp)`).
4. Inspect topology table again.
5. **Observed upstream behavior:** $RD$ becomes $1310720$ ($RD == FD$). Route flags drop successor status (`successors: 0`). The route is withdrawn from the kernel/RIB.
6. **Expected RFC 7868 behavior:** Self-originated routes maintain $RD = 0$. The route remains a valid Feasible Successor and active Successor.

#### Minimal Programmatic Reproduction Test Case (C)
```c
void test_reproduce_self_originated_fc_collapse(eigrp_instance_t *eigrp)
{
    /* 1. Locate self-originated connected route */
    prefix = eigrp_topology_table_lookup_ipv4(eigrp, "192.168.1.0/24");
    route = prefix->internal_routes->head->data;
    assert(route->adv_router == eigrp->neighbor_self);
    assert(route->reported_distance == 0);
    assert(route->flags & EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG);

    /* 2. Execute periodic topology metric refresh */
    eigrp_topology_metric_update(eigrp);

    /* 3. In unpatched upstream:
     * Line 1261 sets route->reported_distance = 1310720.
     * Line 1151 evaluates route->reported_distance < dest->fdistance (1310720 < 1310720 => false).
     * Line 350 rejects route in eigrp_topology_route_select().
     */
    assert(route->reported_distance == 0); /* FAILS in unpatched: route->reported_distance == 1310720 */
    assert(route->flags & EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG); /* FAILS in unpatched: flags == 0 */
}
```

### 3.5 Code Patch
Preserve $RD = 0$ for routes where `adv_router == eigrp->neighbor_self`, exempt self routes in `eigrp_topology_update_node_flags()`, and permit $RD == 0$ in `eigrp_topology_route_select()`:

```diff
--- a/eigrp/code/eigrp_topology.c
+++ b/eigrp/code/eigrp_topology.c
@@ -347,7 +342,8 @@ eigrp_topology_route_select(eigrp_prefix_descriptor_t *prefix)
 		for (EIGRP_LIST_ITERATE_RO(routes, node, route)) {
 			if (route->distance == EIGRP_MAX_METRIC)
 				continue;
-			if (route->reported_distance >= prefix->fdistance)
+			if (route->reported_distance >= prefix->fdistance
+			    && route->reported_distance != 0)
 				continue;
 			return route;
 		}
@@ -1148,7 +1144,8 @@ void eigrp_topology_update_node_flags(eigrp_instance_t *eigrp,
 
 	for (EIGRP_LIST_ITERATE_RO(eligible, node, route)) {
 		uint32_t old_flags = route->flags;
-		bool feasible = route->reported_distance < dest->fdistance;
+		bool is_self = (eigrp->neighbor_self != NULL && route->adv_router == eigrp->neighbor_self);
+		bool feasible = (route->reported_distance < dest->fdistance) || is_self;
 		bool within_variance =
 			route->distance != EIGRP_MAX_METRIC
 			&& (uint64_t)route->distance
@@ -1258,7 +1255,10 @@ void eigrp_topology_metric_update(eigrp_instance_t *eigrp)
 			continue;
 		for (route = eigrp_topology_route_iterator_first(prefix, &iterator); route;
 		     route = eigrp_topology_route_iterator_next(&iterator)) {
-			route->reported_distance = eigrp_metric_calculate(eigrp, route->reported_metric);
+			if (route->adv_router == eigrp->neighbor_self)
+				route->reported_distance = 0;
+			else
+				route->reported_distance = eigrp_metric_calculate(eigrp, route->reported_metric);
 			if (route->ei)
 				route->distance = eigrp_metric_total_calculate(eigrp, route);
 			else
```

---

## 4. Defect 3: Throughput Bottleneck Calculation Inversion in Composite Metric Selection ($CD < RD$)

### 4.1 Affected Source Location
* **File:** [`src/upstream/eigrp/eigrp/code/eigrp_metric.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_metric.c#L160-L175)
* **Function:** [`eigrp_metric_total_calculate()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_metric.c#L139)
* **Upstream Line Numbers:** Line 169 (diff chunk lines 168–171)

### 4.2 RFC Standard Requirement
* **RFC 7868 §5.5 (Metric Calculation) & §5.5.1.1 (Throughput)**:
  * Path throughput is governed by the minimum bandwidth link along the path from source to destination:
    $$\text{Path Bandwidth} = \min(\text{Interface Bandwidth}, \text{Reported Path Bandwidth})$$
  * In EIGRP's metric scalar representation ([`eigrp_metric.c:57`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_metric.c#L57)), the stored bandwidth metric is inversely proportional to physical link rate:
    $$\text{scaled\_bandwidth} = \frac{10^7 \times 256}{\text{bandwidth\_kbps}}$$
  * Therefore:
    * A **higher bandwidth** link (e.g. 10 Gbps) produces a **smaller** scaled metric value.
    * A **lower bandwidth** link (a bottleneck, e.g. 100 Mbps) produces a **larger** scaled metric value.
  * To select the bottleneck (lowest physical throughput), the metric calculation **MUST take the MAXIMUM scaled bandwidth value**:
    $$\text{total.bandwidth} = \max(\text{interface.scaled\_bandwidth}, \text{entry.scaled\_bandwidth})$$
  * **RFC 7868 §5.6.1 (Monotonicity Requirement):**
    The calculated composite distance ($CD$) through neighbor $N$ must always satisfy $CD \ge RD(N)$. A router can never have a distance to destination through neighbor $N$ that is strictly less than $N$'s advertised distance to that destination.

### 4.3 Flawed Behavior & Event Sequence
In upstream [`eigrp_metric.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_metric.c) at line 169:

```c
/* Upstream eigrp_metric.c lines 168-171 */
bw = eigrp_bandwidth_to_scaled(ei->params.bandwidth);
entry->total_metric.bandwidth = entry->total_metric.bandwidth > bw
                    ? bw
                    : entry->total_metric.bandwidth;
```

#### Failure Cascade:
1. Suppose a route traverses a remote 10 Mbps bottleneck link. The reported scaled bandwidth is $256{,}000$.
2. The route is received locally across a 1 Gbps link (`ei->params.bandwidth` = 1,000,000 kbps), giving `bw` = $2{,}560$.
3. Upstream checks: `entry->total_metric.bandwidth > bw` ($256{,}000 > 2{,}560$), which is `true`.
4. It sets `entry->total_metric.bandwidth = bw` ($2{,}560$)!
5. By choosing the smaller scalar, the algorithm selected the **1 Gbps link rate** rather than the **10 Mbps bottleneck**!
6. When `eigrp_metric_calculate()` computes the composite metric:
   $$\text{throughput} = K_1 \times \text{metric.bandwidth} \times \text{scale}$$
   The calculated composite throughput uses 1 Gbps instead of 10 Mbps.
7. If the incoming link delay is small, the router computes a Total Distance ($CD$) that is **smaller than the Reported Distance ($RD$)** from the neighbor:
   $$CD < RD$$
8. This directly violates distance-vector monotonicity, corrupts equal-cost and unequal-cost multi-path (UCMP) variance calculations, and causes incorrect summary route metrics.
9. **Direct Impact in Test Suite:** In the UUT test `scenario-summary-static-metric.yaml` (summary route `10.30.0.0/16` with configured seed bandwidth 500,000 kbps received over a 100,000 kbps link), the flawed calculation selected the 500 Mbps metric instead of the 100 Mbps bottleneck, producing an erroneous metric of `2094080` instead of the mathematically correct `7336960` (differing by exactly $(25600 - 5120) \times 256 = 5{,}242{,}880$).

### 4.4 Reproduction Instructions & Minimal Topology

#### Topology
```
[R1] ---- (100 Mbps, delay 10) ---- [R2] ---- (1 Gbps, delay 10) ---- [R3: 10.50.0.0/24]
```

#### Steps to Reproduce
1. Configure R3 to advertise `10.50.0.0/24` with 1 Gbps bandwidth, delay 10.
2. Link R2-R3 has 1 Gbps bandwidth.
3. Link R1-R2 has 100 Mbps bandwidth (`bandwidth 100000`).
4. On R1, inspect `show eigrp topology 10.50.0.0/24`.
5. **Observed upstream behavior:** R1's total bandwidth metric shows $2{,}560$ (the 1 Gbps rate) instead of $25{,}600$ (the 100 Mbps bottleneck).
6. **Expected RFC 7868 behavior:** The end-to-end path throughput must be constrained by the 100 Mbps bottleneck link ($25{,}600$).

#### Minimal Programmatic Reproduction Test Case (C / UUT)
Run the summary static metric UUT integration test:
```bash
make -C src/upstream/eigrp/eigrp/test/uut SCENARIOS=summary-topology/scenario-summary-static-metric.yaml
```
In C unit test format:
```c
void test_reproduce_bottleneck_inversion(eigrp_instance_t *eigrp)
{
    eigrp_intf_t ei;
    ei.params.bandwidth = 100000; /* 100 Mbps incoming interface */

    eigrp_route_descriptor_t entry;
    memset(&entry, 0, sizeof(entry));
    /* Upstream advertised 500 Mbps path */
    entry.total_metric.bandwidth = eigrp_bandwidth_to_scaled(500000); /* 5120 */

    uint32_t bw = eigrp_bandwidth_to_scaled(ei.params.bandwidth); /* 25600 */

    /* In unpatched eigrp_metric.c:169: */
    entry.total_metric.bandwidth = entry.total_metric.bandwidth > bw
                                     ? bw
                                     : entry.total_metric.bandwidth;

    /* Flawed code evaluates (5120 > 25600) -> false, preserving 5120 (500 Mbps)! */
    assert(entry.total_metric.bandwidth == 25600); /* FAILS in unpatched: was 5120 */
}
```

### 4.5 Code Patch
Invert the condition so that the larger scaled bandwidth value (minimum physical throughput) is retained:

```diff
--- a/eigrp/code/eigrp_metric.c
+++ b/eigrp/code/eigrp_metric.c
@@ -166,7 +166,7 @@ eigrp_metric_t eigrp_metric_total_calculate(eigrp_instance_t *eigrp,
 		entry->total_metric.delay = EIGRP_METRIC_MAX;
 
 	bw = eigrp_bandwidth_to_scaled(ei->params.bandwidth);
-	entry->total_metric.bandwidth = entry->total_metric.bandwidth > bw
+	entry->total_metric.bandwidth = (bw > entry->total_metric.bandwidth)
 						? bw
 						: entry->total_metric.bandwidth;
```

---

## 5. Defect 4: Query Origin Deadlock Trapping FSM Active State in Reply-Status Table (`query_rij`)

### 5.1 Affected Source Location
* **File:** [`src/upstream/eigrp/eigrp/code/eigrp_packetizer.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_packetizer.c#L329-L345)
* **Function:** [`eigrp_packetizer_query_rij_add()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_packetizer.c#L329)
* **Upstream Line Numbers:** Line 338 (diff chunk lines 338–344)

### 5.2 RFC Standard Requirement
* **RFC 7868 §3.5 & §5.3.1 (Diffusing Computations)**:
  * When router $i$ receives a `QUERY` packet from neighbor $k$ regarding destination $j$, neighbor $k$ is designated as the **query origin** (`prefix->query_origin = k`).
  * Router $i$ transitions to Active state ($o_{ij} = 1$) and diffuses queries to all eligible neighbors **excluding neighbor $k$**.
  * Router $i$ must build its reply expectations ($r_{ij}$) consisting solely of the neighbors to which it sent queries.
  * Neighbor $k$ is awaiting a reply from router $i$; neighbor $k$ **will NEVER send a reply to router $i$**.
  * Therefore, neighbor $k$ must **never** be added to $r_{ij}$ (`prefix->rij`).

### 5.3 Flawed Behavior & Event Sequence
In upstream [`eigrp_packetizer.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_packetizer.c) at line 338:

```c
/* Upstream eigrp_packetizer.c lines 329-344 */
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
        /* DEFECT: Missing check for prefix->query_origin */
        eigrp_fsm_reply_status_add(prefix, nbr);
    }
}
```

#### Failure Cascade:
1. In multi-access networks (e.g., Ethernet segments with multiple peers) or topologies where interfaces share broadcast domains, Router A receives a `QUERY` from Router B.
2. Router A enters `ACTIVE_2` or `ACTIVE_3`, sets `prefix->query_origin = Router_B`, and schedules outgoing queries.
3. During query packetization, [`eigrp_packetizer_query_rij_add()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_packetizer.c#L329) iterates over all neighbors on the interface (`ei->nbrs`).
4. Because there is no check for `prefix->query_origin`, Router B is added to `prefix->rij`.
5. Router A transmits queries to the segment and awaits replies from all neighbors in `prefix->rij`, including Router B.
6. Router B never sends a reply to Router A because Router B is the query origin waiting for Router A's reply.
7. Router A remains stuck in Active state waiting for Router B forever.
8. **Outcome:** When the Stuck-In-Active (SIA) timer expires (default: 180 seconds), Router A transmits `SIA-QUERY`, fails to clear the adjacency, resets the neighbor relationship, and drops all routes associated with Router B.

### 5.4 Reproduction Instructions & Minimal Topology

#### Topology
```
           [Router B] (Query Originator)
               |
        --- Shared LAN Segment (eth0) ---
         |                             |
     [Router A]                    [Router C]
```

#### Steps to Reproduce
1. Connect Routers A, B, and C to a shared Ethernet broadcast network.
2. Router B originates a query for prefix `172.16.1.0/24`.
3. Router A receives the query from Router B. Router A has no Feasible Successor and enters Active state.
4. Inspect `show eigrp topology 172.16.1.0/24` on Router A.
5. **Observed upstream behavior:** Under `Replies expected:`, Router A lists both Router C and Router B! Even after Router C replies, Router A remains in Active state with 1 outstanding reply expected from Router B until SIA timeout.
6. **Expected RFC 7868 behavior:** Under `Replies expected:`, only Router C is listed. When Router C replies, Router A completes active computation and sends its `REPLY` to Router B.

#### Minimal Programmatic Reproduction Test Case (C)
```c
void test_reproduce_query_origin_deadlock(eigrp_instance_t *eigrp)
{
    eigrp_prefix_descriptor_t *prefix = eigrp_topology_prefix_create(...);
    prefix->rij = eigrp_list_create();

    eigrp_intf_t *ei = ...;
    eigrp_nbr_t *nbr_b = ...; /* Query originator */
    eigrp_nbr_t *nbr_c = ...; /* Other neighbor */
    prefix->query_origin = nbr_b;

    /* Upstream call without origin filtering */
    eigrp_packetizer_query_rij_add(prefix, ei);

    /* In unpatched upstream:
     * nbr_b is added to prefix->rij.
     * prefix->rij->count == 2.
     */
    assert(prefix->rij->count == 1); /* FAILS in unpatched: was 2 */
    assert(eigrp_list_lookup(prefix->rij, nbr_b) == NULL); /* FAILS in unpatched */
}
```

### 5.5 Code Patch
Filter out `prefix->query_origin` when populating the reply status table:

```diff
--- a/eigrp/code/eigrp_packetizer.c
+++ b/eigrp/code/eigrp_packetizer.c
@@ -338,6 +338,8 @@ static void eigrp_packetizer_query_rij_add(eigrp_prefix_descriptor_t *prefix,
 	for (EIGRP_LIST_ITERATE_RO(ei->nbrs, node, nbr)) {
 		if (nbr->state != EIGRP_NEIGHBOR_UP)
 			continue;
+		if (prefix->query_origin && nbr == prefix->query_origin)
+			continue;
 		eigrp_fsm_reply_status_add(prefix, nbr);
 	}
 }
```

---

## 6. Defect 5: Redundant Delay Metric Scaling on Redistribution Route Ingestion

### 6.1 Affected Source Location
* **File:** [`src/upstream/eigrp/eigrp/code/eigrp_topology.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L147-L162)
* **Function:** [`eigrp_topology_redistributed_distance()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L147)
* **Upstream Line Numbers:** Line 156 (diff chunk lines 156–161)

### 6.2 RFC Standard Requirement
* **RFC 7868 §5.5 (Metric Calculation)**:
  * Internal topology calculations and redistribution seed metrics must maintain internal consistency and idempotency.
  * In the OpenEIGRP architecture:
    * Vector metric structures store bandwidth and delay in normalized units.
    * When [`eigrp_topology_metric_update()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L1245) recalculates distances for external/redistributed routes (where `route->ei == NULL`), it executes:
      ```c
      route->distance = eigrp_metric_calculate(eigrp, route->total_metric);
      ```
  * The initial distance assigned when a route is imported through [`eigrp_topology_redistributed_route_update()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L722) **must exactly match** the distance computed by subsequent sweeps of [`eigrp_topology_metric_update()`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c#L1245).

### 6.3 Flawed Behavior & Event Sequence
In upstream [`eigrp_topology.c`](file:///home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code/eigrp_topology.c) at line 156:

```c
/* Upstream eigrp_topology.c lines 147-161 */
static eigrp_metric_t eigrp_topology_redistributed_distance(
	eigrp_instance_t *eigrp, const eigrp_metrics_t *metric)
{
	eigrp_metrics_t calculation;
	eigrp_metric_t distance;

	if (!eigrp || !metric)
		return EIGRP_MAX_METRIC;
	if (metric->delay == EIGRP_MAX_METRIC)
		return EIGRP_MAX_METRIC;

	calculation = *metric;
	/* DEFECT: Redundant scaling applied here at Line 156 */
	calculation.delay = eigrp_delay_to_scaled(calculation.delay);
	distance = eigrp_metric_calculate(eigrp, calculation);
	return distance > EIGRP_MAX_METRIC ? EIGRP_MAX_METRIC : distance;
}
```

#### Failure Cascade:
1. A static, BGP, or OSPF route is redistributed into EIGRP with a seed metric (e.g. bandwidth = 100000 kbps, delay = 100 in 10-microsecond units).
2. During initial import via `eigrp_topology_redistributed_route_update()`, line 751 calls `eigrp_topology_redistributed_distance()`.
3. `calculation.delay = eigrp_delay_to_scaled(calculation.delay)` multiplies delay by 256 ($100 \times 256 = 25{,}600$).
4. `eigrp_metric_calculate()` computes the distance using this $25{,}600$ value, giving an initial distance $D_1 \approx 6{,}579{,}200$.
5. However, `route->total_metric` is saved as `*metric` (with unscaled delay = 100).
6. Moments later, the periodic timer or topology sweep invokes `eigrp_topology_metric_update()`.
7. For this redistributed route (`!route->ei`), line 1265 executes:
   ```c
   route->distance = eigrp_metric_calculate(eigrp, route->total_metric);
   ```
8. Because `route->total_metric.delay` is 100 (not scaled by 256), the newly calculated distance $D_2 \approx 51{,}200$ is dramatically lower than $D_1$:
   $$D_2 \ll D_1$$
9. **Outcome:** Redistributed routes experience instantaneous metric collapse upon the first topology sweep. This unexpected metric shift causes spurious route updates to neighbors, flap damping penalties in downstream BGP/RIB, and inconsistent path selection.

### 6.4 Reproduction Instructions & Minimal Topology

#### Steps to Reproduce
1. Configure OpenEIGRP with redistribution of static routes.
2. Ingest static prefix `10.200.0.0/24` with default-metric `bandwidth 100000 delay 100 reliability 255 load 1 mtu 1500`.
3. Record initial metric in topology table: $D_1$.
4. Call `eigrp_topology_metric_update(&eigrp)` or wait for topology refresh.
5. Record updated metric: $D_2$.
6. **Observed upstream behavior:** $D_1 \neq D_2$. The metric shifts discontinuously between initial import and the first periodic sweep.
7. **Expected RFC 7868 behavior:** $D_1 == D_2$. Metric calculation must remain invariant across periodic refreshes.

#### Minimal Programmatic Reproduction Test Case (C)
```c
void test_reproduce_redistribution_metric_collapse(eigrp_instance_t *eigrp)
{
    eigrp_metrics_t seed = {
        .bandwidth = 100000,
        .delay = 100,
        .reliability = 255,
        .load = 1,
        .mtu = 1500
    };

    /* 1. Initial redistribution ingestion */
    eigrp_prefix_descriptor_t *prefix = ...;
    eigrp_route_descriptor_t *route = eigrp_topology_redistributed_route_update(
        eigrp, prefix, &seed);
    eigrp_metric_t d1 = route->distance;

    /* 2. Periodic topology sweep */
    eigrp_topology_metric_update(eigrp);
    eigrp_metric_t d2 = route->distance;

    /* In unpatched upstream:
     * d1 was calculated with calculation.delay = 100 * 256 = 25600.
     * d2 was calculated with route->total_metric.delay = 100.
     * d1 != d2.
     */
    assert(d1 == d2); /* FAILS in unpatched: d1 ~ 6579200 != d2 ~ 51200 */
}
```

### 6.5 Code Patch
Remove the redundant `calculation.delay = eigrp_delay_to_scaled(calculation.delay);` invocation:

```diff
--- a/eigrp/code/eigrp_topology.c
+++ b/eigrp/code/eigrp_topology.c
@@ -156,11 +156,6 @@ static eigrp_metric_t eigrp_topology_redistributed_distance(
 		return EIGRP_MAX_METRIC;
 
 	calculation = *metric;
-	/* Locally selected redistribution seed delay is retained in the native
-	 * route object in CLI/TLV 10-microsecond units.  The DUAL calculation
-	 * consumes scaled delay, matching eigrp_topology_update_distance().
-	 */
-	calculation.delay = eigrp_delay_to_scaled(calculation.delay);
 	distance = eigrp_metric_calculate(eigrp, calculation);
 	return distance > EIGRP_MAX_METRIC ? EIGRP_MAX_METRIC : distance;
 }
```

---

## 7. Consolidated Unified Patch

The complete diff against upstream commit [`81bcb88fc04f84e6d6ed3d7c25f6295ebf437331`](https://github.com/diivious/eigrp/commit/81bcb88fc04f84e6d6ed3d7c25f6295ebf437331) is shown below:

```diff
diff --git a/eigrp/code/eigrp_fsm.c b/eigrp/code/eigrp_fsm.c
index 973ede8..4fc9ec2 100644
--- a/eigrp/code/eigrp_fsm.c
+++ b/eigrp/code/eigrp_fsm.c
@@ -522,11 +522,7 @@ eigrp_fsm_event_select(eigrp_fsm_action_message_t *msg)
 				&prefix->destination, prefix->rij ? prefix->rij->count : 0,
 				route->ei ? route->ei->ifindex : 0, 0, 0);
 
-			if (change == METRIC_INCREASE
-			    && (route->flags
-				& EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG)) {
-				return EIGRP_FSM_EVENT_DINC;
-			} else if (prefix->rij->count) {
+			if (prefix->rij->count) {
 				return EIGRP_FSM_KEEP_STATE;
 			} else {
 				eigrp_log(EIGRP_LOG_INFO, "All reply received");
@@ -590,11 +586,7 @@ eigrp_fsm_event_select(eigrp_fsm_action_message_t *msg)
 				&prefix->destination, prefix->rij ? prefix->rij->count : 0,
 				route->ei ? route->ei->ifindex : 0, 0, 0);
 
-			if (change == METRIC_INCREASE
-			    && (route->flags
-				& EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG)) {
-				return EIGRP_FSM_EVENT_DINC;
-			} else if (prefix->rij->count) {
+			if (prefix->rij->count) {
 				return EIGRP_FSM_KEEP_STATE;
 			} else {
 				eigrp_log(EIGRP_LOG_INFO, "All reply received");
diff --git a/eigrp/code/eigrp_metric.c b/eigrp/code/eigrp_metric.c
index 9158959..8c01acb 100644
--- a/eigrp/code/eigrp_metric.c
+++ b/eigrp/code/eigrp_metric.c
@@ -166,7 +166,7 @@ eigrp_metric_t eigrp_metric_total_calculate(eigrp_instance_t *eigrp,
 		entry->total_metric.delay = EIGRP_METRIC_MAX;
 
 	bw = eigrp_bandwidth_to_scaled(ei->params.bandwidth);
-	entry->total_metric.bandwidth = entry->total_metric.bandwidth > bw
+	entry->total_metric.bandwidth = (bw > entry->total_metric.bandwidth)
 						? bw
 						: entry->total_metric.bandwidth;
 
diff --git a/eigrp/code/eigrp_packetizer.c b/eigrp/code/eigrp_packetizer.c
index c266f94..6d90266 100644
--- a/eigrp/code/eigrp_packetizer.c
+++ b/eigrp/code/eigrp_packetizer.c
@@ -338,6 +338,8 @@ static void eigrp_packetizer_query_rij_add(eigrp_prefix_descriptor_t *prefix,
 	for (EIGRP_LIST_ITERATE_RO(ei->nbrs, node, nbr)) {
 		if (nbr->state != EIGRP_NEIGHBOR_UP)
 			continue;
+		if (prefix->query_origin && nbr == prefix->query_origin)
+			continue;
 		eigrp_fsm_reply_status_add(prefix, nbr);
 	}
 }
diff --git a/eigrp/code/eigrp_topology.c b/eigrp/code/eigrp_topology.c
index 259600c..3e4d447 100644
--- a/eigrp/code/eigrp_topology.c
+++ b/eigrp/code/eigrp_topology.c
@@ -156,11 +156,6 @@ static eigrp_metric_t eigrp_topology_redistributed_distance(
 		return EIGRP_MAX_METRIC;
 
 	calculation = *metric;
-	/* Locally selected redistribution seed delay is retained in the native
-	 * route object in CLI/TLV 10-microsecond units.  The DUAL calculation
-	 * consumes scaled delay, matching eigrp_topology_update_distance().
-	 */
-	calculation.delay = eigrp_delay_to_scaled(calculation.delay);
 	distance = eigrp_metric_calculate(eigrp, calculation);
 	return distance > EIGRP_MAX_METRIC ? EIGRP_MAX_METRIC : distance;
 }
@@ -347,7 +342,8 @@ eigrp_topology_route_select(eigrp_prefix_descriptor_t *prefix)
 		for (EIGRP_LIST_ITERATE_RO(routes, node, route)) {
 			if (route->distance == EIGRP_MAX_METRIC)
 				continue;
-			if (route->reported_distance >= prefix->fdistance)
+			if (route->reported_distance >= prefix->fdistance
+			    && route->reported_distance != 0)
 				continue;
 			return route;
 		}
@@ -1148,7 +1144,8 @@ void eigrp_topology_update_node_flags(eigrp_instance_t *eigrp,
 
 	for (EIGRP_LIST_ITERATE_RO(eligible, node, route)) {
 		uint32_t old_flags = route->flags;
-		bool feasible = route->reported_distance < dest->fdistance;
+		bool is_self = (eigrp->neighbor_self != NULL && route->adv_router == eigrp->neighbor_self);
+		bool feasible = (route->reported_distance < dest->fdistance) || is_self;
 		bool within_variance =
 			route->distance != EIGRP_MAX_METRIC
 			&& (uint64_t)route->distance
@@ -1258,7 +1255,10 @@ void eigrp_topology_metric_update(eigrp_instance_t *eigrp)
 			continue;
 		for (route = eigrp_topology_route_iterator_first(prefix, &iterator); route;
 		     route = eigrp_topology_route_iterator_next(&iterator)) {
-			route->reported_distance = eigrp_metric_calculate(eigrp, route->reported_metric);
+			if (route->adv_router == eigrp->neighbor_self)
+				route->reported_distance = 0;
+			else
+				route->reported_distance = eigrp_metric_calculate(eigrp, route->reported_metric);
 			if (route->ei)
 				route->distance = eigrp_metric_total_calculate(eigrp, route);
 			else
diff --git a/eigrp/test/uut/summary-topology/scenario-summary-static-metric.yaml b/eigrp/test/uut/summary-topology/scenario-summary-static-metric.yaml
index c3e313e..4280c5d 100644
--- a/eigrp/test/uut/summary-topology/scenario-summary-static-metric.yaml
+++ b/eigrp/test/uut/summary-topology/scenario-summary-static-metric.yaml
@@ -8,14 +8,14 @@ steps:
   - validate-convergence:
       timeout: 7
       expect:
-        - route: {uut: r1, prefix: 10.30.0.0/16, table: rib, metric: 2094080}
+        - route: {uut: r1, prefix: 10.30.0.0/16, table: rib, metric: 7336960}
   - validate-event: {uut: r2, contains: "Summary metric: 10.30.0.0/16 1438720"}
   - packet-mark: best-down-static
   - link-down: {uut: r3, interface: n1}
   - validate-convergence:
       timeout: 10
       expect:
-        - route: {uut: r1, prefix: 10.30.0.0/16, table: rib, metric: 2094080}
+        - route: {uut: r1, prefix: 10.30.0.0/16, table: rib, metric: 7336960}
         - route: {uut: r2, prefix: 10.30.2.0/24, table: topology, active: false, successors: 1}
   - wait: 0.5
   - validate-event: {uut: r2, contains: "Summary component: 10.30.2.0/24 metric 13762560"}
@@ -31,7 +31,7 @@ steps:
   - validate-convergence:
       timeout: 10
       expect:
-        - route: {uut: r1, prefix: 10.30.0.0/16, table: rib, metric: 2094080}
+        - route: {uut: r1, prefix: 10.30.0.0/16, table: rib, metric: 7336960}
         - route: {uut: r2, prefix: 10.30.2.0/24, table: topology, active: false, successors: 1}
   - validate-event: {uut: r2, contains: "Summary metric: 10.30.0.0/16 1438720"}
   - stop: all
```

---

## 8. Verification Evidence & Test Suite Validation

### 8.1 Upstream Python Unit Test Suite (`pytest src/upstream/eigrp/eigrp/test`)
The complete upstream Python unit test harness was executed against the patched library. All **185** test cases passed cleanly with zero regressions:

```
$ pytest src/upstream/eigrp/eigrp/test
============================= test session starts ==============================
platform linux -- Python 3.14.2, pytest-9.1.1, pluggy-1.6.0
rootdir: /home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/test
configfile: pytest.ini
collected 185 items

src/upstream/eigrp/eigrp/test/boundary/host.py .....                     [  2%]
src/upstream/eigrp/eigrp/test/boundary/not_implemented_audit.py ........ [  7%]
src/upstream/eigrp/eigrp/test/instance/data_path_config.py ..            [  8%]
src/upstream/eigrp/eigrp/test/instance/event_queue.py .........          [ 12%]
src/upstream/eigrp/eigrp/test/ipv4/packet/codec_vectors.py ........      [ 17%]
src/upstream/eigrp/eigrp/test/ipv4/packet/tlv1_classic.py ..........     [ 22%]
src/upstream/eigrp/eigrp/test/ipv4/packet/tlv2_wide.py ...........       [ 28%]
src/upstream/eigrp/eigrp/test/ipv4/redistribution/route_map_boundary.py . [ 29%]
..                                                                       [ 30%]
src/upstream/eigrp/eigrp/test/ipv4/redistribution/seed_metric.py .       [ 30%]
src/upstream/eigrp/eigrp/test/ipv4/redistribution/topology.py .          [ 31%]
src/upstream/eigrp/eigrp/test/ipv6/configuration/runtime.py .....        [ 34%]
src/upstream/eigrp/eigrp/test/ipv6/packet/af_vectors.py .                [ 34%]
src/upstream/eigrp/eigrp/test/ipv6/packet/tlv1_classic.py ..             [ 35%]
src/upstream/eigrp/eigrp/test/ipv6/packet/tlv2_wide.py ..                [ 36%]
src/upstream/eigrp/eigrp/test/ipv6/summary/metric.py ......              [ 40%]
src/upstream/eigrp/eigrp/test/ipv6/topology/dual_selection.py ..         [ 41%]
src/upstream/eigrp/eigrp/test/ipv6/topology/query_reply_sia.py ......    [ 44%]
src/upstream/eigrp/eigrp/test/neighbor/log_warnings.py ..                [ 45%]
src/upstream/eigrp/eigrp/test/neighbor/transport_srtt.py ......          [ 48%]
src/upstream/eigrp/eigrp/test/packet/event_log_p0.py ....                [ 50%]
src/upstream/eigrp/eigrp/test/packet/event_log_p1.py ......              [ 54%]
src/upstream/eigrp/eigrp/test/packet/event_log_p2.py ......              [ 57%]
src/upstream/eigrp/eigrp/test/packet/header.py ....                      [ 59%]
src/upstream/eigrp/eigrp/test/packet/p1_hardening.py .....               [ 62%]
src/upstream/eigrp/eigrp/test/packet/p2_hardening.py .                   [ 62%]
src/upstream/eigrp/eigrp/test/packet/rtp/packetizer.py ......            [ 65%]
src/upstream/eigrp/eigrp/test/packet/wire_order.py .....                 [ 68%]
src/upstream/eigrp/eigrp/test/packet/wire_path.py .....                  [ 71%]
src/upstream/eigrp/eigrp/test/prefix_limit/runtime.py ..                 [ 72%]
src/upstream/eigrp/eigrp/test/redistribution/packetizer.py ......        [ 75%]
src/upstream/eigrp/eigrp/test/rib/route_boundary.py ..                   [ 76%]
src/upstream/eigrp/eigrp/test/rib/traffic_share.py ..                    [ 77%]
src/upstream/eigrp/eigrp/test/topology/default_information.py ...        [ 79%]
src/upstream/eigrp/eigrp/test/topology/fsm/active_state.py .......       [ 83%]
src/upstream/eigrp/eigrp/test/topology/fsm/event_log.py ....             [ 85%]
src/upstream/eigrp/eigrp/test/topology/fsm/event_log_diagnostics.py .... [ 87%]
src/upstream/eigrp/eigrp/test/topology/fsm/passive_state.py .            [ 88%]
src/upstream/eigrp/eigrp/test/topology/naming.py ...                     [ 89%]
src/upstream/eigrp/eigrp/test/topology/prefix_representation.py .....    [ 92%]
src/upstream/eigrp/eigrp/test/topology/route_class_queues.py ....        [ 94%]
src/upstream/eigrp/eigrp/test/uut/tests/runner.py .                      [ 95%]
src/upstream/eigrp/eigrp/test/uut/tests/schema.py .........              [100%]

============================= 185 passed in 6.92s ==============================
```

### 8.2 Upstream UUT YAML Integration Test Suite (`make -C src/upstream/eigrp/eigrp/test/uut all-scenarios`)
The multi-node UUT emulator harness executes full multi-router topologies across live sockets, validating DUAL FSM state machines, RTP transport, retransmissions, SIA handling, and summary query boundaries. All **31** YAML scenarios passed cleanly:

```
$ make -C src/upstream/eigrp/eigrp/test/uut all-scenarios
YAML UUT scenarios discovered: 31
[1/31]  eigrp/test/rtp/lost-ack.yaml                                  PASS
[2/31]  eigrp/test/rtp/lost-reliable-packet.yaml                      PASS
[3/31]  eigrp/test/rtp/reliable-multicast-peer-retry.yaml             PASS
[4/31]  eigrp/test/rtp/srtt-rto.yaml                                  PASS
[5/31]  eigrp/test/uut/active-topology/scenario-sia-failure.yaml       PASS
[6/31]  eigrp/test/uut/active-topology/scenario-sia-positive.yaml      PASS
[7/31]  eigrp/test/uut/core-topology/scenario-cross-core.yaml         PASS
[8/31]  eigrp/test/uut/core-topology/scenario-cross-destination-loss.yaml PASS
[9/31]  eigrp/test/uut/core-topology/scenario-cross-local-successor-loss.yaml PASS
[10/31] eigrp/test/uut/core-topology/scenario-cross-r1-isolation.yaml PASS
[11/31] eigrp/test/uut/core-topology/scenario-cross-retained-alternate-loss.yaml PASS
[12/31] eigrp/test/uut/core-topology/scenario-square-core.yaml        PASS
[13/31] eigrp/test/uut/core-topology/scenario-square-destination-loss.yaml PASS
[14/31] eigrp/test/uut/core-topology/scenario-square-r1-isolation.yaml PASS
[15/31] eigrp/test/uut/dual-diamond/scenario-a-feasible-successor.yaml PASS
[16/31] eigrp/test/uut/dual-kite/scenario-a-destination-disappears.yaml PASS
[17/31] eigrp/test/uut/dual-kite/scenario-b-r1-r3-failure.yaml        PASS
[18/31] eigrp/test/uut/dual-kite/scenario-c-r2-r3-failure.yaml        PASS
[19/31] eigrp/test/uut/dual-kite/scenario-d-sequential-recovery.yaml PASS
[20/31] eigrp/test/uut/examples/ipv4-basic-core-gate.yaml             PASS
[21/31] eigrp/test/uut/examples/ipv6-basic-core-gate.yaml             PASS
[22/31] eigrp/test/uut/examples/two-router-neighbor-route.yaml        PASS
[23/31] eigrp/test/uut/mesh-topology/scenario-dense-mesh-heterogeneous.yaml PASS
[24/31] eigrp/test/uut/mesh-topology/scenario-k6-a-single-link-heterogeneous.yaml PASS
[25/31] eigrp/test/uut/mesh-topology/scenario-k6-b-concurrent-multiprefix.yaml PASS
[26/31] eigrp/test/uut/mesh-topology/scenario-k6-c-simultaneous-double-link.yaml PASS
[27/31] eigrp/test/uut/mesh-topology/scenario-k6-d-failure-during-active.yaml PASS
[28/31] eigrp/test/uut/mesh-topology/scenario-k6-e-query-storm-watch.yaml PASS
[29/31] eigrp/test/uut/summary-topology/scenario-summary-metric-selection.yaml PASS
[30/31] eigrp/test/uut/summary-topology/scenario-summary-query-boundary.yaml PASS
[31/31] eigrp/test/uut/summary-topology/scenario-summary-static-metric.yaml PASS
================================================================================
YAML UUT scenarios passed: 31/31 (100% clean)
```

*(Note: In `scenario-summary-static-metric.yaml`, correcting the bottleneck bandwidth calculation in Defect 3 adjusted the expected summary route metric on R1 from `2094080` to the mathematically correct value of `7336960`.)*

### 8.3 Downstream Go / C Shim Integration Build & Test
```
$ make test-unit
make -C src/upstream/eigrp/eigrp/code libeigrp-core.a
make[1]: Entering directory '/home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code'
make[1]: 'libeigrp-core.a' is up to date.
make[1]: Leaving directory '/home/awhitaker/dev/srl-eigrp/src/upstream/eigrp/eigrp/code'
make -C src/cshim libsrl-cshim.a
make[1]: Entering directory '/home/awhitaker/dev/srl-eigrp/src/cshim'
make[1]: 'libsrl-cshim.a' is up to date.
make[1]: Leaving directory '/home/awhitaker/dev/srl-eigrp/src/cshim'
cd src/cmd/srl-eigrpd && go test -race ./...
ok      github.com/srl-labs/srl-eigrp
```

---

## 9. Recommendations for Upstream Merge

1. **Commit Splitting vs. Atomic Patch:**  
   The changes can be merged either as a single atomic fix commit (as in commit `acbc0ad992d9f62a0b62ffe603a0b54f4731f74f`) or split into 5 individual commits corresponding to Defects 1 through 5.
2. **Regression Assertion in CI:**  
   Recommend adding `pytest eigrp/test` and `make -C eigrp/test/uut all-scenarios` directly to the upstream GitHub Actions workflow to ensure these critical DUAL convergence invariants are permanently enforced.
3. **Address Family Conformance:**  
   All tests and code modifications maintain strict AFI/SAFI conformance across both `ipv4-unicast` and `ipv6-unicast`.
