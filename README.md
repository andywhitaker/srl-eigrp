# EIGRP for Nokia SR Linux (NDK Protocol Daemon)

[![Build & Tests](https://img.shields.io/badge/tests-38%20passed-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-Nokia%20SR%20Linux%2024.x%2B-blue.svg)]()
[![License](https://img.shields.io/badge/license-GPL--2.0-yellow.svg)]()

Native integration of Donnie V. Savage's EIGRP engine with **Nokia SR Linux** via the NetOps Development Kit (NDK).

This daemon (`srl-eigrpd`) runs as an in-process protocol agent inside SR Linux, programming the FIB, supporting DUAL (Diffusing Update Algorithm) convergence, exposing YANG-modeled configuration, providing native SR Linux CLI `show` & `tools` commands, and streaming real-time telemetry.

---

## ⚡ Quick Start: 3 Simple Steps

Loading EIGRP onto your Nokia SR Linux switch or container takes less than two minutes.

### Step 1: Install the Package
Copy the Debian package to your SR Linux device and install it:

```bash
# On your SR Linux bash shell:
sudo dpkg -i srl-eigrpd_0.1.0_linux_amd64.deb
```
> [!NOTE]
> The package installer automatically verifies your Control Plane Protection (CPM) filter, registers the YANG data models, and integrates with the SR Linux Application Manager (`app_mgr`).

---

### Step 2: Configure EIGRP
Open the SR Linux CLI (`sr_cli`) and configure your interface and EIGRP autonomous system:

```text
enter candidate

# 1. Ensure your IP interface is configured
set / interface ethernet-1/1 subinterface 0 ipv4 admin-state enable
set / interface ethernet-1/1 subinterface 0 ipv4 address 10.0.0.1/30

# 2. Add interface to network-instance default
set / network-instance default interface ethernet-1/1.0

# 3. Enable EIGRP Autonomous System 100
set / network-instance default protocols eigrp admin-state enable
set / network-instance default protocols eigrp autonomous-system 100
set / network-instance default protocols eigrp router-id 192.0.2.1

# 4. Set global default interface settings (optional)
set / network-instance default protocols eigrp default-interface admin-state enable
set / network-instance default protocols eigrp default-interface hello-interval 5
set / network-instance default protocols eigrp default-interface hold-time 15

# 5. Enable EIGRP on specific interfaces (inherits default-interface settings)
set / network-instance default protocols eigrp interface ethernet-1/1.0 admin-state enable
set / network-instance default protocols eigrp interface system0.0 admin-state enable
set / network-instance default protocols eigrp interface system0.0 passive true

commit now
```

---

### Step 3: Verify Operation
Check your neighbor adjacency and the DUAL topology table:

```text
--{ running }--[  ]--
A:srl1# show network-instance default protocols eigrp neighbor
================================================================================
EIGRP Neighbors for Network-Instance: default (AS: 100)
--------------------------------------------------------------------------------
Neighbor IP      Interface          State    Hold (s)   Uptime (s)   SRTT (ms)  RTO (ms)  
--------------------------------------------------------------------------------
10.0.0.2         ethernet-1/1.0     Up       14         120          3          200       
================================================================================

A:srl1# show network-instance default protocols eigrp topology
================================================================================
EIGRP DUAL Topology Table for Network-Instance: default (AS: 100)
--------------------------------------------------------------------------------
Codes: P - Passive, A - Active, U - Update, Q - Query, R - Reply
--------------------------------------------------------------------------------
P 10.0.0.0/30, 1 successors, FD is 7208960
    via 0.0.0.0 (7208960/0), ethernet-1/1.0 Successor
P 192.0.2.2/32, 1 successors, FD is 7864320
    via 10.0.0.2 (7864320/7208960), ethernet-1/1.0 Successor
================================================================================
```

---

## 🔍 Native SR Linux CLI Commands

The package includes native CLI plugins extending both `show` and `tools` operational modes.

### Show Commands (`show network-instance <name> protocols eigrp ...`)

| Command | Description |
| :--- | :--- |
| `show ... protocols eigrp status` | Overall daemon status, Autonomous System, Router ID, admin/oper state, neighbor/route summary counts |
| `show ... protocols eigrp neighbor [ip]` | Active neighbors table, or detailed view for a specific neighbor IP (timers, SRTT, RTO, learned routes) |
| `show ... protocols eigrp interfaces [name]` | Participating interfaces table, or detailed view for a specific interface (device name, IPs, traffic stats) |
| `show ... protocols eigrp routes` | Routes programmed in FIB, next-hops, composite metric, route type (Internal/External), and preference |
| `show ... protocols eigrp topology` | DUAL topology table showing passive/active prefixes, successor count, Feasible Distance (FD), and Reported Distance (RD) |
| `show ... protocols eigrp traffic` | Interface packet counters (reliable/unreliable multicast, unicast, retransmissions, CR packets) |

### Tools Commands (`tools network-instance <name> protocols eigrp ...`)

| Command | Description |
| :--- | :--- |
| `tools ... neighbor clear <peer-ip>` | Clears adjacency with a specific peer and renegotiates peering (peer IP strictly required) |
| `tools ... neighbor reset-all` | Resets all active EIGRP neighbor sessions across the entire network instance |
| `tools ... neighbor bfd-down <peer-ip>` | Triggers immediate neighbor teardown upon BFD session down notification |
| `tools ... graceful-restart planned-restart` | Initiates planned graceful restart (NSF) with hello graceful-shutdown signaling and FIB route retention |
| `tools ... restart` | Performs a fast protocol soft-restart / neighbor reset |
| `tools ... check-cpm` | Verifies whether the Control Plane Protection (CPM) filter accepts IP protocol 88 |

### State Database Inspection (`info from state`)

All live operational state is continuously streamed directly into the Nokia SR Linux State Datastore under `/network-instance <name>/protocols/eigrp`:
```text
A:srl1# info from state /network-instance default protocols eigrp
    oper-state up
    total-interfaces 2
    total-neighbors 1
    total-routes 1
    interface ethernet-1/1.0 {
        oper-state up
        ip-address 10.0.0.1
        prefix-length 30
    }
    neighbor 10.0.0.2 {
        interface ethernet-1/1.0
        state Up
        hold-time 14
        uptime 41s
        srtt-ms 9
        rto-ms 200
    }
    route 192.0.2.2/32 {
        next-hop 10.0.0.2
        metric 7864320
        external false
        preference 90
    }
```

---

## ⚙️ Advanced Configuration Options

All features are fully modeled in YANG under `/network-instance <name>/protocols/eigrp`:

### 1. Default-Interface & Per-Interface Configuration
Like SR Linux OSPF and IS-IS, interfaces are configured under `interface <name>` and inherit settings from `default-interface`:
```text
set / network-instance default protocols eigrp default-interface admin-state enable
set / network-instance default protocols eigrp default-interface hello-interval 5
set / network-instance default protocols eigrp default-interface hold-time 15
set / network-instance default protocols eigrp interface ethernet-1/1.0 admin-state enable
set / network-instance default protocols eigrp interface system0.0 passive true
```

### 2. Unequal-Cost Load Balancing (Variance)
Allows EIGRP to install feasible successor routes with metrics up to `variance × FD` into the FIB:
```text
set / network-instance default protocols eigrp variance 2
```

### 3. Equal-Cost Multipath (ECMP Maximum Paths)
Limits the maximum number of parallel paths installed in the FIB (1 to 64):
```text
set / network-instance default protocols eigrp maximum-paths 4
```

### 4. Named Metric Weights (K-Values)
Configure K-values using semantic parameter names:
```text
set / network-instance default protocols eigrp metrics bandwidth 1     # K1: Bandwidth
set / network-instance default protocols eigrp metrics load 0          # K2: Load
set / network-instance default protocols eigrp metrics delay 1         # K3: Delay
set / network-instance default protocols eigrp metrics reliability 0   # K4: Reliability
set / network-instance default protocols eigrp metrics mtu 0           # K5: MTU
```

### 5. Routing Policy Export & Import (`export-policy` / `import-policy`)
Attach standard Nokia SR Linux routing policies to filter or set custom EIGRP metrics on redistributed routes:
```text
# 1. Define routing policy with EIGRP metric action
set / routing-policy policy eigrp-export statement 10 match protocol local
set / routing-policy policy eigrp-export statement 10 action policy-result accept
set / routing-policy policy eigrp-export statement 10 action eigrp metric bandwidth 100000
set / routing-policy policy eigrp-export statement 10 action eigrp metric delay 100
set / routing-policy policy eigrp-export statement 10 action eigrp metric reliability 255
set / routing-policy policy eigrp-export statement 10 action eigrp metric load 1
set / routing-policy policy eigrp-export statement 10 action eigrp metric mtu 1500

# 2. Attach policy to EIGRP
set / network-instance default protocols eigrp export-policy eigrp-export
set / network-instance default protocols eigrp import-policy eigrp-export
```

### 6. Multi-VRF / Multi-Instance Support
Run concurrent, isolated EIGRP protocol instances across multiple network instances (e.g., `default` and secondary `ip-vrf` instances):
```text
# 1. Create secondary IP-VRF
set / network-instance vrf-1 type ip-vrf admin-state enable
set / network-instance vrf-1 interface ethernet-1/1.1
set / network-instance vrf-1 interface lo0.1

# 2. Configure independent EIGRP instance inside vrf-1
set / network-instance vrf-1 protocols eigrp admin-state enable
set / network-instance vrf-1 protocols eigrp autonomous-system 200
set / network-instance vrf-1 protocols eigrp router-id 192.0.2.11
set / network-instance vrf-1 protocols eigrp interface ethernet-1/1.1 admin-state enable
set / network-instance vrf-1 protocols eigrp interface lo0.1 admin-state enable passive true
```
All routes, FIB injection via NDK, and telemetry streaming are completely isolated per network instance and viewable via `show network-instance <name> protocols eigrp ...`.

### 7. Interface Fine-Tuning (Split-Horizon, Next-Hop-Self, Bandwidth, Delay)
Interfaces inherit from `default-interface` or can be overridden individually:
```text
set / network-instance default protocols eigrp interface ethernet-1/1.0 split-horizon true
set / network-instance default protocols eigrp interface ethernet-1/1.0 next-hop-self false
set / network-instance default protocols eigrp interface ethernet-1/1.0 bandwidth 1000000
set / network-instance default protocols eigrp interface ethernet-1/1.0 delay 100
```

### 8. Protocol Timers & Hop Count Limits
Configure DUAL Stuck-in-Active (SIA) timer and hop count limits:
```text
set / network-instance default protocols eigrp timers active-time 3
set / network-instance default protocols eigrp maximum-hops 100
```

### 9. Route Summarization
Configure manual summary prefixes with custom administrative distance directly on interfaces:
```text
set / network-instance default protocols eigrp interface ethernet-1/1.0 summary-address 10.0.0.0/16 distance 5
```

### 10. Static Neighbors
Statically define point-to-point unicast neighbors for non-broadcast multi-access (NBMA) networks:
```text
set / network-instance default protocols eigrp static-neighbor 10.0.0.2 interface ethernet-1/1.0
```

### 11. Wide Metrics & RIB Scale (RFC 7868)
EIGRP for SR Linux implements RFC 7868 64-bit wide metric calculations, supporting high-speed interfaces (100G/400G/800G) and picosecond latency resolution:
- **64-Bit Wide Metric Calculation**: Uses wide composite metric formula across K1–K6 weights (bandwidth, delay, load, reliability, MTU, extended attributes).
- **RIB Scaling Factor (`rib-scale`)**: The SR Linux FIB and Linux kernel accept 32-bit route metrics. The `rib-scale` leaf (default `128`, range `1..255`) scales 64-bit EIGRP wide metrics down to 32-bit FIB metrics via integer division:
  $$\text{FIB metric} = \lfloor \frac{\text{wide-metric}}{\text{rib-scale}} \rfloor$$

```text
# Configure rib-scale (default 128)
set / network-instance default protocols eigrp rib-scale 64
set / network-instance default protocols eigrp wide-metrics true
```
Verify the wide metric and scaled FIB metric via CLI:
```text
A:srl1# info from state network-instance default protocols eigrp
    rib-scale 64
    route 192.0.2.2/32 {
        wide-metric 7864320
        metric 122880
    }

A:srl1# show network-instance default ipv4 route 192.0.2.2/32
    metric: 122880
```

### 12. Packet Authentication (MD5 & HMAC-SHA-256)
Secure EIGRP peering and route exchanges with cryptographic digest authentication:
- **Supported Algorithms**: `md5` (RFC 1321) and `hmac-sha-256` (RFC 4868).
- **Keychain Integration**: References standard SR Linux system keychains (`/system/authentication/keychain`).
- **Encrypted Password Handling**: Automatically detects and decrypts Nokia SR Linux encrypted passwords (`$aes1$...`) or accepts plaintext passwords.
- **Replay Protection**: Enforces monotonic packet sequence numbers to prevent packet injection and replay attacks.

```text
# 1. Define an MD5 or HMAC-SHA-256 keychain in SR Linux
set / system authentication keychain eigrp-md5-key admin-state enable type ospf key 1 algorithm md5 authentication-key authsecret123
set / system authentication keychain eigrp-sha-key admin-state enable type isis key 1 algorithm hmac-sha-256 authentication-key shasecret456

# 2. Attach keychain to an interface (or default-interface)
set / network-instance default protocols eigrp interface ethernet-1/1.0 authentication mode md5 keychain eigrp-md5-key

# Or enable HMAC-SHA-256 authentication:
set / network-instance default protocols eigrp interface ethernet-1/1.0 authentication mode hmac-sha-256 keychain eigrp-sha-key
```

### 13. Graceful Restart / Non-Stop Forwarding (NSF)
Graceful Restart enables hitless control plane restarts while preserving dataplane FIB forwarding:
- **Restarter & Helper Modes**: Supports both restarting node operation and neighbor helper mode (`helper-mode true`) to retain routes learned from restarting peers.
- **RFC-Compliant Signaling**: Distinguishes Hello graceful shutdown signaling (`EIGRP_HELLO_GRACEFUL_SHUTDOWN` with K=255) from Restart signaling (`EIGRP_RS_FLAG`).
- **Continuous Dataplane Forwarding**: During a planned restart, FIB routes programmed via NDK remain active, preventing traffic drops during protocol reload and topology resynchronization.

```text
# Enable and configure Graceful Restart
set / network-instance default protocols eigrp graceful-restart admin-state enable
set / network-instance default protocols eigrp graceful-restart restart-time 120
set / network-instance default protocols eigrp graceful-restart helper-mode true
```
Initiate an operational planned graceful restart:
```text
A:srl1# tools network-instance default protocols eigrp graceful-restart planned-restart
```

### 14. Bidirectional Forwarding Detection (BFD)
Integrates EIGRP with the Nokia SR Linux micro-BFD engine for sub-second failure detection:
- **Hardware-Accelerated Detection**: Offloads hello monitoring to the SR Linux BFD subsystem, detecting physical link and forwarding failures in milliseconds.
- **NDK BFD Service Integration**: Listens for asynchronous `BfdSessionNotification` events from the NDK manager.
- **Fast Adjacency Teardown**: Upon BFD session down transition, immediately clears the neighbor adjacency and triggers DUAL recalculation without waiting for hold timer expiration.

```text
# Enable BFD globally for all EIGRP interfaces via default-interface
set / network-instance default protocols eigrp default-interface bfd admin-state enable
set / network-instance default protocols eigrp default-interface bfd desired-minimum-tx-interval 100000
set / network-instance default protocols eigrp default-interface bfd required-minimum-receive 100000
set / network-instance default protocols eigrp default-interface bfd detection-multiplier 3

# Or enable/override per individual interface
set / network-instance default protocols eigrp interface ethernet-1/1.0 bfd admin-state enable
```
Simulate or trigger neighbor teardown via BFD down event:
```text
A:srl1# tools network-instance default protocols eigrp neighbor bfd-down 10.0.0.2
```

### 15. IPv6 EIGRP Support
Enable dual-stack or pure IPv6 EIGRP peering using link-local multicast (`ff02::a`) and NDK `ipv6-unicast` route injection:
```text
# 1. Enable IPv6 addressing on interface
set / interface ethernet-1/1 subinterface 0 ipv6 admin-state enable
set / interface ethernet-1/1 subinterface 0 ipv6 address 2001:db8:1::1/64

# 2. Enable IPv6 EIGRP
set / network-instance default protocols eigrp ipv6-unicast admin-state enable
set / network-instance default protocols eigrp ipv6-unicast autonomous-system 100
set / network-instance default protocols eigrp ipv6-unicast router-id 192.0.2.1
set / network-instance default protocols eigrp ipv6-unicast interface ethernet-1/1.0 admin-state enable
```
Verify IPv6 neighbors and routes:
```text
show network-instance default protocols eigrp neighbor
show network-instance default ipv6 route
```

---

## 🛡️ Control Plane Protection (CPM Filter)

Nokia SR Linux uses hardware and kernel Control Plane Protection (CPM) filters to protect the management plane and CPU from denial-of-service traffic. By default, incoming packets with unregistered IP protocols are dropped.

EIGRP uses **IP Protocol 88**.

### Automated Provisioning
The `srl-eigrpd` Debian package automatically injects the required rule during installation:
```text
acl acl-filter cpm type ipv4 entry 88 action accept match protocol 88
```

### Manual Verification
If your CPM filter has a custom name or you wish to verify the filter rule manually, run:
```text
A:srl1# tools network-instance default protocols eigrp check-cpm
================================================================================
Verifying Control Plane Protection (CPM Filter) for EIGRP (IP Protocol 88)...
--------------------------------------------------------------------------------
[OK] Entry 88: action accept, match protocol 88.
[OK] Inbound IP protocol 88 packets are accepted by CPM filter 'cpm'.
================================================================================
```

---

## 🏗️ Architecture & Design

```text
+-----------------------------------------------------------------------+
| Nokia SR Linux                                                        |
|                                                                       |
|   +--------------------------+       +----------------------------+   |
|   |   SR Linux Mgmt Server   |       |    SR Linux NDK Manager    |   |
|   +------------+-------------+       +--------------+-------------+   |
|                |                                    |                 |
|                | Config (JSON via gRPC)             | FIB Route Add / |
|                |                                    | Telemetry Push  |
|                v                                    v                 |
|   +---------------------------------------------------------------+   |
|   | srl-eigrpd (Go NDK Daemon)                                    |   |
|   |   - AgentRegister & NotificationStream                        |   |
|   |   - RouteAddOrUpdate & NextHopGroupAddOrUpdate (_sdk)         |   |
|   |   - TelemetryAddOrUpdate (/var/run/srl_eigrp_state.json)      |   |
|   |   - Local Unix Socket IPC Server (/var/run/srl_eigrpd_ipc.sock)|  |
|   +-------------------------------+-------------------------------+   |
|                                   | cgo                               |
|                                   v                                   |
|   +---------------------------------------------------------------+   |
|   | srl-cshim (C Host Shim)                                       |   |
|   |   - Network Namespace Isolation (/var/run/netns/srbase-*)     |   |
|   |   - POSIX poll(2) Event Loop, Monotonic Clocks & Timers       |   |
|   |   - Raw Sockets (IP proto 88), Multicast (224.0.0.10)         |   |
|   |   - RFC 7868 IP/EIGRP Checksum Offload Handling               |   |
|   |   - Topology & Interface Traffic Iterators                    |   |
|   +-------------------------------+-------------------------------+   |
|                                   | Public API Contract               |
|                                   v                                   |
|   +---------------------------------------------------------------+   |
|   | EIGRP Core Engine (libeigrp-core.a)                           |   |
|   |   - Diffusing Update Algorithm (DUAL Finite State Machine)    |   |
|   |   - Reliable Transport Protocol (RTP) Sequence & Ack Tracking |   |
|   |   - TLV Packet Encoding & Parsing                             |   |
|   +---------------------------------------------------------------+   |
+-----------------------------------------------------------------------+
```

### Key Architectural Highlights
1. **Zero Core Modifications:** Upstream EIGRP engine (`src/upstream/eigrp/`) remains 100% clean and unmodified, allowing seamless synchronization with upstream improvements.
2. **Network Namespace Isolation:** Raw sockets are created inside the specific Linux network namespace (`/var/run/netns/srbase-<netinst>`), ensuring multi-VRF isolation and avoiding host namespace leakage.
3. **Hardware Checksum Offload Resiliency:** Computes RFC 7868 one's complement checksums explicitly for outbound frames to prevent packet drops across virtual veth interfaces and offload-enabled hardware ASICs.
4. **Decoupled Unix Socket IPC:** Dedicated non-blocking local IPC listener for `tools` operational commands ensures instant responsiveness without stalling the gRPC config pipeline.

---

## 🧪 Automated Testing & Validation

The project includes dual automated test suites executed with `pytest` and `containerlab`:

### SRL-to-SRL Peering Test Suite
Deploys two interconnected SR Linux nodes (`srl1` <-> `srl2`) running EIGRP:
```bash
make deploy-srl
make test-srl
```
**38 Automated Tests Executed (100% Pass Rate):**
- **IPv4 Default Instance**: Neighbor discovery, FIB route injection (preference 90), data plane ping, CLI show status/neighbor/routes/interfaces/topology/traffic, State DB verification, CPM filter validation, tools neighbor clear & reset-all.
- **Config & Policy Enhancements**: Default-interface configuration, passive interface inheritance, named metrics keys, routing-policy metric augmentation, dynamic interface deletion and re-addition.
- **Dual Admin/Oper State & Summarization**: Dual administrative and operational state modeling across all administrative controls, and dynamic summary-address tracking in State DB.
- **Multi-VRF (`ip-vrf`)**: Secondary VRF (`vrf-1`) neighbor peering, isolated FIB injection, dataplane ping, CLI show reports, State DB streaming, and operational tools.
- **IPv6 EIGRP**: IPv6 enable/disable lifecycle, link-local multicast neighbor peering (`ff02::a`), IPv6 FIB route installation, IPv6 data plane ping, CLI show commands, State DB telemetry, IPv6 tools clear, and IPv6 passive interface toggling.
- **RFC 7868 Wide Metrics**: 64-bit wide metric computation, dynamic `rib-scale` factor re-weighting (scaling 64-bit metrics down into 32-bit FIB metrics), and State DB telemetry.
- **Packet Authentication**: MD5 and HMAC-SHA-256 cryptographic digests, Nokia SR Linux system keychain integration, invalid/mismatched key rejection, and live authentication removal.
- **Graceful Restart (NSF)**: Planned graceful restart signaling, continuous FIB forwarding route retention across restarts, and peer resynchronization.
- **BFD Integration**: Sub-second neighbor teardown upon BFD session down transitions.

### Multi-Vendor Interoperability Test Suite (SRL to FRRouting)
Deploys an SR Linux node peering with an industry-standard FRRouting (`eigrpd`) router:
```bash
make deploy-frr
make test-frr
```

---

## 📦 Building from Source

To build the static core library, host shim, Go binary, and Debian package from scratch:

### Prerequisites
- Docker (for `goreleaser/nfpm`)
- Go 1.22+
- GCC / Make
- Containerlab & pytest (for running the validation test suites)

### Build Commands
```bash
# Build all components and generate the .deb package in dist/
make all

# Clean build artifacts
make clean
```
The output `.deb` package will be created in `dist/srl-eigrpd_0.1.0_linux_amd64.deb`.
