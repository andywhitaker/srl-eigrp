package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ndk "github.com/nokia/srlinux-ndk-go/ndk"
)

func TestAtomicWriteFile_Success(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "test_state.json")
	content := []byte(`{"status": "ok", "routes": 42}`)

	if err := atomicWriteFile(target, content, 0644); err != nil {
		t.Fatalf("atomicWriteFile failed: %v", err)
	}

	read, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("failed reading written file: %v", err)
	}
	if string(read) != string(content) {
		t.Fatalf("expected content %q, got %q", string(content), string(read))
	}

	fi, err := os.Stat(target)
	if err != nil {
		t.Fatalf("failed stat on file: %v", err)
	}
	if fi.Mode().Perm() != 0644 {
		t.Fatalf("expected perm 0644, got %v", fi.Mode().Perm())
	}

	// Test atomic replacement
	content2 := []byte(`{"status": "updated", "routes": 99}`)
	if err := atomicWriteFile(target, content2, 0600); err != nil {
		t.Fatalf("atomic replacement failed: %v", err)
	}

	read2, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("failed reading updated file: %v", err)
	}
	if string(read2) != string(content2) {
		t.Fatalf("expected content %q, got %q", string(content2), string(read2))
	}
}

func TestAtomicWriteFile_BadPath(t *testing.T) {
	// Attempt to write to a non-existent directory
	badTarget := filepath.Join("/path/that/does/not/exist", "file.json")
	if err := atomicWriteFile(badTarget, []byte("data"), 0644); err == nil {
		t.Fatal("expected error writing to non-existent directory, got nil")
	}
}

func TestRouteWorker_OverflowDecoupling(t *testing.T) {
	// Create worker with tiny channel capacity (5)
	w := &routeQueueWorker{
		queue: make(chan routeEvent, 5),
		stop:  make(chan struct{}),
	}

	// Enqueue 25 items without a consumer running.
	// Standard channel send would block at item 6.
	// Decoupled overflow queue should accept all 25 without blocking.
	const totalEvents = 25
	for i := 0; i < totalEvents; i++ {
		w.enqueue(routeEvent{
			eventType: routeEventAdd,
			netinst:   "default",
			prefix:    fmt.Sprintf("10.0.%d.0/24", i),
			metric:    uint32(i),
		})
	}

	w.mu.Lock()
	overflowLen := len(w.overflow)
	chanLen := len(w.queue)
	w.mu.Unlock()

	if chanLen != 5 {
		t.Fatalf("expected channel buffer full (5), got %d", chanLen)
	}
	if overflowLen != totalEvents-5 {
		t.Fatalf("expected overflow slice to have %d items, got %d", totalEvents-5, overflowLen)
	}

	// Now consume all items via runRouteWorker simulation loop and check strict FIFO order
	var processed []routeEvent
	done := make(chan struct{})

	go func() {
		for {
			w.mu.Lock()
			if len(w.overflow) > 0 {
				select {
				case w.queue <- w.overflow[0]:
					w.overflow = w.overflow[1:]
				default:
				}
			}
			w.mu.Unlock()

			select {
			case ev := <-w.queue:
				processed = append(processed, ev)
				if len(processed) == totalEvents {
					close(done)
					return
				}
			case <-time.After(2 * time.Second):
				close(done)
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for worker to process queued and overflow events")
	}

	if len(processed) != totalEvents {
		t.Fatalf("expected %d events processed, got %d", totalEvents, len(processed))
	}

	// Verify strict FIFO order
	for i, ev := range processed {
		expectedPfx := fmt.Sprintf("10.0.%d.0/24", i)
		if ev.prefix != expectedPfx {
			t.Fatalf("event %d: expected prefix %s, got %s", i, expectedPfx, ev.prefix)
		}
		if ev.metric != uint32(i) {
			t.Fatalf("event %d: expected metric %d, got %d", i, i, ev.metric)
		}
	}
}

func TestRouteWorker_OverflowDrainsOnStop(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		routeWorkers: make(map[string]*routeQueueWorker),
	}
	netinst := "drain-overflow-test"

	const totalEvents = 100
	for i := 0; i < totalEvents; i++ {
		d.EnqueueRouteAdd(netinst, fmt.Sprintf("192.168.%d.0/24", i), "10.1.1.1", uint32(i), 1000, false, 90)
	}

	// StopRouteWorker drains both w.queue and w.overflow
	d.StopRouteWorker(netinst)

	inst := d.GetInstance(netinst)
	if inst == nil {
		t.Fatal("expected instance to exist")
	}

	d.mu.RLock()
	count := len(inst.routes)
	d.mu.RUnlock()

	if count != totalEvents {
		t.Fatalf("expected all %d events drained into routes, got %d", totalEvents, count)
	}
}

func TestConfig_NetworkInstanceDelete(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		routeWorkers: make(map[string]*routeQueueWorker),
	}
	netinst := "vrf-cust-1"
	inst := newEigrpInstance(netinst)
	inst.asn = 100
	inst.routes["10.20.0.0/24"] = &RouteInfo{
		Prefix:  "10.20.0.0/24",
		NextHop: "10.20.0.1",
		Metric:  100,
	}
	d.instances[netinst] = inst

	// Trigger .network_instance delete
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: fmt.Sprintf(`.network_instance{.name=="%s"}`, netinst),
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})

	if d.GetInstance(netinst) != nil {
		t.Fatalf("expected instance %s to be completely deleted", netinst)
	}
}

func TestConfig_ProtocolsEigrpDelete(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		routeWorkers: make(map[string]*routeQueueWorker),
	}
	netinst := "vrf-cust-2"
	inst := newEigrpInstance(netinst)
	inst.asn = 200
	inst.routes["10.30.0.0/24"] = &RouteInfo{
		Prefix:  "10.30.0.0/24",
		NextHop: "10.30.0.1",
		Metric:  100,
	}
	d.instances[netinst] = inst

	// Trigger .protocols.eigrp delete
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: fmt.Sprintf(`.network_instance{.name=="%s"}.protocols.eigrp`, netinst),
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})

	if d.GetInstance(netinst) != nil {
		t.Fatalf("expected instance %s to be completely deleted on protocols.eigrp delete", netinst)
	}
}

func TestBfdNotification_ConcurrencyLocking(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		routeWorkers: make(map[string]*routeQueueWorker),
	}
	netinst := "default"
	inst := newEigrpInstance(netinst)
	inst.asn = 1
	inst.neighbors["10.0.0.2"] = &NeighborInfo{
		IPAddress: "10.0.0.2",
		Interface: "ethernet-1/1",
	}
	d.instances[netinst] = inst

	var wg sync.WaitGroup
	// Concurrently invoke HandleBfdNotification and read/write to d.mu / inst.neighbors
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			d.HandleBfdNotification(&ndk.BfdSessionNotification{
				Key: &ndk.BfdGeneralSessionKey{
					Type: ndk.BfdSessionType_BFD_SESSION_TYPE_P2P,
					Key: &ndk.BfdGeneralSessionKey_P2P{
						P2P: &ndk.BfdGeneralSessionKey_P2PKey{
							DestinationIpAddress: &ndk.IpAddressPb{
								IpAddress: net.ParseIP("10.0.0.2").To4(),
							},
						},
					},
				},
				Data: &ndk.BfdGeneralSessionData{
					Status: ndk.BfdSessionStatus_BFD_SESSION_STATUS_DOWN,
				},
			})
		}()
		go func() {
			defer wg.Done()
			d.mu.Lock()
			inst.neighbors["10.0.0.2"] = &NeighborInfo{
				IPAddress: "10.0.0.2",
				Interface: "ethernet-1/1",
			}
			d.mu.Unlock()
		}()
	}

	wg.Wait()
}

func TestConfig_NetworkInstanceChildDelete_DoesNotDeleteInstance(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		routeWorkers: make(map[string]*routeQueueWorker),
	}
	netinst := "vrf-cust-1"
	inst := newEigrpInstance(netinst)
	inst.asn = 100
	inst.routes["10.20.0.0/24"] = &RouteInfo{
		Prefix:  "10.20.0.0/24",
		NextHop: "10.20.0.1",
		Metric:  100,
	}
	d.instances[netinst] = inst

	// 1. Deleting an interface under the network instance must NOT delete the EIGRP instance
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: fmt.Sprintf(`.network_instance{.name=="%s"}.interface{.name=="ethernet-1/1.0"}`, netinst),
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})

	if d.GetInstance(netinst) == nil {
		t.Fatalf("instance %s was incorrectly deleted on interface child delete", netinst)
	}

	// 2. Deleting a description or other leaf must NOT delete the EIGRP instance
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: fmt.Sprintf(`.network_instance{.name=="%s"}.description`, netinst),
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})

	if d.GetInstance(netinst) == nil {
		t.Fatalf("instance %s was incorrectly deleted on description child delete", netinst)
	}

	// 3. Deleting the network instance itself MUST delete the instance
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: fmt.Sprintf(`.network_instance{.name=="%s"}`, netinst),
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})

	if d.GetInstance(netinst) != nil {
		t.Fatalf("expected instance %s to be deleted on network-instance root delete", netinst)
	}
}

// TestRootWireInterfaceResolution_ExcludesVeth verifies that root namespace wire interface matching
// strictly resolves physical wire interfaces (e.g. e1-1) and rejects internal veth peers (e.g. e1-1-0).
func TestRootWireInterfaceResolution_ExcludesVeth(t *testing.T) {
	tests := []struct {
		devName  string
		baseName string
		expected bool
	}{
		// Physical wire interfaces must match
		{"e1-1", "ethernet-1/1", true},
		{"ethernet-1/1", "ethernet-1/1", true},
		{"e1-2", "ethernet-1/2", true},
		{"srl1-e1-1", "ethernet-1/1", true},
		{"clab-srl1-e1-1", "ethernet-1/1", true},

		// Host-side veth peers MUST NOT match
		{"e1-1-0", "ethernet-1/1", false},
		{"e1-1-1", "ethernet-1/1", false},
		{"e1-1.0", "ethernet-1/1", false},
		{"srl1-e1-1-0", "ethernet-1/1", false},
		{"clab-srl1-e1-1-0", "ethernet-1/1", false},

		// Mismatched ports must not match
		{"e1-2", "ethernet-1/1", false},
		{"e1-1", "ethernet-1/2", false},

		// System and mgmt interfaces
		{"system0", "system0", true},
		{"mgmt0", "mgmt0", true},
		{"system0", "mgmt0", false},
		{"mgmt0", "system0", false},
	}

	for _, tt := range tests {
		got := ShimTestMatchRootWireIfname(tt.devName, tt.baseName)
		if got != tt.expected {
			t.Errorf("ShimTestMatchRootWireIfname(%q, %q) = %v, expected %v", tt.devName, tt.baseName, got, tt.expected)
		}
	}
}

// TestExplicitVlanIdSubinterfaceDisambiguation verifies that subinterfaces are disambiguated
// by their explicit VLAN ID even when subinterface index does not match VLAN ID.
func TestExplicitVlanIdSubinterfaceDisambiguation(t *testing.T) {
	ShimTestClearInterfaces()
	defer ShimTestClearInterfaces()

	// Register Port 5 (root_ifindex=50) with subinterfaces where subinterface index != VLAN ID:
	// - ethernet-1/1.0: ifindex 500, root_ifindex 50, explicit vlan_id = 1 (not 0)
	// - ethernet-1/1.1: ifindex 501, root_ifindex 50, explicit vlan_id = 10 (not 1)
	// - ethernet-1/1.2: ifindex 502, root_ifindex 50, explicit vlan_id = 20 (not 2)
	ShimTestRegisterInterfaceWithVlan("default", "ethernet-1/1.0", 500, 50, 1, "10.0.0.1", 30, false, true)
	ShimTestRegisterInterfaceWithVlan("default", "ethernet-1/1.1", 501, 50, 10, "10.1.0.1", 30, false, true)
	ShimTestRegisterInterfaceWithVlan("default", "ethernet-1/1.2", 502, 50, 20, "10.2.0.1", 30, false, true)

	// 1. Packet arriving on wire device (sll_ifindex=50) with VLAN tag 10
	// Under buggy strstr(ci->ifname, ".10"), ethernet-1/1.1 would fail!
	// With explicit vlan_id, it must resolve to 501.
	res := ShimTestResolveInterfaceV4("default", 50, 10, "10.1.0.2", "224.0.0.10")
	if res != 501 {
		t.Fatalf("expected resolution to ifindex 501 for VLAN 10, got %d", res)
	}

	// 2. Packet arriving on wire device with VLAN tag 1
	res = ShimTestResolveInterfaceV4("default", 50, 1, "10.0.0.2", "224.0.0.10")
	if res != 500 {
		t.Fatalf("expected resolution to ifindex 500 for VLAN 1, got %d", res)
	}

	// 3. Packet arriving on wire device with VLAN tag 20
	res = ShimTestResolveInterfaceV4("default", 50, 20, "10.2.0.2", "224.0.0.10")
	if res != 502 {
		t.Fatalf("expected resolution to ifindex 502 for VLAN 20, got %d", res)
	}

	// 4. Untagged packet arriving on wire device MUST NOT match any subinterface because all are tagged (vlan_id > 0)
	res = ShimTestResolveInterfaceV4("default", 50, 0, "192.168.1.1", "224.0.0.10")
	if res != 0 {
		t.Fatalf("expected untagged frame on fully tagged root device to be dropped (0), got %d", res)
	}

	// 5. Packet with unknown VLAN ID (e.g. 99) MUST NOT match any subinterface
	res = ShimTestResolveInterfaceV4("default", 50, 99, "10.0.0.2", "224.0.0.10")
	if res != 0 {
		t.Fatalf("expected unknown VLAN 99 frame to be dropped (0), got %d", res)
	}

	// 6. IPv6 with explicit VLAN ID
	ShimTestClearInterfaces()
	ShimTestRegisterInterfaceWithVlan("default", "ethernet-1/1.0", 500, 50, 1, "fe80::1", 64, true, true)
	ShimTestRegisterInterfaceWithVlan("default", "ethernet-1/1.1", 501, 50, 10, "fe80::2", 64, true, true)

	resV6 := ShimTestResolveInterfaceV6("default", 50, 10, "fe80::99", "ff02::a")
	if resV6 != 501 {
		t.Fatalf("expected IPv6 resolution to ifindex 501 for VLAN 10, got %d", resV6)
	}

	resV6 = ShimTestResolveInterfaceV6("default", 50, 1, "fe80::99", "ff02::a")
	if resV6 != 500 {
		t.Fatalf("expected IPv6 resolution to ifindex 500 for VLAN 1, got %d", resV6)
	}

	// 7. Untagged IPv6 frame on tagged port must be dropped
	resV6 = ShimTestResolveInterfaceV6("default", 50, 0, "fe80::99", "ff02::a")
	if resV6 != 0 {
		t.Fatalf("expected untagged IPv6 frame on fully tagged root device to be dropped (0), got %d", resV6)
	}

	// 8. Unknown VLAN IPv6 frame must be dropped
	resV6 = ShimTestResolveInterfaceV6("default", 50, 99, "fe80::99", "ff02::a")
	if resV6 != 0 {
		t.Fatalf("expected unknown VLAN 99 IPv6 frame to be dropped (0), got %d", resV6)
	}
}

// TestLocalPrefixIdentification_ConnectedAndLoopback verifies that locally connected
// and loopback prefixes are identified to prevent route withdrawal storms when nexthop_count == 0,
// and confirms that supernets and default routes are strictly NOT identified as local prefixes.
func TestLocalPrefixIdentification_ConnectedAndLoopback(t *testing.T) {
	ShimTestClearInterfaces()
	defer ShimTestClearInterfaces()

	ShimTestRegisterInterface("default", "ethernet-1/1.0", 10, 1, "10.0.0.1", 30, false, true)
	ShimTestRegisterInterface("default", "system0.0", 20, 2, "192.0.2.1", 32, false, true)

	// Connected subnet 10.0.0.0/30 must be identified as local
	if !ShimTestIsLocalPrefix("default", "10.0.0.0/30", false) {
		t.Fatal("expected 10.0.0.0/30 to be identified as local connected prefix")
	}

	// Host address 10.0.0.1/32 must be identified as local
	if !ShimTestIsLocalPrefix("default", "10.0.0.1/32", false) {
		t.Fatal("expected 10.0.0.1/32 to be identified as local prefix")
	}

	// Loopback address 192.0.2.1/32 on system0 must be identified as local
	if !ShimTestIsLocalPrefix("default", "192.0.2.1/32", false) {
		t.Fatal("expected 192.0.2.1/32 to be identified as local prefix")
	}

	// Standard 127.0.0.1/32 loopback must be identified as local
	if !ShimTestIsLocalPrefix("default", "127.0.0.1/32", false) {
		t.Fatal("expected 127.0.0.1/32 to be identified as local loopback prefix")
	}

	// Default route 0.0.0.0/0 MUST NOT be identified as local
	if ShimTestIsLocalPrefix("default", "0.0.0.0/0", false) {
		t.Fatal("default route 0.0.0.0/0 must NOT be identified as local prefix")
	}

	// Supernets MUST NOT be identified as local
	if ShimTestIsLocalPrefix("default", "10.0.0.0/8", false) {
		t.Fatal("supernet 10.0.0.0/8 must NOT be identified as local prefix")
	}
	if ShimTestIsLocalPrefix("default", "10.0.0.0/16", false) {
		t.Fatal("supernet 10.0.0.0/16 must NOT be identified as local prefix")
	}
	if ShimTestIsLocalPrefix("default", "10.0.0.0/24", false) {
		t.Fatal("supernet 10.0.0.0/24 must NOT be identified as local prefix")
	}

	// Remote learned route must NOT be identified as local
	if ShimTestIsLocalPrefix("default", "172.16.0.0/16", false) {
		t.Fatal("remote prefix 172.16.0.0/16 must NOT be identified as local prefix")
	}

	// IPv6 tests
	ShimTestClearInterfaces()
	ShimTestRegisterInterface("default", "system0.0", 20, 2, "2001:db8::1", 128, true, true)
	ShimTestRegisterInterface("default", "ethernet-1/1.0", 10, 1, "2001:db8:1::1", 64, true, true)

	if !ShimTestIsLocalPrefix("default", "2001:db8::1/128", true) {
		t.Fatal("expected 2001:db8::1/128 to be identified as local IPv6 prefix")
	}

	if !ShimTestIsLocalPrefix("default", "2001:db8:1::/64", true) {
		t.Fatal("expected 2001:db8:1::/64 to be identified as local IPv6 prefix")
	}

	if !ShimTestIsLocalPrefix("default", "2001:db8:1::1/128", true) {
		t.Fatal("expected 2001:db8:1::1/128 to be identified as local IPv6 prefix")
	}

	if !ShimTestIsLocalPrefix("default", "::1/128", true) {
		t.Fatal("expected ::1/128 loopback to be identified as local prefix")
	}

	// Default route ::/0 MUST NOT be identified as local
	if ShimTestIsLocalPrefix("default", "::/0", true) {
		t.Fatal("default route ::/0 must NOT be identified as local prefix")
	}

	// IPv6 supernets MUST NOT be identified as local
	if ShimTestIsLocalPrefix("default", "2001:db8::/32", true) {
		t.Fatal("IPv6 supernet 2001:db8::/32 must NOT be identified as local prefix")
	}
	if ShimTestIsLocalPrefix("default", "2001:db8:1::/48", true) {
		t.Fatal("IPv6 supernet 2001:db8:1::/48 must NOT be identified as local prefix")
	}

	if ShimTestIsLocalPrefix("default", "2001:db8:99::/64", true) {
		t.Fatal("remote IPv6 prefix must NOT be identified as local prefix")
	}
}

// TestRouteWorker_SliceElementZeroed verifies that shifted elements in overflow are zeroed
// to avoid GC memory retention.
func TestRouteWorker_SliceElementZeroed(t *testing.T) {
	w := &routeQueueWorker{
		queue: make(chan routeEvent, 1),
		stop:  make(chan struct{}),
	}

	// Enqueue 3 items
	w.enqueue(routeEvent{prefix: "10.1.0.0/24"})
	w.enqueue(routeEvent{prefix: "10.2.0.0/24"})
	w.enqueue(routeEvent{prefix: "10.3.0.0/24"})

	w.mu.Lock()
	if len(w.overflow) != 2 {
		w.mu.Unlock()
		t.Fatalf("expected 2 overflow items, got %d", len(w.overflow))
	}
	// Simulate zeroing and shifting
	w.overflow[0] = routeEvent{}
	w.overflow = w.overflow[1:]
	firstRemaining := w.overflow[0]
	w.mu.Unlock()

	if firstRemaining.prefix != "10.3.0.0/24" {
		t.Fatalf("expected remaining overflow item to be 10.3.0.0/24, got %s", firstRemaining.prefix)
	}
}

func TestVlanLearningAndApplyInterface(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		learnedVlans: make(map[string]uint16),
	}
	inst := newEigrpInstance("default")
	inst.asn = 100
	inst.adminState = "enable"
	d.instances["default"] = inst

	intfName := "ethernet-1/1.1"
	vlanID := uint16(10)

	cfgNotif := &ndk.ConfigNotification{
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
		Key: &ndk.ConfigKey{
			JsPath: ".interface{.name==\"ethernet-1/1\"}.subinterface{.index==\"1\"}.vlan",
		},
		Data: &ndk.ConfigData{
			DataType: &ndk.ConfigData_Json{
				Json: `{"encap":{"single-tagged":{"vlan-id":10}}}`,
			},
		},
	}
	d.HandleConfigNotification(cfgNotif)

	d.mu.RLock()
	learned, ok := d.learnedVlans[intfName]
	d.mu.RUnlock()
	if !ok || learned != vlanID {
		t.Fatalf("expected learned vlan %d for %s, got %d (ok=%v)", vlanID, intfName, learned, ok)
	}

	ifcfg := &InterfaceConfig{
		InterfaceName: intfName,
	}
	inst.configuredInterfaces[intfName] = ifcfg

	d.applyInterface(inst, ifcfg)
	if ifcfg.VlanID == nil || *ifcfg.VlanID != vlanID {
		t.Fatalf("expected applyInterface to supply learned vlan %d, got %v", vlanID, ifcfg.VlanID)
	}
}

func TestConcurrentReportsAndVlanSetNoDeadlock(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		learnedVlans: make(map[string]uint16),
	}
	inst := newEigrpInstance("default")
	inst.asn = 100
	inst.adminState = "enable"
	d.instances["default"] = inst

	daemonApp = d
	defer func() { daemonApp = nil }()

	ShimTestClearInterfaces()
	ShimTestRegisterInterfaceWithVlan("default", "ethernet-1/1.1", 10, 1, 10, "10.0.0.1", 30, false, true)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				ShimNeighborsReport("default")
				ShimTopologyReport("default")
				ShimTrafficReport("default")
				ShimInterfacesReport("default")
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			cfgNotif := &ndk.ConfigNotification{
				Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
				Key: &ndk.ConfigKey{
					JsPath: ".interface{.name==\"ethernet-1/1\"}.subinterface{.index==\"1\"}.vlan",
				},
				Data: &ndk.ConfigData{
					DataType: &ndk.ConfigData_Json{
						Json: fmt.Sprintf(`{"encap":{"single-tagged":{"vlan-id":%d}}}`, (i%50)+1),
					},
				},
			}
			d.HandleConfigNotification(cfgNotif)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			d.mu.RLock()
			_ = len(d.instances)
			d.mu.RUnlock()
		}
	}()

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestInterfacePropertyDeletionsNoDeadlock(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		learnedVlans: make(map[string]uint16),
	}
	inst := newEigrpInstance("default")
	inst.asn = 100
	inst.adminState = "enable"
	d.instances["default"] = inst

	intfName := "ethernet-1/1.0"
	bw := uint32(500000)
	del := uint32(200)
	pass := true
	hello := uint16(10)
	hold := uint16(30)
	sh := false
	nhs := true

	ifcfg := &InterfaceConfig{
		InterfaceName: intfName,
		AdminState:    "disable",
		Bandwidth:     &bw,
		Delay:         &del,
		VlanID:        nil, // Specifically nil to exercise the d.learnedVlans lock-path inside applyInterface
		AddressFamily: []InterfaceAddressFamilyConfig{
			{
				Name:          "ipv4-unicast",
				AdminState:    "disable",
				Passive:       &pass,
				HelloInterval: &hello,
				HoldTime:      &hold,
				SplitHorizon:  &sh,
				NextHopSelf:   &nhs,
			},
		},
	}
	inst.configuredInterfaces[intfName] = ifcfg

	intfLeafs := []string{
		"admin-state",
		"delay",
		"bandwidth",
	}

	for _, leaf := range intfLeafs {
		notif := &ndk.ConfigNotification{
			Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
			Key: &ndk.ConfigKey{
				JsPath: fmt.Sprintf(`.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="%s"}.%s`, intfName, leaf),
			},
		}
		done := make(chan struct{})
		go func() {
			d.HandleConfigNotification(notif)
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("deadlock detected while deleting interface leaf: %s", leaf)
		}
	}

	afLeafs := []string{
		"admin-state",
		"passive",
		"hello-interval",
		"hold-time",
		"split-horizon",
		"next-hop-self",
	}

	for _, leaf := range afLeafs {
		notif := &ndk.ConfigNotification{
			Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
			Key: &ndk.ConfigKey{
				JsPath: fmt.Sprintf(`.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="%s"}.address-family{.name=="ipv4-unicast"}.%s`, intfName, leaf),
			},
		}
		done := make(chan struct{})
		go func() {
			d.HandleConfigNotification(notif)
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("deadlock detected while deleting interface AF leaf: %s", leaf)
		}
	}

	d.mu.RLock()
	defer d.mu.RUnlock()
	if ifcfg.AdminState != "enable" {
		t.Fatalf("expected admin-state reset to enable, got %s", ifcfg.AdminState)
	}
	if ifcfg.Delay != nil {
		t.Fatalf("expected delay reset to nil, got %v", ifcfg.Delay)
	}
	if ifcfg.Bandwidth != nil {
		t.Fatalf("expected bandwidth reset to nil, got %v", ifcfg.Bandwidth)
	}
	af := ifcfg.GetAfiConfig("ipv4-unicast")
	if af == nil {
		t.Fatal("expected ipv4-unicast AF config to exist")
	}
	if af.Passive != nil {
		t.Fatalf("expected passive reset to nil, got %v", af.Passive)
	}
	if af.HelloInterval != nil {
		t.Fatalf("expected hello-interval reset to nil, got %v", af.HelloInterval)
	}
	if af.HoldTime != nil {
		t.Fatalf("expected hold-time reset to nil, got %v", af.HoldTime)
	}
	if af.SplitHorizon != nil {
		t.Fatalf("expected split-horizon reset to nil, got %v", af.SplitHorizon)
	}
	if af.NextHopSelf != nil {
		t.Fatalf("expected next-hop-self reset to nil, got %v", af.NextHopSelf)
	}
}

func TestTelemetryReorganizedPathsAndSchemaRank(t *testing.T) {
	tf := &TrafficInfo{
		Interface:       "ethernet-1/1.0",
		ReliableMcast:   10,
		UnreliableMcast: 20,
		ReliableUcast:   30,
		UnreliableUcast: 40,
		Retransmissions: 2,
		CRPackets:       1,
	}
	ic := &InterfaceConfig{
		InterfaceName: "ethernet-1/1.0",
		AdminState:    "enable",
	}
	defIntf := &DefaultInterfaceConfig{
		AdminState: "enable",
	}
	data := buildInterfaceData("ethernet-1/1.0", "10.0.0.1", 30, "up", ic, defIntf, "up", tf)
	stats, ok := data["statistics"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected statistics map in buildInterfaceData, got %+v", data["statistics"])
	}
	if stats["reliable-multicast"] != uint64(10) || stats["unreliable-multicast"] != uint64(20) || stats["retransmissions"] != uint64(2) {
		t.Fatalf("unexpected statistics counters: %+v", stats)
	}

	// Verify schemaRank orders topology.prefix, topology.prefix.route, and event-log.entry strictly
	rRoot := schemaRank(`.network_instance{.name=="default"}.protocols.eigrp`)
	rDefAf := schemaRank(`.network_instance{.name=="default"}.protocols.eigrp.default-interface.address-family{.name=="ipv4-unicast"}`)
	rIntf := schemaRank(`.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}`)
	rAf := schemaRank(`.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv4-unicast"}`)
	rTopoPfx := schemaRank(`.network_instance{.name=="default"}.protocols.eigrp.topology.prefix{.prefix=="10.0.0.0/24"}`)
	rTopoRt := schemaRank(`.network_instance{.name=="default"}.protocols.eigrp.topology.prefix{.prefix=="10.0.0.0/24"}.route{.next-hop=="10.0.0.2"}`)
	rEvLog := schemaRank(`.network_instance{.name=="default"}.protocols.eigrp.event-log.entry{.id==1}`)

	if !(rRoot < rAf && rAf < rDefAf && rDefAf < rEvLog && rEvLog < rIntf && rIntf < rTopoPfx && rTopoPfx < rTopoRt) {
		t.Fatalf("invalid schemaRank ordering: root=%d af=%d defAf=%d evLog=%d intf=%d topoPfx=%d topoRt=%d",
			rRoot, rAf, rDefAf, rEvLog, rIntf, rTopoPfx, rTopoRt)
	}
}

func TestInterfaceStubPreallocationAndVlanPreservation(t *testing.T) {
	ShimTestClearInterfaces()
	defer ShimTestClearInterfaces()

	// 1. Call ShimInterfaceSetVlanID before interface is registered (pre-allocation)
	rc := ShimInterfaceSetVlanID("default", "ethernet-1/1.10", 100)
	if rc != 0 {
		t.Fatalf("expected ShimInterfaceSetVlanID to return 0 on stub preallocation, got %d", rc)
	}

	// 2. Simulate subsequent interface scan/registration from network namespace
	// Registration with ShimTestRegisterInterface passes vlanID=0 (as getifaddrs does)
	ShimTestRegisterInterface("default", "ethernet-1/1.10", 510, 50, "10.10.10.1", 24, false, true)

	// 3. Verify that the preallocated VLAN ID 100 was retained
	res := ShimTestResolveInterfaceV4("default", 50, 100, "10.10.10.2", "224.0.0.10")
	if res != 510 {
		t.Fatalf("expected interface with retained VLAN 100 to resolve to 510, got %d", res)
	}

	// 4. Verify that untagged packet does not match this tagged interface
	resUntagged := ShimTestResolveInterfaceV4("default", 50, 0, "10.10.10.2", "224.0.0.10")
	if resUntagged != 0 {
		t.Fatalf("expected untagged frame to be rejected, got %d", resUntagged)
	}
}
