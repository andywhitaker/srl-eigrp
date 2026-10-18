package main

import (
	"encoding/json"
	"net"
	"testing"

	ndk "github.com/nokia/srlinux-ndk-go/ndk"
)

func TestPolicyAction_UnmarshalJSON(t *testing.T) {
	// 1. Test parsing with SR Linux YANG module prefix "srl_nokia-eigrp:eigrp"
	jsonWithPrefix := []byte(`{
		"policy-result": "accept",
		"srl_nokia-eigrp:eigrp": {
			"metric": {
				"bandwidth": 200000,
				"delay": 250,
				"reliability": 250,
				"load": 5,
				"mtu": 1400
			}
		}
	}`)
	var pa1 PolicyAction
	if err := json.Unmarshal(jsonWithPrefix, &pa1); err != nil {
		t.Fatalf("failed unmarshaling policy action with prefix: %v", err)
	}
	if pa1.PolicyResult != "accept" {
		t.Errorf("expected policy-result 'accept', got %q", pa1.PolicyResult)
	}
	if pa1.Eigrp.Metric.Bandwidth != 200000 || pa1.Eigrp.Metric.Delay != 250 || pa1.Eigrp.Metric.Mtu != 1400 {
		t.Errorf("metric mismatch for prefix key: %+v", pa1.Eigrp.Metric)
	}

	// 2. Test parsing with standard "eigrp"
	jsonStandard := []byte(`{
		"policy-result": "accept",
		"eigrp": {
			"metric": {
				"bandwidth": 100000,
				"delay": 100,
				"reliability": 255,
				"load": 1,
				"mtu": 1500
			}
		}
	}`)
	var pa2 PolicyAction
	if err := json.Unmarshal(jsonStandard, &pa2); err != nil {
		t.Fatalf("failed unmarshaling standard policy action: %v", err)
	}
	if pa2.Eigrp.Metric.Bandwidth != 100000 || pa2.Eigrp.Metric.Delay != 100 {
		t.Errorf("metric mismatch for standard key: %+v", pa2.Eigrp.Metric)
	}
}

func TestMatchProtocol_PrefixStripping(t *testing.T) {
	tests := []struct {
		name        string
		policyProto string
		routeType   string
		routeOwner  string
		isV6        bool
		expected    bool
	}{
		{
			name:        "ospfv2 with module prefix on v4 route",
			policyProto: "srl_nokia-common:ospfv2",
			routeType:   "ospf",
			routeOwner:  "ospf_mgr",
			isV6:        false,
			expected:    true,
		},
		{
			name:        "ospfv2 with module prefix on v6 route should not match",
			policyProto: "srl_nokia-common:ospfv2",
			routeType:   "ospf",
			routeOwner:  "ospf_mgr",
			isV6:        true,
			expected:    false,
		},
		{
			name:        "ospfv3 with module prefix on v6 route",
			policyProto: "srl_nokia-common:ospfv3",
			routeType:   "ospfv3",
			routeOwner:  "ospf_mgr",
			isV6:        true,
			expected:    true,
		},
		{
			name:        "static with module prefix",
			policyProto: "srl_nokia-routing-policy:static",
			routeType:   "static",
			routeOwner:  "static_route_mgr",
			isV6:        false,
			expected:    true,
		},
		{
			name:        "local/connected with module prefix",
			policyProto: "srl_nokia-common:local",
			routeType:   "local",
			routeOwner:  "net_inst_mgr",
			isV6:        false,
			expected:    true,
		},
		{
			name:        "bgp without prefix",
			policyProto: "bgp",
			routeType:   "bgp",
			routeOwner:  "bgp_mgr",
			isV6:        false,
			expected:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := matchProtocol(tc.policyProto, tc.routeType, tc.routeOwner, tc.isV6)
			if res != tc.expected {
				t.Errorf("matchProtocol(%q, %q, %q, %v) = %v; expected %v",
					tc.policyProto, tc.routeType, tc.routeOwner, tc.isV6, res, tc.expected)
			}
		})
	}
}

func TestComputeNhgName_Deduplication(t *testing.T) {
	nhs1 := []string{"10.0.0.1", "10.0.0.2"}
	nhs2 := []string{"10.0.0.2", "10.0.0.1"}
	nhs3 := []string{"10.0.0.1", "10.0.0.3"}

	name1 := computeNhgName("default", nhs1)
	name2 := computeNhgName("default", nhs2)
	name3 := computeNhgName("default", nhs3)

	if name1 != name2 {
		t.Fatalf("expected identical NHG name for permuted next-hops, got %q vs %q", name1, name2)
	}
	if name1 == name3 {
		t.Fatalf("expected different NHG names for different next-hops, got same: %q", name1)
	}
}

func TestNhgRefCounting_Lifecycle(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		prefixToNhg:  make(map[string]string),
		nhgRefCounts: make(map[string]int),
	}

	netinst := "default"
	pfx1 := "10.1.1.0/24"
	pfx2 := "10.2.2.0/24"
	nh := "192.168.1.1"

	// Route 1 added
	d.OnRouteAdd(netinst, pfx1, nh, 1000, 100000, false, 90)

	nhgName := computeNhgName(netinst, []string{nh})
	d.nhgMu.Lock()
	count1 := d.nhgRefCounts[nhgName]
	assignedNhg1 := d.prefixToNhg[netinst+":"+pfx1]
	d.nhgMu.Unlock()

	if count1 != 1 {
		t.Fatalf("expected refcount 1 for NHG, got %d", count1)
	}
	if assignedNhg1 != nhgName {
		t.Fatalf("expected prefix mapped to %q, got %q", nhgName, assignedNhg1)
	}

	// Route 2 added with same nexthop
	d.OnRouteAdd(netinst, pfx2, nh, 2000, 200000, false, 90)

	d.nhgMu.Lock()
	count2 := d.nhgRefCounts[nhgName]
	assignedNhg2 := d.prefixToNhg[netinst+":"+pfx2]
	d.nhgMu.Unlock()

	if count2 != 2 {
		t.Fatalf("expected refcount 2 after second route added, got %d", count2)
	}
	if assignedNhg2 != nhgName {
		t.Fatalf("expected second prefix mapped to %q, got %q", nhgName, assignedNhg2)
	}

	// Withdraw Route 1
	d.withdrawRouteInternal(netinst, pfx1)

	d.nhgMu.Lock()
	count3 := d.nhgRefCounts[nhgName]
	_, pfx1Exists := d.prefixToNhg[netinst+":"+pfx1]
	d.nhgMu.Unlock()

	if count3 != 1 {
		t.Fatalf("expected refcount 1 after withdrawing pfx1, got %d", count3)
	}
	if pfx1Exists {
		t.Fatalf("expected pfx1 removed from prefixToNhg mapping")
	}

	// Withdraw Route 2
	d.withdrawRouteInternal(netinst, pfx2)

	d.nhgMu.Lock()
	count4, nhgExists := d.nhgRefCounts[nhgName]
	_, pfx2Exists := d.prefixToNhg[netinst+":"+pfx2]
	d.nhgMu.Unlock()

	if nhgExists || count4 != 0 {
		t.Fatalf("expected NHG deleted from refCounts map when refcount reaches 0, got count %d (exists: %v)", count4, nhgExists)
	}
	if pfx2Exists {
		t.Fatalf("expected pfx2 removed from prefixToNhg mapping")
	}
}

func TestHandleRouteAndAppIdNotification_InMemoryTracking(t *testing.T) {
	d := &EigrpDaemon{
		appId:           999,
		instances:       make(map[string]*EigrpInstance),
		appIdToName:     make(map[uint32]string),
		candidateRoutes: make(map[string]map[string]CandidateRoute),
	}

	// Register app 42 as ospf_mgr
	d.HandleAppIdNotification(&ndk.AppIdentNotification{
		Key:  &ndk.AppIdentKey{Id: 42},
		Data: &ndk.AppIdentData{Name: "ospf_mgr"},
	})

	if owner := d.getAppOwner(42); owner != "ospf_mgr" {
		t.Fatalf("expected app owner 'ospf_mgr', got %q", owner)
	}

	// Send route notification owned by app 42
	pfxIP := net.ParseIP("192.168.10.0").To4()
	nhIP := net.ParseIP("10.0.0.2").To4()
	d.HandleRouteNotification(&ndk.IpRouteNotification{
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
		Key: &ndk.RouteKey{
			NetworkInstanceName: "default",
			IpPrefix: &ndk.IpAddrPrefLenPb{
				IpAddr:       &ndk.IpAddressPb{IpAddress: pfxIP},
				PrefixLength: 24,
			},
		},
		Data: &ndk.Route{
			OwnerId: 42,
			Nexthops: []*ndk.NextHop{
				{
					Nexthop: &ndk.NextHop_IpNexthop{
						IpNexthop: &ndk.IpAddressPb{IpAddress: nhIP},
					},
				},
			},
		},
	})

	routes, err := d.GetCandidateRoutes("default", "ipv4-unicast")
	if err != nil {
		t.Fatalf("failed GetCandidateRoutes: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 candidate route, got %d", len(routes))
	}
	if routes[0].Prefix != "192.168.10.0/24" {
		t.Errorf("expected prefix '192.168.10.0/24', got %q", routes[0].Prefix)
	}
	if routes[0].RouteOwner != "ospf_mgr" {
		t.Errorf("expected RouteOwner 'ospf_mgr', got %q", routes[0].RouteOwner)
	}
	if routes[0].NextHop != "10.0.0.2" {
		t.Errorf("expected NextHop '10.0.0.2', got %q", routes[0].NextHop)
	}

	// Route notification owned by EIGRP itself (appId 999) should be ignored
	eigrpPfx := net.ParseIP("172.16.0.0").To4()
	d.HandleRouteNotification(&ndk.IpRouteNotification{
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
		Key: &ndk.RouteKey{
			NetworkInstanceName: "default",
			IpPrefix: &ndk.IpAddrPrefLenPb{
				IpAddr:       &ndk.IpAddressPb{IpAddress: eigrpPfx},
				PrefixLength: 16,
			},
		},
		Data: &ndk.Route{
			OwnerId: 999,
		},
	})

	routesAfterSelf, _ := d.GetCandidateRoutes("default", "ipv4-unicast")
	if len(routesAfterSelf) != 1 {
		t.Fatalf("expected EIGRP self route to be skipped, got %d routes", len(routesAfterSelf))
	}

	// Route delete notification should remove candidate route
	d.HandleRouteNotification(&ndk.IpRouteNotification{
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
		Key: &ndk.RouteKey{
			NetworkInstanceName: "default",
			IpPrefix: &ndk.IpAddrPrefLenPb{
				IpAddr:       &ndk.IpAddressPb{IpAddress: pfxIP},
				PrefixLength: 24,
			},
		},
	})

	routesAfterDel, _ := d.GetCandidateRoutes("default", "ipv4-unicast")
	if len(routesAfterDel) != 0 {
		t.Fatalf("expected 0 candidate routes after deletion, got %d", len(routesAfterDel))
	}
}

func TestNetworkInstance_IdResolutionAndRouteMigration(t *testing.T) {
	d := &EigrpDaemon{
		appId:           999,
		instances:       make(map[string]*EigrpInstance),
		appIdToName:     make(map[uint32]string),
		candidateRoutes: make(map[string]map[string]CandidateRoute),
		netinstIdToName: make(map[string]string),
		netinstNameToId: make(map[string]string),
	}

	// 1. Initial resolution of system defaults
	if resolved := d.resolveNetinstName("10241"); resolved != "default" {
		t.Fatalf("expected 10241 to resolve to 'default', got %q", resolved)
	}

	// 2. Handle NetworkInstanceNotification for default (10241) and vrf-1 (10242)
	d.HandleNetworkInstanceNotification(&ndk.NetworkInstanceNotification{
		Op:  ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
		Key: &ndk.NetworkInstanceKey{InstanceName: "vrf-1"},
		Data: &ndk.NetworkInstanceData{
			NetworkInstanceId: 10242,
		},
	})

	if resolved := d.resolveNetinstName("10242"); resolved != "vrf-1" {
		t.Fatalf("expected 10242 to resolve to 'vrf-1', got %q", resolved)
	}
	if id, ok := d.getNetinstId("vrf-1"); !ok || id != "10242" {
		t.Fatalf("expected vrf-1 ID to be '10242', got %q", id)
	}

	// 3. Register app owner
	d.HandleAppIdNotification(&ndk.AppIdentNotification{
		Key:  &ndk.AppIdentKey{Id: 50},
		Data: &ndk.AppIdentData{Name: "bgp_mgr"},
	})

	// 4. Send route notification arriving with numeric network_instance_name "10242"
	pfxIP := net.ParseIP("10.10.10.0").To4()
	d.HandleRouteNotification(&ndk.IpRouteNotification{
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
		Key: &ndk.RouteKey{
			NetworkInstanceName: "10242",
			IpPrefix: &ndk.IpAddrPrefLenPb{
				IpAddr:       &ndk.IpAddressPb{IpAddress: pfxIP},
				PrefixLength: 24,
			},
		},
		Data: &ndk.Route{
			OwnerId: 50,
		},
	})

	// Querying by friendly name "vrf-1" should find it
	routes, err := d.GetCandidateRoutes("vrf-1", "ipv4-unicast")
	if err != nil {
		t.Fatalf("failed GetCandidateRoutes: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route under 'vrf-1', got %d", len(routes))
	}
	if routes[0].Prefix != "10.10.10.0/24" {
		t.Errorf("expected prefix '10.10.10.0/24', got %q", routes[0].Prefix)
	}
	if routes[0].RouteOwner != "bgp_mgr" {
		t.Errorf("expected owner 'bgp_mgr', got %q", routes[0].RouteOwner)
	}

	// 5. Test route arrival BEFORE network instance notification (orphan migration)
	pfxIP2 := net.ParseIP("10.20.20.0").To4()
	d.HandleRouteNotification(&ndk.IpRouteNotification{
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
		Key: &ndk.RouteKey{
			NetworkInstanceName: "10243",
			IpPrefix: &ndk.IpAddrPrefLenPb{
				IpAddr:       &ndk.IpAddressPb{IpAddress: pfxIP2},
				PrefixLength: 24,
			},
		},
		Data: &ndk.Route{
			OwnerId: 50,
		},
	})

	// Now network instance notification arrives for vrf-2 (10243)
	d.HandleNetworkInstanceNotification(&ndk.NetworkInstanceNotification{
		Op:  ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
		Key: &ndk.NetworkInstanceKey{InstanceName: "vrf-2"},
		Data: &ndk.NetworkInstanceData{
			NetworkInstanceId: 10243,
		},
	})

	// Querying by friendly name "vrf-2" should now find the migrated route
	routesVrf2, err := d.GetCandidateRoutes("vrf-2", "ipv4-unicast")
	if err != nil {
		t.Fatalf("failed GetCandidateRoutes for vrf-2: %v", err)
	}
	if len(routesVrf2) != 1 {
		t.Fatalf("expected 1 route under 'vrf-2' after migration, got %d", len(routesVrf2))
	}
	if routesVrf2[0].Prefix != "10.20.20.0/24" {
		t.Errorf("expected prefix '10.20.20.0/24', got %q", routesVrf2[0].Prefix)
	}
}
