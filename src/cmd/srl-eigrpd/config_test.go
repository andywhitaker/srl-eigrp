package main

import (
	"testing"
	"time"

	ndk "github.com/nokia/srlinux-ndk-go/ndk"
)

func TestCandidateRouteCache_HitAndTTL(t *testing.T) {
	d := &EigrpDaemon{
		instances:  make(map[string]*EigrpInstance),
		routeCache: make(map[string]*candidateRouteCacheEntry),
	}

	netinst := "default"
	afi := "ipv4-unicast"
	cacheKey := netinst + ":" + afi

	initialRoutes := []CandidateRoute{
		{
			Prefix:     "10.10.10.0/24",
			RouteType:  "static",
			RouteOwner: "static",
			NextHop:    "192.168.1.1",
			AFI:        afi,
		},
	}

	// Populate cache
	d.routeCacheMu.Lock()
	d.routeCache[cacheKey] = &candidateRouteCacheEntry{
		routes:    initialRoutes,
		timestamp: time.Now(),
		dirty:     false,
	}
	d.routeCacheMu.Unlock()

	// Hit test: should return cached routes without calling CLI
	routes, err := d.GetCandidateRoutes(netinst, afi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 1 || routes[0].Prefix != "10.10.10.0/24" {
		t.Fatalf("expected cached route 10.10.10.0/24, got %v", routes)
	}

	// Invalidation test: mark netinst dirty
	d.InvalidateCandidateRouteCache(netinst)

	d.routeCacheMu.RLock()
	entry := d.routeCache[cacheKey]
	isDirty := entry.dirty
	d.routeCacheMu.RUnlock()

	if !isDirty {
		t.Fatal("expected entry to be marked dirty after InvalidateCandidateRouteCache")
	}
}

func TestCandidateRouteCache_InvalidateAll(t *testing.T) {
	d := &EigrpDaemon{
		instances:  make(map[string]*EigrpInstance),
		routeCache: make(map[string]*candidateRouteCacheEntry),
	}

	d.routeCache["default:ipv4-unicast"] = &candidateRouteCacheEntry{
		routes:    nil,
		timestamp: time.Now(),
		dirty:     false,
	}
	d.routeCache["vrf-red:ipv4-unicast"] = &candidateRouteCacheEntry{
		routes:    nil,
		timestamp: time.Now(),
		dirty:     false,
	}

	d.InvalidateCandidateRouteCache("*")

	for k, entry := range d.routeCache {
		if !entry.dirty {
			t.Fatalf("expected entry %s to be dirty", k)
		}
	}
}

func TestVariance_Configuration(t *testing.T) {
	inst := newEigrpInstance("default")
	if inst.variance != 1 {
		t.Fatalf("expected default variance to be 1, got %d", inst.variance)
	}

	// Set variance > 1
	inst.variance = 2
	if inst.variance != 2 {
		t.Fatalf("expected variance 2, got %d", inst.variance)
	}

	inst.variance = 128
	if inst.variance != 128 {
		t.Fatalf("expected variance 128, got %d", inst.variance)
	}
}

func TestCandidateRouteCache_TTLExpiration(t *testing.T) {
	d := &EigrpDaemon{
		instances:  make(map[string]*EigrpInstance),
		routeCache: make(map[string]*candidateRouteCacheEntry),
	}

	cacheKey := "default:ipv4-unicast"

	// Insert entry with expired timestamp (31 seconds ago)
	d.routeCacheMu.Lock()
	d.routeCache[cacheKey] = &candidateRouteCacheEntry{
		routes: []CandidateRoute{
			{Prefix: "10.0.0.0/8"},
		},
		timestamp: time.Now().Add(-31 * time.Second),
		dirty:     false,
	}
	d.routeCacheMu.Unlock()

	// Direct check: should be recognized as expired
	d.routeCacheMu.RLock()
	entry := d.routeCache[cacheKey]
	isExpired := time.Since(entry.timestamp) >= candidateRouteCacheTTL
	d.routeCacheMu.RUnlock()

	if !isExpired {
		t.Fatal("expected entry to be expired after TTL duration")
	}
}

func TestCandidateRouteCache_NilSafety(t *testing.T) {
	d := &EigrpDaemon{} // routeCache is nil
	d.InvalidateCandidateRouteCache("default")
	d.InvalidateCandidateRouteCache("*")
}

func TestConfig_SubPathVarianceNotification(t *testing.T) {
	d := &EigrpDaemon{
		instances:  make(map[string]*EigrpInstance),
		routeCache: make(map[string]*candidateRouteCacheEntry),
	}

	netinst := "default"
	// Sub-path direct value
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: ".network_instance{.name==\"default\"}.protocols.eigrp.variance",
		},
		Data: &ndk.ConfigData{
			DataType: &ndk.ConfigData_Json{
				Json: "2",
			},
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	inst := d.GetInstance(netinst)
	if inst == nil || inst.variance != 2 {
		t.Fatalf("expected variance 2, got %v", inst)
	}

	// Sub-path JSON wrapper
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: ".network_instance{.name==\"default\"}.protocols.eigrp.variance",
		},
		Data: &ndk.ConfigData{
			DataType: &ndk.ConfigData_Json{
				Json: "{\"variance\": 4}",
			},
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_UPDATE,
	})

	if inst.variance != 4 {
		t.Fatalf("expected variance 4, got %d", inst.variance)
	}

	// Sub-path DELETE resets to 1
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: ".network_instance{.name==\"default\"}.protocols.eigrp.variance",
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})

	if inst.variance != 1 {
		t.Fatalf("expected variance reset to 1 on delete, got %d", inst.variance)
	}
}

func TestConfig_PreferenceSubPaths(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		routeWorkers: make(map[string]*routeQueueWorker),
	}
	netinst := "default"

	// 1. Preference create
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: ".network_instance{.name==\"default\"}.protocols.eigrp.preference",
		},
		Data: &ndk.ConfigData{
			DataType: &ndk.ConfigData_Json{
				Json: "110",
			},
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	inst := d.GetInstance(netinst)
	if inst == nil || inst.preference != 110 {
		t.Fatalf("expected preference 110, got %v", inst)
	}

	// 2. External Preference create
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: ".network_instance{.name==\"default\"}.protocols.eigrp.external-preference",
		},
		Data: &ndk.ConfigData{
			DataType: &ndk.ConfigData_Json{
				Json: "180",
			},
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	if inst.externalPreference != 180 {
		t.Fatalf("expected externalPreference 180, got %d", inst.externalPreference)
	}

	// 3. Delete preference resets to 90
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: ".network_instance{.name==\"default\"}.protocols.eigrp.preference",
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})
	if inst.preference != 90 {
		t.Fatalf("expected preference reset to 90, got %d", inst.preference)
	}

	// 4. Delete external-preference resets to 170
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: ".network_instance{.name==\"default\"}.protocols.eigrp.external-preference",
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})
	if inst.externalPreference != 170 {
		t.Fatalf("expected externalPreference reset to 170, got %d", inst.externalPreference)
	}
}

func TestConfig_AddressFamilyPreference(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		routeWorkers: make(map[string]*routeQueueWorker),
	}
	netinst := "default"

	// Create AF ipv4-unicast with custom preference
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: ".network_instance{.name==\"default\"}.protocols.eigrp.address-family{.name==\"ipv4-unicast\"}",
		},
		Data: &ndk.ConfigData{
			DataType: &ndk.ConfigData_Json{
				Json: "{\"name\":\"ipv4-unicast\",\"preference\":85,\"external-preference\":165}",
			},
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	inst := d.GetInstance(netinst)
	if inst == nil {
		t.Fatal("expected instance to exist")
	}

	if p := inst.GetAfiPreference("ipv4-unicast"); p != 85 {
		t.Fatalf("expected AF preference 85, got %d", p)
	}
	if ep := inst.GetAfiExternalPreference("ipv4-unicast"); ep != 165 {
		t.Fatalf("expected AF externalPreference 165, got %d", ep)
	}

	// Delete AF preference
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath:         ".network_instance{.name==\"default\"}.protocols.eigrp.address-family{.name==\"ipv4-unicast\"}.preference",
			JsPathWithKeys: ".network_instance{.name==\"default\"}.protocols.eigrp.address-family{.name==\"ipv4-unicast\"}.preference",
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})

	if p := inst.GetAfiPreference("ipv4-unicast"); p != 90 {
		t.Fatalf("expected AF preference fallback to top-level 90, got %d", p)
	}
}

func TestConfig_StaticNeighborSubPath(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		routeWorkers: make(map[string]*routeQueueWorker),
	}
	netinst := "default"

	// Create static neighbor
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath:         ".network_instance{.name==\"default\"}.protocols.eigrp.static-neighbor{.ip-address==\"10.10.1.2\"}",
			JsPathWithKeys: ".network_instance{.name==\"default\"}.protocols.eigrp.static-neighbor{.ip-address==\"10.10.1.2\"}",
		},
		Data: &ndk.ConfigData{
			DataType: &ndk.ConfigData_Json{
				Json: "{\"ip-address\":\"10.10.1.2\",\"interface\":\"ethernet-1/1.0\"}",
			},
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	inst := d.GetInstance(netinst)
	if inst == nil {
		t.Fatal("expected instance to exist")
	}

	d.mu.RLock()
	sn, exists := inst.staticNeighbors["10.10.1.2"]
	d.mu.RUnlock()

	if !exists || sn == nil || sn.Interface != "ethernet-1/1.0" {
		t.Fatalf("expected static neighbor 10.10.1.2 on ethernet-1/1.0, got %+v", sn)
	}

	// Delete static neighbor
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath:         ".network_instance{.name==\"default\"}.protocols.eigrp.static-neighbor{.ip-address==\"10.10.1.2\"}",
			JsPathWithKeys: ".network_instance{.name==\"default\"}.protocols.eigrp.static-neighbor{.ip-address==\"10.10.1.2\"}",
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})

	d.mu.RLock()
	_, exists = inst.staticNeighbors["10.10.1.2"]
	d.mu.RUnlock()

	if exists {
		t.Fatal("expected static neighbor 10.10.1.2 to be deleted")
	}
}

func TestConfig_SummaryAddressSubPath(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		routeWorkers: make(map[string]*routeQueueWorker),
	}
	netinst := "default"

	// Create summary-address on interface ethernet-1/1.0
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath:         ".network_instance{.name==\"default\"}.protocols.eigrp.interface{.interface-name==\"ethernet-1/1.0\"}.summary-address{.prefix==\"10.50.0.0/16\"}",
			JsPathWithKeys: ".network_instance{.name==\"default\"}.protocols.eigrp.interface{.interface-name==\"ethernet-1/1.0\"}.summary-address{.prefix==\"10.50.0.0/16\"}",
		},
		Data: &ndk.ConfigData{
			DataType: &ndk.ConfigData_Json{
				Json: "{\"prefix\":\"10.50.0.0/16\",\"distance\":5}",
			},
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	inst := d.GetInstance(netinst)
	if inst == nil {
		t.Fatal("expected instance to exist")
	}

	d.mu.RLock()
	ic, exists := inst.configuredInterfaces["ethernet-1/1.0"]
	d.mu.RUnlock()

	if !exists || ic == nil {
		t.Fatal("expected interface ethernet-1/1.0 to exist")
	}

	saList := ic.GetAfiSummaryAddresses("ipv4-unicast")
	if len(saList) != 1 || saList[0].Prefix != "10.50.0.0/16" {
		t.Fatalf("expected summary address 10.50.0.0/16, got %+v", saList)
	}

	// Delete summary address
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath:         ".network_instance{.name==\"default\"}.protocols.eigrp.interface{.interface-name==\"ethernet-1/1.0\"}.summary-address{.prefix==\"10.50.0.0/16\"}",
			JsPathWithKeys: ".network_instance{.name==\"default\"}.protocols.eigrp.interface{.interface-name==\"ethernet-1/1.0\"}.summary-address{.prefix==\"10.50.0.0/16\"}",
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})

	saList = ic.GetAfiSummaryAddresses("ipv4-unicast")
	if len(saList) != 0 {
		t.Fatalf("expected summary address to be deleted, got %+v", saList)
	}
}

func TestConfig_UpstreamFeaturesSubPaths(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		routeWorkers: make(map[string]*routeQueueWorker),
		learnedVlans: make(map[string]uint16),
	}
	netinst := "default"

	// 1. Top-level traffic-share-balanced, auto-summary, event-log-size
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.traffic-share-balanced`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `true`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.auto-summary`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `true`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.event-log-size`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `1000`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	inst := d.GetInstance(netinst)
	if inst == nil {
		t.Fatal("expected instance to exist")
	}
	if !inst.trafficShareBalanced || !inst.GetAfiTrafficShareBalanced("ipv4-unicast") {
		t.Fatal("expected trafficShareBalanced to be true")
	}
	if !inst.autoSummary || !inst.GetAfiAutoSummary("ipv4-unicast") {
		t.Fatal("expected autoSummary to be true")
	}
	if inst.eventLogSize != 1000 {
		t.Fatalf("expected eventLogSize 1000, got %d", inst.eventLogSize)
	}

	// 2. Top-level default-metric and maximum-prefix
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.default-metric`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `{"bandwidth":50000,"delay":200,"reliability":250,"load":5,"mtu":1400}`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.maximum-prefix`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `{"limit":500,"threshold":80,"warning-only":true}`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	dm := inst.GetAfiDefaultMetric("ipv4-unicast")
	if dm == nil || dm.Bandwidth != 50000 || dm.Delay != 200 || dm.Reliability != 250 || dm.Load != 5 || dm.Mtu != 1400 {
		t.Fatalf("unexpected default-metric: %+v", dm)
	}
	mp := inst.GetAfiMaximumPrefix("ipv4-unicast")
	if mp == nil || mp.Limit != 500 || mp.Threshold != 80 || mp.WarningOnly == nil || !*mp.WarningOnly {
		t.Fatalf("unexpected maximum-prefix: %+v", mp)
	}

	// Verify evaluateRoutePolicyWithDefault uses configured default-metric when policy metric is unset
	pol := &PolicyDef{
		Name:          "export-all",
		DefaultAction: PolicyAction{PolicyResult: "accept"},
	}
	ok, evalMetric := evaluateRoutePolicyWithDefault(CandidateRoute{Prefix: "10.99.0.0/24", RouteType: "static"}, pol, dm)
	if !ok || evalMetric.Bandwidth != 50000 || evalMetric.Delay != 200 || evalMetric.Mtu != 1400 {
		t.Fatalf("expected evaluateRoutePolicyWithDefault to use default-metric fallback, got ok=%v metric=%+v", ok, evalMetric)
	}

	// 3. AFI-level overrides for ipv6-unicast
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv6-unicast"}.traffic-share-balanced`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `false`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv6-unicast"}.default-metric.bandwidth`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `250000`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv6-unicast"}.maximum-prefix.limit`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `1200`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	if inst.GetAfiTrafficShareBalanced("ipv6-unicast") {
		t.Fatal("expected ipv6-unicast trafficShareBalanced override to be false")
	}
	if dm6 := inst.GetAfiDefaultMetric("ipv6-unicast"); dm6 == nil || dm6.Bandwidth != 250000 {
		t.Fatalf("expected ipv6-unicast default-metric bandwidth 250000, got %+v", dm6)
	}
	if mp6 := inst.GetAfiMaximumPrefix("ipv6-unicast"); mp6 == nil || mp6.Limit != 1200 {
		t.Fatalf("expected ipv6-unicast maximum-prefix limit 1200, got %+v", mp6)
	}

	// 4. Interface and default-interface bandwidth-percent
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.default-interface.bandwidth-percent`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `65`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.bandwidth-percent`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `75`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.address-family{.name=="ipv6-unicast"}.bandwidth-percent`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `85`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	d.mu.RLock()
	ic := inst.configuredInterfaces["ethernet-1/1.0"]
	defIntf := inst.defaultIntf
	d.mu.RUnlock()

	if ic == nil || defIntf == nil {
		t.Fatal("expected interface and default-interface to be configured")
	}
	if got := defIntf.GetAfiBandwidthPercent("ipv4-unicast"); got != 65 {
		t.Fatalf("expected default-interface bandwidth-percent 65, got %d", got)
	}
	if got := ic.GetAfiBandwidthPercent("ipv4-unicast", defIntf); got != 75 {
		t.Fatalf("expected interface ipv4-unicast bandwidth-percent 75, got %d", got)
	}
	if got := ic.GetAfiBandwidthPercent("ipv6-unicast", defIntf); got != 85 {
		t.Fatalf("expected interface ipv6-unicast bandwidth-percent 85, got %d", got)
	}

	// Delete interface AF bandwidth-percent -> falls back to interface level (75)
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.address-family{.name=="ipv6-unicast"}.bandwidth-percent`},
		Op:  ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})
	if got := ic.GetAfiBandwidthPercent("ipv6-unicast", defIntf); got != 75 {
		t.Fatalf("expected interface ipv6-unicast bandwidth-percent fallback to 75, got %d", got)
	}

	// Delete interface bandwidth-percent -> falls back to default-interface level (65)
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.bandwidth-percent`},
		Op:  ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})
	if got := ic.GetAfiBandwidthPercent("ipv4-unicast", defIntf); got != 65 {
		t.Fatalf("expected interface bandwidth-percent fallback to 65, got %d", got)
	}
}

func TestEventLogReportAndSizeLimit(t *testing.T) {
	d := &EigrpDaemon{
		instances: make(map[string]*EigrpInstance),
	}
	inst := newEigrpInstance("default")
	inst.eventLogSize = 3
	d.instances["default"] = inst

	d.OnEventLogReport("default", 1, 1000, "DUAL event 1")
	d.OnEventLogReport("default", 2, 2000, "DUAL event 2")
	d.OnEventLogReport("default", 3, 3000, "DUAL event 3")
	d.OnEventLogReport("default", 4, 4000, "DUAL event 4")

	d.mu.RLock()
	evCount := len(inst.eventLog)
	firstID := inst.eventLog[0].ID
	lastID := inst.eventLog[evCount-1].ID
	d.mu.RUnlock()

	if evCount != 3 {
		t.Fatalf("expected eventLog trimmed to size 3, got %d", evCount)
	}
	if firstID != 2 || lastID != 4 {
		t.Fatalf("expected event IDs [2..4], got first=%d last=%d", firstID, lastID)
	}

	// Test Shim wrappers
	_ = ShimInterfaceBandwidthPercentUpdate("default", "ethernet-1/1.0", "ipv4-unicast", 50)
	_ = ShimTrafficShareBalancedUpdate("default", true)
	_ = ShimAutoSummaryUpdate("default", false)
	_ = ShimDefaultMetricUpdate("default", 100000, 100, 255, 1, 1500)
	_ = ShimMaxPrefixUpdate("default", 1000, 75, true)
	_ = ShimEventLogSizeUpdate("default", 500)
	_ = ShimEventLogClear("default")
	ShimEventLogReport("default")
	_ = ShimTopologyClear("default", "")
}

func TestSummaryAddressAndMaxPrefixLeafDeletes(t *testing.T) {
	d := &EigrpDaemon{
		instances: make(map[string]*EigrpInstance),
	}
	inst := newEigrpInstance("default")
	d.instances["default"] = inst

	// 1. Configure interface AF summary-address and update/delete distance leaf
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.address-family{.name=="ipv4-unicast"}.summary-address{.prefix=="10.0.0.0/8"}.distance`,
			Keys:   []string{"default", "ethernet-1/1.0", "ipv4-unicast", "10.0.0.0/8"},
		},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `25`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.mu.RLock()
	ic := inst.configuredInterfaces["ethernet-1/1.0"]
	sas := ic.GetAfiSummaryAddresses("ipv4-unicast")
	d.mu.RUnlock()
	if len(sas) != 1 || sas[0].Prefix != "10.0.0.0/8" || sas[0].Distance != 25 {
		t.Fatalf("expected summary-address 10.0.0.0/8 distance 25, got %+v", sas)
	}

	// Delete distance leaf -> resets distance to default 5 without deleting summary-address
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.address-family{.name=="ipv4-unicast"}.summary-address{.prefix=="10.0.0.0/8"}.distance`,
			Keys:   []string{"default", "ethernet-1/1.0", "ipv4-unicast", "10.0.0.0/8"},
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})
	d.mu.RLock()
	sas = ic.GetAfiSummaryAddresses("ipv4-unicast")
	d.mu.RUnlock()
	if len(sas) != 1 || sas[0].Distance != 5 {
		t.Fatalf("expected summary-address distance reset to 5, got %+v", sas)
	}

	// 2. Configure maximum-prefix with warning-only and threshold, then delete leaves
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.maximum-prefix`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `{"limit": 50, "threshold": 80, "warning-only": true}`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.maximum-prefix.warning-only`},
		Op:  ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.maximum-prefix.threshold`},
		Op:  ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})
	d.mu.RLock()
	mp := inst.maximumPrefix
	d.mu.RUnlock()
	if mp == nil || mp.Limit != 50 || mp.Threshold != 75 || (mp.WarningOnly != nil && *mp.WarningOnly) {
		t.Fatalf("expected maximum-prefix limit=50 threshold=75 warning-only=false, got %+v", mp)
	}
}

func TestContainerUpdateYangDefaultNonShadowing(t *testing.T) {
	d := &EigrpDaemon{
		instances: make(map[string]*EigrpInstance),
	}
	inst := newEigrpInstance("default")
	d.instances["default"] = inst

	// Simulate SR Linux cfg_mgr top-level container notification where address-family and interface include YANG defaults
	topJSON := `{
		"admin-state": "SRL_NOKIA_COMMON_ADMIN_STATE_ENABLE",
		"autonomous-system": 100,
		"router-id": "10.0.0.1",
		"preference": 110,
		"external-preference": 180,
		"traffic-share-balanced": true,
		"auto-summary": true,
		"default-metric": {"bandwidth": 50000, "delay": 200, "reliability": 250, "load": 5, "mtu": 1400},
		"maximum-prefix": {"limit": 500, "threshold": 80, "warning-only": true},
		"default-interface": {
			"admin-state": "SRL_NOKIA_COMMON_ADMIN_STATE_ENABLE",
			"bandwidth-percent": 65,
			"address-family": [
				{"name": "ipv4-unicast", "admin-state": "SRL_NOKIA_COMMON_ADMIN_STATE_ENABLE", "bandwidth-percent": 50}
			]
		},
		"address-family": [
			{
				"name": "ipv4-unicast",
				"admin-state": "SRL_NOKIA_COMMON_ADMIN_STATE_ENABLE",
				"preference": 90,
				"external-preference": 170,
				"traffic-share-balanced": false,
				"auto-summary": false,
				"default-metric": {"bandwidth": 100000, "delay": 100, "reliability": 255, "load": 1, "mtu": 1500},
				"maximum-prefix": {"threshold": 75, "warning-only": false}
			}
		]
	}`
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: topJSON}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	if got := inst.GetAfiPreference("ipv4-unicast"); got != 110 {
		t.Fatalf("expected ipv4-unicast preference 110 (inherited from top-level), got %d", got)
	}
	if got := inst.GetAfiExternalPreference("ipv4-unicast"); got != 180 {
		t.Fatalf("expected ipv4-unicast external-preference 180 (inherited from top-level), got %d", got)
	}
	if !inst.GetAfiTrafficShareBalanced("ipv4-unicast") {
		t.Fatal("expected ipv4-unicast traffic-share-balanced true (inherited from top-level)")
	}
	if !inst.GetAfiAutoSummary("ipv4-unicast") {
		t.Fatal("expected ipv4-unicast auto-summary true (inherited from top-level)")
	}
	if dm := inst.GetAfiDefaultMetric("ipv4-unicast"); dm == nil || dm.Bandwidth != 50000 || dm.Delay != 200 {
		t.Fatalf("expected ipv4-unicast default-metric inherited from top-level, got %+v", dm)
	}
	if mp := inst.GetAfiMaximumPrefix("ipv4-unicast"); mp == nil || mp.Limit != 500 || mp.Threshold != 80 {
		t.Fatalf("expected ipv4-unicast maximum-prefix inherited from top-level, got %+v", mp)
	}

	// Simulate interface container notification with YANG default bandwidth-percent 50
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}`,
			Keys:   []string{"default", "ethernet-1/1.0"},
		},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `{
			"admin-state": "SRL_NOKIA_COMMON_ADMIN_STATE_ENABLE",
			"bandwidth-percent": 50,
			"address-family": [
				{"name": "ipv4-unicast", "admin-state": "SRL_NOKIA_COMMON_ADMIN_STATE_ENABLE", "bandwidth-percent": 50}
			]
		}`}},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	d.mu.RLock()
	ic := inst.configuredInterfaces["ethernet-1/1.0"]
	defIntf := inst.defaultIntf
	d.mu.RUnlock()
	if got := ic.GetAfiBandwidthPercent("ipv4-unicast", defIntf); got != 65 {
		t.Fatalf("expected interface ipv4-unicast bandwidth-percent 65 (inherited from default-interface), got %d", got)
	}

	// Now update interface container with bandwidth-percent 75 while AF still has YANG default 50
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}`,
			Keys:   []string{"default", "ethernet-1/1.0"},
		},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `{
			"admin-state": "SRL_NOKIA_COMMON_ADMIN_STATE_ENABLE",
			"bandwidth-percent": 75,
			"address-family": [
				{"name": "ipv4-unicast", "admin-state": "SRL_NOKIA_COMMON_ADMIN_STATE_ENABLE", "bandwidth-percent": 50}
			]
		}`}},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	d.mu.RLock()
	ic = inst.configuredInterfaces["ethernet-1/1.0"]
	d.mu.RUnlock()
	if got := ic.GetAfiBandwidthPercent("ipv4-unicast", defIntf); got != 75 {
		t.Fatalf("expected interface ipv4-unicast bandwidth-percent 75 (inherited from interface), got %d", got)
	}
}
