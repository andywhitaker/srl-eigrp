package main

import (
	"encoding/json"
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
	if v := inst.GetAfiVariance("ipv4-unicast"); v != 1 {
		t.Fatalf("expected default variance to be 1, got %d", v)
	}

	// Set variance > 1 per AFI
	inst.addressFamily = []AddressFamilyConfig{
		{Name: "ipv4-unicast", Variance: 2},
		{Name: "ipv6-unicast", Variance: 128},
	}
	if v := inst.GetAfiVariance("ipv4-unicast"); v != 2 {
		t.Fatalf("expected ipv4-unicast variance 2, got %d", v)
	}
	if v := inst.GetAfiVariance("ipv6-unicast"); v != 128 {
		t.Fatalf("expected ipv6-unicast variance 128, got %d", v)
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
	// Sub-path direct value under address-family
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: ".network_instance{.name==\"default\"}.protocols.eigrp.address-family{.name==\"ipv4-unicast\"}.variance",
		},
		Data: &ndk.ConfigData{
			DataType: &ndk.ConfigData_Json{
				Json: "2",
			},
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	inst := d.GetInstance(netinst)
	if inst == nil || inst.GetAfiVariance("ipv4-unicast") != 2 {
		t.Fatalf("expected variance 2, got %v", inst)
	}

	// Sub-path JSON wrapper
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: ".network_instance{.name==\"default\"}.protocols.eigrp.address-family{.name==\"ipv4-unicast\"}.variance",
		},
		Data: &ndk.ConfigData{
			DataType: &ndk.ConfigData_Json{
				Json: "{\"variance\": 4}",
			},
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_UPDATE,
	})

	if v := inst.GetAfiVariance("ipv4-unicast"); v != 4 {
		t.Fatalf("expected variance 4, got %d", v)
	}

	// Sub-path DELETE resets to 1
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: ".network_instance{.name==\"default\"}.protocols.eigrp.address-family{.name==\"ipv4-unicast\"}.variance",
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})

	if v := inst.GetAfiVariance("ipv4-unicast"); v != 1 {
		t.Fatalf("expected variance reset to 1 on delete, got %d", v)
	}
}

func TestConfig_PreferenceSubPaths(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		routeWorkers: make(map[string]*routeQueueWorker),
	}
	netinst := "default"

	// 1. Preference create under address-family
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: ".network_instance{.name==\"default\"}.protocols.eigrp.address-family{.name==\"ipv4-unicast\"}.preference",
		},
		Data: &ndk.ConfigData{
			DataType: &ndk.ConfigData_Json{
				Json: "110",
			},
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	inst := d.GetInstance(netinst)
	if inst == nil || inst.GetAfiPreference("ipv4-unicast") != 110 {
		t.Fatalf("expected preference 110, got %v", inst)
	}

	// 2. External Preference create under address-family
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: ".network_instance{.name==\"default\"}.protocols.eigrp.address-family{.name==\"ipv4-unicast\"}.external-preference",
		},
		Data: &ndk.ConfigData{
			DataType: &ndk.ConfigData_Json{
				Json: "180",
			},
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	if ep := inst.GetAfiExternalPreference("ipv4-unicast"); ep != 180 {
		t.Fatalf("expected externalPreference 180, got %d", ep)
	}

	// 3. Delete preference resets to 90
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: ".network_instance{.name==\"default\"}.protocols.eigrp.address-family{.name==\"ipv4-unicast\"}.preference",
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})
	if p := inst.GetAfiPreference("ipv4-unicast"); p != 90 {
		t.Fatalf("expected preference reset to 90, got %d", p)
	}

	// 4. Delete external-preference resets to 170
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: ".network_instance{.name==\"default\"}.protocols.eigrp.address-family{.name==\"ipv4-unicast\"}.external-preference",
		},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})
	if ep := inst.GetAfiExternalPreference("ipv4-unicast"); ep != 170 {
		t.Fatalf("expected externalPreference reset to 170, got %d", ep)
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

	// Create summary-address on interface ethernet-1/1.0 address-family ipv4-unicast
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath:         ".network_instance{.name==\"default\"}.protocols.eigrp.interface{.interface-name==\"ethernet-1/1.0\"}.address-family{.name==\"ipv4-unicast\"}.summary-address{.prefix==\"10.50.0.0/16\"}",
			JsPathWithKeys: ".network_instance{.name==\"default\"}.protocols.eigrp.interface{.interface-name==\"ethernet-1/1.0\"}.address-family{.name==\"ipv4-unicast\"}.summary-address{.prefix==\"10.50.0.0/16\"}",
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
			JsPath:         ".network_instance{.name==\"default\"}.protocols.eigrp.interface{.interface-name==\"ethernet-1/1.0\"}.address-family{.name==\"ipv4-unicast\"}.summary-address{.prefix==\"10.50.0.0/16\"}",
			JsPathWithKeys: ".network_instance{.name==\"default\"}.protocols.eigrp.interface{.interface-name==\"ethernet-1/1.0\"}.address-family{.name==\"ipv4-unicast\"}.summary-address{.prefix==\"10.50.0.0/16\"}",
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

	// 1. Per-AFI traffic-share-balanced, auto-summary, maximum-paths, maximum-hops, import-policy, and top-level event-log-size
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv4-unicast"}.traffic-share-balanced`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `true`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv4-unicast"}.auto-summary`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `true`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv4-unicast"}.maximum-paths`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `8`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv4-unicast"}.maximum-hops`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `50`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv4-unicast"}.import-policy`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `"import-v4"`}},
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
	if !inst.GetAfiTrafficShareBalanced("ipv4-unicast") {
		t.Fatal("expected ipv4-unicast trafficShareBalanced to be true")
	}
	if !inst.GetAfiAutoSummary("ipv4-unicast") {
		t.Fatal("expected ipv4-unicast autoSummary to be true")
	}
	if mp := inst.GetAfiMaximumPaths("ipv4-unicast"); mp != 8 {
		t.Fatalf("expected ipv4-unicast maximum-paths 8, got %d", mp)
	}
	if mh := inst.GetAfiMaximumHops("ipv4-unicast"); mh != 50 {
		t.Fatalf("expected ipv4-unicast maximum-hops 50, got %d", mh)
	}
	if ip := inst.GetAfiImportPolicy("ipv4-unicast"); ip != "import-v4" {
		t.Fatalf("expected ipv4-unicast import-policy import-v4, got %s", ip)
	}
	if inst.eventLogSize != 1000 {
		t.Fatalf("expected eventLogSize 1000, got %d", inst.eventLogSize)
	}

	// 2. Per-AFI default-metric and maximum-prefix on ipv4-unicast
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv4-unicast"}.default-metric`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `{"bandwidth":50000,"delay":200,"reliability":250,"load":5,"mtu":1400}`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv4-unicast"}.maximum-prefix`},
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

	// 3. AFI-level independent config for ipv6-unicast
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

	// 4. Interface and default-interface address-family bandwidth-percent inheritance
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.default-interface.address-family{.name=="ipv4-unicast"}.bandwidth-percent`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `65`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.default-interface.address-family{.name=="ipv6-unicast"}.bandwidth-percent`},
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
		t.Fatalf("expected default-interface ipv4-unicast bandwidth-percent 65, got %d", got)
	}
	if got := ic.GetAfiBandwidthPercent("ipv4-unicast", defIntf); got != 65 {
		t.Fatalf("expected interface ipv4-unicast bandwidth-percent inherited from default-interface (65), got %d", got)
	}
	if got := ic.GetAfiBandwidthPercent("ipv6-unicast", defIntf); got != 85 {
		t.Fatalf("expected interface ipv6-unicast bandwidth-percent 85, got %d", got)
	}

	// Delete interface AF bandwidth-percent -> falls back to default-interface AF level (75)
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.address-family{.name=="ipv6-unicast"}.bandwidth-percent`},
		Op:  ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})
	if got := ic.GetAfiBandwidthPercent("ipv6-unicast", defIntf); got != 75 {
		t.Fatalf("expected interface ipv6-unicast bandwidth-percent fallback to default-interface AF (75), got %d", got)
	}

	// Delete default-interface AF bandwidth-percent -> falls back to YANG default (50)
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.default-interface.address-family{.name=="ipv4-unicast"}.bandwidth-percent`},
		Op:  ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})
	if got := ic.GetAfiBandwidthPercent("ipv4-unicast", defIntf); got != 50 {
		t.Fatalf("expected interface ipv4-unicast bandwidth-percent fallback to 50, got %d", got)
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
	_ = ShimTrafficShareBalancedUpdate("default", "ipv4-unicast", true)
	_ = ShimAutoSummaryUpdate("default", "ipv4-unicast", false)
	_ = ShimDefaultMetricUpdate("default", "ipv4-unicast", 100000, 100, 255, 1, 1500)
	_ = ShimMaxPrefixUpdate("default", "ipv4-unicast", 1000, 75, true)
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

	// 2. Configure maximum-prefix with warning-only and threshold under address-family, then delete leaves
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv4-unicast"}.maximum-prefix`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `{"limit": 50, "threshold": 80, "warning-only": true}`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv4-unicast"}.maximum-prefix.warning-only`},
		Op:  ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv4-unicast"}.maximum-prefix.threshold`},
		Op:  ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})
	mp := inst.GetAfiMaximumPrefix("ipv4-unicast")
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

	// Simulate SR Linux cfg_mgr top-level container notification with default-interface AF and address-family settings
	topJSON := `{
		"admin-state": "SRL_NOKIA_COMMON_ADMIN_STATE_ENABLE",
		"autonomous-system": 100,
		"router-id": "10.0.0.1",
		"default-interface": {
			"admin-state": "SRL_NOKIA_COMMON_ADMIN_STATE_ENABLE",
			"bandwidth": 250000,
			"delay": 50,
			"address-family": [
				{
					"name": "ipv4-unicast",
					"admin-state": "SRL_NOKIA_COMMON_ADMIN_STATE_ENABLE",
					"hello-interval": 10,
					"hold-time": 30,
					"bandwidth-percent": 65,
					"passive": true,
					"split-horizon": false,
					"next-hop-self": true
				}
			]
		},
		"address-family": [
			{
				"name": "ipv4-unicast",
				"admin-state": "SRL_NOKIA_COMMON_ADMIN_STATE_ENABLE",
				"preference": 110,
				"external-preference": 180,
				"variance": 3,
				"maximum-paths": 8,
				"maximum-hops": 60,
				"traffic-share-balanced": true,
				"auto-summary": true,
				"default-metric": {"bandwidth": 50000, "delay": 200, "reliability": 250, "load": 5, "mtu": 1400},
				"maximum-prefix": {"limit": 500, "threshold": 80, "warning-only": true}
			}
		]
	}`
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: topJSON}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	if got := inst.GetAfiPreference("ipv4-unicast"); got != 110 {
		t.Fatalf("expected ipv4-unicast preference 110, got %d", got)
	}
	if got := inst.GetAfiExternalPreference("ipv4-unicast"); got != 180 {
		t.Fatalf("expected ipv4-unicast external-preference 180, got %d", got)
	}
	if got := inst.GetAfiVariance("ipv4-unicast"); got != 3 {
		t.Fatalf("expected ipv4-unicast variance 3, got %d", got)
	}
	if got := inst.GetAfiMaximumPaths("ipv4-unicast"); got != 8 {
		t.Fatalf("expected ipv4-unicast maximum-paths 8, got %d", got)
	}
	if got := inst.GetAfiMaximumHops("ipv4-unicast"); got != 60 {
		t.Fatalf("expected ipv4-unicast maximum-hops 60, got %d", got)
	}
	if !inst.GetAfiTrafficShareBalanced("ipv4-unicast") {
		t.Fatal("expected ipv4-unicast traffic-share-balanced true")
	}
	if !inst.GetAfiAutoSummary("ipv4-unicast") {
		t.Fatal("expected ipv4-unicast auto-summary true")
	}
	if dm := inst.GetAfiDefaultMetric("ipv4-unicast"); dm == nil || dm.Bandwidth != 50000 || dm.Delay != 200 {
		t.Fatalf("expected ipv4-unicast default-metric 50000/200, got %+v", dm)
	}
	if mp := inst.GetAfiMaximumPrefix("ipv4-unicast"); mp == nil || mp.Limit != 500 || mp.Threshold != 80 {
		t.Fatalf("expected ipv4-unicast maximum-prefix 500/80, got %+v", mp)
	}

	// Simulate interface container notification where AF includes YANG defaults (e.g. bandwidth-percent 50, hello-interval 5)
	// which must NOT shadow default-interface AF settings (bandwidth-percent 65, hello-interval 10)!
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{
			JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}`,
			Keys:   []string{"default", "ethernet-1/1.0"},
		},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `{
			"admin-state": "SRL_NOKIA_COMMON_ADMIN_STATE_ENABLE",
			"address-family": [
				{
					"name": "ipv4-unicast",
					"admin-state": "SRL_NOKIA_COMMON_ADMIN_STATE_ENABLE",
					"hello-interval": 5,
					"hold-time": 15,
					"bandwidth-percent": 50,
					"passive": false,
					"split-horizon": true,
					"next-hop-self": false
				}
			]
		}`}},
		Op: ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	d.mu.RLock()
	ic := inst.configuredInterfaces["ethernet-1/1.0"]
	defIntf := inst.defaultIntf
	d.mu.RUnlock()
	if got := ic.GetAfiBandwidthPercent("ipv4-unicast", defIntf); got != 65 {
		t.Fatalf("expected interface ipv4-unicast bandwidth-percent 65 (inherited from default-interface AF), got %d", got)
	}
	if got := ic.GetAfiHelloInterval("ipv4-unicast", defIntf); got != 10 {
		t.Fatalf("expected interface ipv4-unicast hello-interval 10 (inherited from default-interface AF), got %d", got)
	}
	if got := ic.GetAfiHoldTime("ipv4-unicast", defIntf); got != 30 {
		t.Fatalf("expected interface ipv4-unicast hold-time 30 (inherited from default-interface AF), got %d", got)
	}
	if !ic.IsAfiPassive("ipv4-unicast", defIntf.IsAfiPassive("ipv4-unicast")) {
		t.Fatal("expected interface ipv4-unicast passive true (inherited from default-interface AF)")
	}
	if ic.GetAfiSplitHorizon("ipv4-unicast", defIntf) {
		t.Fatal("expected interface ipv4-unicast split-horizon false (inherited from default-interface AF)")
	}
	if !ic.GetAfiNextHopSelf("ipv4-unicast", defIntf) {
		t.Fatal("expected interface ipv4-unicast next-hop-self true (inherited from default-interface AF)")
	}
	if bw := ic.GetBandwidth(defIntf); bw == nil || *bw != 250000 {
		t.Fatalf("expected interface bandwidth 250000 (inherited from default-interface), got %v", bw)
	}
	if del := ic.GetDelay(defIntf); del == nil || *del != 50 {
		t.Fatalf("expected interface delay 50 (inherited from default-interface), got %v", del)
	}
}

func TestReconcileImportedRoutes_UpdatesPreferenceAndAppliesImportPolicy(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		routeWorkers: make(map[string]*routeQueueWorker),
		policyDefs:   make(map[string]*PolicyDef),
	}
	netinst := "default"
	inst := newEigrpInstance(netinst)
	inst.asn = 100
	d.instances[netinst] = inst

	// Add internal and external routes with default preferences (90 and 170)
	d.OnRouteAdd(netinst, "10.10.1.0/24", "10.0.0.2", 1000, 128000, false, 90, "ethernet-1/1.0")
	d.OnRouteAdd(netinst, "172.16.1.0/24", "10.0.0.2", 2000, 256000, true, 170, "ethernet-1/1.0")

	d.mu.RLock()
	rInt := inst.routes["10.10.1.0/24"]
	rExt := inst.routes["172.16.1.0/24"]
	d.mu.RUnlock()
	if rInt == nil || rInt.Preference != 90 {
		t.Fatalf("expected initial internal route preference 90, got %+v", rInt)
	}
	if rExt == nil || rExt.Preference != 170 {
		t.Fatalf("expected initial external route preference 170, got %+v", rExt)
	}

	// Update ipv4-unicast preference to 110 and external-preference to 180
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv4-unicast"}.preference`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `110`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv4-unicast"}.external-preference`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `180`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	d.mu.RLock()
	rInt = inst.routes["10.10.1.0/24"]
	rExt = inst.routes["172.16.1.0/24"]
	d.mu.RUnlock()
	if rInt == nil || rInt.Preference != 110 {
		t.Fatalf("expected reconciled internal route preference 110, got %+v", rInt)
	}
	if rExt == nil || rExt.Preference != 180 {
		t.Fatalf("expected reconciled external route preference 180, got %+v", rExt)
	}

	// Delete preference and external-preference -> routes must revert to 90 and 170
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv4-unicast"}.preference`},
		Op:  ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv4-unicast"}.external-preference`},
		Op:  ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})

	d.mu.RLock()
	rInt = inst.routes["10.10.1.0/24"]
	rExt = inst.routes["172.16.1.0/24"]
	d.mu.RUnlock()
	if rInt == nil || rInt.Preference != 90 {
		t.Fatalf("expected reverted internal route preference 90, got %+v", rInt)
	}
	if rExt == nil || rExt.Preference != 170 {
		t.Fatalf("expected reverted external route preference 170, got %+v", rExt)
	}

	// Configure reject-all import-policy -> routes must be withdrawn from inst.routes
	d.mu.Lock()
	d.policyDefs["deny-all"] = &PolicyDef{
		Name:          "deny-all",
		DefaultAction: PolicyAction{PolicyResult: "reject"},
	}
	d.mu.Unlock()
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv4-unicast"}.import-policy`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `"deny-all"`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	d.mu.RLock()
	routeCountAfterDeny := len(inst.routes)
	d.mu.RUnlock()
	if routeCountAfterDeny != 0 {
		t.Fatalf("expected 0 routes installed after reject import-policy, got %d", routeCountAfterDeny)
	}

	// Delete import-policy -> routes must be re-installed from learnedRoutes
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv4-unicast"}.import-policy`},
		Op:  ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})
	d.mu.RLock()
	routeCountAfterDelete := len(inst.routes)
	d.mu.RUnlock()
	if routeCountAfterDelete != 2 {
		t.Fatalf("expected 2 routes restored after deleting import-policy, got %d", routeCountAfterDelete)
	}
}

func TestInterfaceAfiBfdAndAuthSubPathMergeAndDelete(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		learnedVlans: make(map[string]uint16),
	}
	inst := newEigrpInstance("default")
	d.instances["default"] = inst

	// 1. Configure interface AF admin-state enable, then configure bfd admin-state enable, tx-interval, multiplier via leaf notifications
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.address-family{.name=="ipv4-unicast"}.admin-state`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `"enable"`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.address-family{.name=="ipv4-unicast"}.bfd.admin-state`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `"enable"`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.address-family{.name=="ipv4-unicast"}.bfd.desired-minimum-tx-interval`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `250000`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.address-family{.name=="ipv4-unicast"}.bfd.detection-multiplier`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `5`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	d.mu.RLock()
	ic := inst.configuredInterfaces["ethernet-1/1.0"]
	bfd := ic.GetAfiBfd("ipv4-unicast", nil)
	d.mu.RUnlock()
	if bfd == nil || bfd.AdminState != "enable" || bfd.DesiredMinimumTxInterval == nil || *bfd.DesiredMinimumTxInterval != 250000 || bfd.DetectionMultiplier == nil || *bfd.DetectionMultiplier != 5 {
		t.Fatalf("unexpected bfd config after leaf updates: %+v", bfd)
	}

	// Setting bfd.admin-state to disable MUST NOT disable the interface AF admin-state!
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.address-family{.name=="ipv4-unicast"}.bfd.admin-state`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `"disable"`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_UPDATE,
	})
	d.mu.RLock()
	afEnabled := ic.IsAfiEnabled("ipv4-unicast", nil)
	bfd = ic.GetAfiBfd("ipv4-unicast", nil)
	d.mu.RUnlock()
	if !afEnabled {
		t.Fatal("disabling bfd.admin-state unexpectedly disabled interface address-family admin-state")
	}
	if bfd == nil || bfd.AdminState != "disable" {
		t.Fatalf("expected bfd.AdminState disable, got %+v", bfd)
	}

	// Delete only bfd.detection-multiplier -> DesiredMinimumTxInterval must be preserved
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.address-family{.name=="ipv4-unicast"}.bfd.detection-multiplier`},
		Op:  ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})
	d.mu.RLock()
	bfd = ic.GetAfiBfd("ipv4-unicast", nil)
	d.mu.RUnlock()
	if bfd == nil || bfd.DetectionMultiplier != nil || bfd.DesiredMinimumTxInterval == nil || *bfd.DesiredMinimumTxInterval != 250000 {
		t.Fatalf("expected detection-multiplier nil and tx-interval 250000 preserved, got %+v", bfd)
	}

	// 2. Configure authentication leaves individually, then delete authentication-key leaf
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.address-family{.name=="ipv4-unicast"}.authentication.mode`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `"md5"`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.address-family{.name=="ipv4-unicast"}.authentication.keychain`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `"kc-md5"`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.address-family{.name=="ipv4-unicast"}.authentication.authentication-key`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `"secret"`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.address-family{.name=="ipv4-unicast"}.authentication.authentication-key`},
		Op:  ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})
	d.mu.RLock()
	auth := ic.GetAfiAuthentication("ipv4-unicast", nil)
	d.mu.RUnlock()
	if auth == nil || auth.Mode != "md5" || auth.Keychain != "kc-md5" || auth.AuthenticationKey != "" {
		t.Fatalf("expected auth mode=md5 keychain=kc-md5 auth-key=\"\", got %+v", auth)
	}
}

func TestDefaultMetricLeafDeleteAndBuildInterfaceData(t *testing.T) {
	d := &EigrpDaemon{
		instances: make(map[string]*EigrpInstance),
	}
	inst := newEigrpInstance("default")
	d.instances["default"] = inst

	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv4-unicast"}.default-metric`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `{"bandwidth":250000,"delay":200,"reliability":255,"load":1,"mtu":1500}`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.address-family{.name=="ipv4-unicast"}.default-metric.delay`},
		Op:  ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})
	dm := inst.GetAfiDefaultMetric("ipv4-unicast")
	if dm == nil || dm.Bandwidth != 250000 || dm.Delay != 100 {
		t.Fatalf("expected default-metric bandwidth=250000 delay=100 after deleting delay leaf, got %+v", dm)
	}

	tf := &TrafficInfo{ReliableMcast: 5, UnreliableMcast: 20}
	intfData := buildInterfaceData("ethernet-1/1.0", "10.0.0.1", 30, "up", nil, nil, "up", tf)
	if intfData["ip-address"] != "10.0.0.1" || intfData["prefix-length"] != uint32(30) {
		t.Fatalf("expected buildInterfaceData to include ip-address=10.0.0.1 and prefix-length=30, got %+v", intfData)
	}
	stats, ok := intfData["statistics"].(map[string]interface{})
	if !ok || stats["unreliable-multicast"] != uint64(20) {
		t.Fatalf("expected interface statistics unreliable-multicast=20, got %+v", intfData["statistics"])
	}
}

func TestTwoLevelAdminStateInheritance(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		learnedVlans: make(map[string]uint16),
	}
	inst := newEigrpInstance("default")
	d.instances["default"] = inst

	// 1. Configure default-interface/address-family[ipv6-unicast]/admin-state = "disable"
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.default-interface.address-family{.name=="ipv6-unicast"}.admin-state`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `"disable"`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	// Configure link-level interface ethernet-1/1.0/admin-state = "enable"
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.admin-state`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `"enable"`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})

	d.mu.RLock()
	ic := inst.configuredInterfaces["ethernet-1/1.0"]
	defIntf := inst.defaultIntf
	d.mu.RUnlock()

	if ic == nil || defIntf == nil {
		t.Fatal("expected ic and defIntf to be non-nil")
	}

	// Verify ipv4-unicast is enabled, but ipv6-unicast remains disabled (inherited from default-interface AF)
	if !ic.IsAfiEnabled("ipv4-unicast", defIntf) {
		t.Fatal("expected ipv4-unicast to be enabled")
	}
	if ic.IsAfiEnabled("ipv6-unicast", defIntf) {
		t.Fatal("expected ipv6-unicast to remain disabled when only link-level interface admin-state=enable is configured")
	}

	// Verify publishInterfaceSublists also reports admin-state="disable" for ipv6-unicast (both when ic != nil and ic == nil)
	for _, testIc := range []*InterfaceConfig{ic, nil} {
		keys := make(map[string]struct{})
		var states []*ndk.TelemetryInfo
		publishInterfaceSublists("default", "ethernet-1/1.0", "up", defIntf, testIc, "up", nil, nil, nil, keys, &states)
		var v6Admin string
		for _, st := range states {
			if st.Key.JsPath == `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.address-family{.name=="ipv6-unicast"}` {
				var m map[string]interface{}
				if err := json.Unmarshal([]byte(st.Data.JsonContent), &m); err != nil {
					t.Fatalf("failed to unmarshal telemetry JSON: %v", err)
				}
				v6Admin, _ = m["admin-state"].(string)
			}
		}
		if v6Admin != "disable" {
			t.Fatalf("expected telemetry ipv6-unicast admin-state=disable (ic=%v), got %q", testIc, v6Admin)
		}
	}

	// 2. Explicitly configure interface ethernet-1/1.0/address-family[ipv6-unicast]/admin-state = "enable" -> overrides default-interface AF disable
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.address-family{.name=="ipv6-unicast"}.admin-state`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `"enable"`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	if !ic.IsAfiEnabled("ipv6-unicast", defIntf) {
		t.Fatal("expected ipv6-unicast to be enabled when interface AF admin-state=enable is explicitly configured")
	}

	// 3. Configure default-interface/admin-state = "disable"
	// Since ethernet-1/1.0 has link-level admin-state = "enable" explicitly configured, it overrides default-interface/admin-state = "disable"
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.default-interface.admin-state`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `"disable"`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	if got := ic.GetAdminState(defIntf); got != "enable" {
		t.Fatalf("expected interface link-level admin-state=enable to override default-interface admin-state=disable, got %q", got)
	}
	if !ic.IsAfiEnabled("ipv4-unicast", defIntf) {
		t.Fatal("expected ipv4-unicast on ethernet-1/1.0 to remain enabled when link-level admin-state=enable overrides default-interface admin-state=disable")
	}

	// Delete link-level admin-state on ethernet-1/1.0 -> now inherits default-interface/admin-state = "disable"
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.admin-state`},
		Op:  ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})
	if got := ic.GetAdminState(defIntf); got != "disable" {
		t.Fatalf("expected interface link-level admin-state to inherit disable after deleting interface admin-state, got %q", got)
	}
	if ic.IsAfiEnabled("ipv4-unicast", defIntf) || ic.IsAfiEnabled("ipv6-unicast", defIntf) {
		t.Fatal("expected both AFs to be disabled when inherited link-level admin-state is disable")
	}

	// 4. Re-enable default-interface/admin-state = "enable", delete interface AF ipv6-unicast override (so ipv6-unicast is disabled via default-interface AF),
	// and verify OnInterfaceReport for IPv6 does NOT overwrite link-level InterfaceInfo.AdminState to "disable".
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.default-interface.admin-state`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `"enable"`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_UPDATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key: &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.address-family{.name=="ipv6-unicast"}.admin-state`},
		Op:  ndk.SdkMgrOperation_SDK_MGR_OPERATION_DELETE,
	})
	d.OnInterfaceReport("default", "ethernet-1/1.0", "10.0.0.1", 30, "up")
	d.OnInterfaceReport("default", "ethernet-1/1.0", "2001:db8::1", 64, "up")
	d.mu.RLock()
	ifInfo := inst.interfaces["ethernet-1/1.0"]
	d.mu.RUnlock()
	if ifInfo == nil || ifInfo.AdminState != "enable" || ifInfo.OperState != "up" {
		t.Fatalf("expected link-level InterfaceInfo AdminState=enable OperState=up when only ipv6-unicast AF is disabled, got %+v", ifInfo)
	}

	// 5. Verify container notifications carrying YANG default "enable" do NOT clobber prior leaf notifications ("disable")
	// and .default-interface container update for ipv4-unicast does NOT wipe out ipv6-unicast entry.
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.default-interface`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `{"admin-state":"SRL_NOKIA_COMMON_ADMIN_STATE_ENABLE","address-family":[{"name":"ipv4-unicast","admin-state":"SRL_NOKIA_COMMON_ADMIN_STATE_ENABLE","hello-interval":10}]}`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_UPDATE,
	})
	if ic.IsAfiEnabled("ipv6-unicast", inst.defaultIntf) {
		t.Fatal("expected default-interface ipv6-unicast admin-state=disable to survive .default-interface container update for ipv4-unicast")
	}

	// Leaf notification sets interface ethernet-1/1.0 ipv4-unicast admin-state = "disable", followed by container notification with YANG default enable
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.address-family{.name=="ipv4-unicast"}.admin-state`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `"disable"`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_CREATE,
	})
	d.HandleConfigNotification(&ndk.ConfigNotification{
		Key:  &ndk.ConfigKey{JsPath: `.network_instance{.name=="default"}.protocols.eigrp.interface{.interface-name=="ethernet-1/1.0"}.address-family{.name=="ipv4-unicast"}`},
		Data: &ndk.ConfigData{DataType: &ndk.ConfigData_Json{Json: `{"name":"ipv4-unicast","admin-state":"SRL_NOKIA_COMMON_ADMIN_STATE_ENABLE","hello-interval":7}`}},
		Op:   ndk.SdkMgrOperation_SDK_MGR_OPERATION_UPDATE,
	})
	if ic.IsAfiEnabled("ipv4-unicast", inst.defaultIntf) {
		t.Fatal("expected leaf-configured interface AF admin-state=disable not to be overwritten by container YANG default enable")
	}
	if got := ic.GetAfiHelloInterval("ipv4-unicast", inst.defaultIntf); got != 7 {
		t.Fatalf("expected interface AF hello-interval=7 from container merge, got %d", got)
	}
}
