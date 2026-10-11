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
