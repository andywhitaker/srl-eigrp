package main

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestRouteQueue_StrictFIFOOrdering(t *testing.T) {
	worker := &routeQueueWorker{
		queue: make(chan routeEvent, 200),
		stop:  make(chan struct{}),
	}

	const eventCount = 100
	var processed []routeEvent
	var mu sync.Mutex
	done := make(chan struct{})

	// Dedicated single consumer (like runRouteWorker)
	go func() {
		for {
			select {
			case ev := <-worker.queue:
				mu.Lock()
				processed = append(processed, ev)
				if len(processed) == eventCount {
					mu.Unlock()
					close(done)
					return
				}
				mu.Unlock()
			case <-time.After(3 * time.Second):
				close(done)
				return
			}
		}
	}()

	// Enqueue flapping events: Add, Del, Add, Del...
	for i := 0; i < eventCount; i++ {
		pfx := fmt.Sprintf("192.168.%d.0/24", i/2)
		if i%2 == 0 {
			worker.queue <- routeEvent{
				eventType:  routeEventAdd,
				netinst:    "default",
				prefix:     pfx,
				nexthop:    "10.0.0.1",
				metric:     uint32(i),
				wideMetric: uint64(i * 100),
				isExt:      false,
			}
		} else {
			worker.queue <- routeEvent{
				eventType: routeEventDel,
				netinst:   "default",
				prefix:    pfx,
			}
		}
	}

	<-done

	mu.Lock()
	defer mu.Unlock()
	if len(processed) != eventCount {
		t.Fatalf("expected %d processed events, got %d", eventCount, len(processed))
	}

	for i, ev := range processed {
		expectedType := routeEventAdd
		if i%2 != 0 {
			expectedType = routeEventDel
		}
		if ev.eventType != expectedType {
			t.Fatalf("event %d: expected type %v, got %v", i, expectedType, ev.eventType)
		}
		if expectedType == routeEventAdd && ev.metric != uint32(i) {
			t.Fatalf("event %d: expected metric %d, got %d", i, i, ev.metric)
		}
	}
}

func TestRouteWorker_EnqueueAndProcess(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		routeWorkers: make(map[string]*routeQueueWorker),
	}

	netinst := "default"
	pfx := "10.200.1.0/24"

	// Test EnqueueRouteAdd
	d.EnqueueRouteAdd(netinst, pfx, "10.0.0.1", 100, 1000, false, 90)

	// Wait for worker to process
	time.Sleep(50 * time.Millisecond)

	inst := d.GetInstance(netinst)
	if inst == nil {
		t.Fatal("expected instance to be created")
	}

	d.mu.RLock()
	route, ok := inst.routes[pfx]
	d.mu.RUnlock()
	if !ok || route == nil {
		t.Fatalf("expected route %s to be installed in RIB", pfx)
	}
	if route.NextHop != "10.0.0.1" || route.Metric != 100 {
		t.Fatalf("unexpected route info: %+v", route)
	}

	// Test EnqueueRouteDel
	d.EnqueueRouteDel(netinst, pfx)

	// Wait for worker to process
	time.Sleep(50 * time.Millisecond)

	d.mu.RLock()
	_, ok = inst.routes[pfx]
	d.mu.RUnlock()
	if ok {
		t.Fatalf("expected route %s to be deleted from RIB", pfx)
	}

	d.StopRouteWorker(netinst)
}

func TestRouteWorker_PerNetworkInstanceIsolation(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		routeWorkers: make(map[string]*routeQueueWorker),
	}

	w1 := d.getOrCreateRouteWorker("default")
	w2 := d.getOrCreateRouteWorker("vrf-red")

	if w1 == w2 {
		t.Fatal("expected distinct workers for different network instances")
	}

	w1Again := d.getOrCreateRouteWorker("default")
	if w1 != w1Again {
		t.Fatal("expected same worker returned for same network instance")
	}

	d.StopAllRouteWorkers()

	d.routeWorkersMu.Lock()
	count := len(d.routeWorkers)
	d.routeWorkersMu.Unlock()
	if count != 0 {
		t.Fatalf("expected 0 route workers after StopAllRouteWorkers, got %d", count)
	}
}

func TestRouteWorker_StopWorkerDrain(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		routeWorkers: make(map[string]*routeQueueWorker),
	}

	netinst := "drain-test"
	for i := 0; i < 10; i++ {
		pfx := fmt.Sprintf("10.0.%d.0/24", i)
		d.EnqueueRouteAdd(netinst, pfx, "10.0.0.1", uint32(100+i), 1000, false, 90)
	}

	// StopRouteWorker must block until all queued events are drained and installed
	d.StopRouteWorker(netinst)

	inst := d.GetInstance(netinst)
	if inst == nil {
		t.Fatal("expected instance to exist")
	}

	d.mu.RLock()
	routeCount := len(inst.routes)
	d.mu.RUnlock()

	if routeCount != 10 {
		t.Fatalf("expected 10 drained routes, got %d", routeCount)
	}
}

func TestRouteWorker_NilMapSafety(t *testing.T) {
	d := &EigrpDaemon{} // routeWorkers is nil
	// None of these should panic
	d.EnqueueRouteAdd("default", "10.0.0.0/24", "10.0.0.1", 100, 1000, false, 90)
	d.EnqueueRouteDel("default", "10.0.0.0/24")
	d.StopRouteWorker("default")
	d.StopAllRouteWorkers()

	// Fib sync nil guards
	d.FibSyncStart(nil)
	d.FibSyncEnd(nil)
}

func TestRouteWorker_ConcurrentMultiVRF(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		routeWorkers: make(map[string]*routeQueueWorker),
	}

	vrfs := []string{"default", "vrf-1", "vrf-2", "vrf-3", "vrf-4"}
	var wg sync.WaitGroup

	for _, vrf := range vrfs {
		wg.Add(1)
		go func(v string) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				pfx := fmt.Sprintf("10.%d.0.0/16", i)
				d.EnqueueRouteAdd(v, pfx, "10.0.0.1", uint32(i*10), uint64(i*1000), false, 90)
				d.EnqueueRouteDel(v, pfx)
			}
		}(vrf)
	}

	wg.Wait()
	time.Sleep(100 * time.Millisecond)

	d.routeWorkersMu.Lock()
	workerCount := len(d.routeWorkers)
	d.routeWorkersMu.Unlock()

	if workerCount != len(vrfs) {
		t.Fatalf("expected %d workers, got %d", len(vrfs), workerCount)
	}

	d.StopAllRouteWorkers()
}

func TestRouteWorker_RapidFlapStress(t *testing.T) {
	d := &EigrpDaemon{
		instances:    make(map[string]*EigrpInstance),
		routeWorkers: make(map[string]*routeQueueWorker),
	}

	netinst := "stress-test"
	pfx := "172.16.0.0/16"

	// Perform 100 rapid add/del flap cycles
	for i := 0; i < 100; i++ {
		d.EnqueueRouteAdd(netinst, pfx, "10.1.1.1", uint32(i), uint64(i*100), false, 90)
		d.EnqueueRouteDel(netinst, pfx)
	}

	// Final state should be route added
	d.EnqueueRouteAdd(netinst, pfx, "10.1.1.254", 500, 50000, false, 90)

	time.Sleep(150 * time.Millisecond)

	inst := d.GetInstance(netinst)
	if inst == nil {
		t.Fatal("expected instance to exist")
	}

	d.mu.RLock()
	r, ok := inst.routes[pfx]
	d.mu.RUnlock()

	if !ok || r == nil {
		t.Fatalf("expected route %s to be present after stress test", pfx)
	}
	if r.NextHop != "10.1.1.254" || r.Metric != 500 {
		t.Fatalf("expected final route state (nh=10.1.1.254, metric=500), got %+v", r)
	}

	d.StopRouteWorker(netinst)
}

func TestRel030OverridesCheck(t *testing.T) {
	if rc := ShimTestRel030OverridesCheck(); rc != 0 {
		t.Fatalf("ShimTestRel030OverridesCheck failed with rc=%d", rc)
	}
}

