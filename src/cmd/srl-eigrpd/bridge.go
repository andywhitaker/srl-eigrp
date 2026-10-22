package main

/*
#cgo CFLAGS: -I../../upstream/eigrp/eigrp/code -I../../cshim
#cgo LDFLAGS: -rdynamic -L../../cshim -L../../upstream/eigrp/eigrp/code -Wl,--wrap=eigrp_topology_metric_update -Wl,--wrap=eigrp_summary_route_build -Wl,--wrap=eigrp_summary_query_route_build -Wl,--wrap=eigrp_topology_prefix_admit -Wl,--wrap=eigrp_nbr_prefix_admit -Wl,--wrap=eigrp_update_receive -Wl,--wrap=eigrp_topology_neighbor_down -Wl,--wrap=eigrp_nbr_codec_select -Wl,--wrap=eigrp_nbr_codec_update -Wl,--start-group -leigrp-core -lsrl-cshim -Wl,--end-group -lpthread -ldl -lstdc++
#include <stdlib.h>
#include "srl_cshim.h"
*/
import "C"
import (
	"sync"
	"time"
	"unsafe"
)

type routeEventType int

const (
	routeEventAdd routeEventType = iota
	routeEventDel
)

type routeEvent struct {
	eventType  routeEventType
	netinst    string
	prefix     string
	nexthop    string
	metric     uint32
	wideMetric uint64
	isExt      bool
	preference uint32
	ifname     string
}

type routeQueueWorker struct {
	mu       sync.Mutex
	overflow []routeEvent
	queue    chan routeEvent
	stop     chan struct{}
	done     chan struct{}
}

func (w *routeQueueWorker) enqueue(ev routeEvent) {
	select {
	case <-w.stop:
		return
	default:
	}

	w.mu.Lock()
	if len(w.overflow) > 0 {
		w.overflow = append(w.overflow, ev)
		w.mu.Unlock()
		return
	}
	select {
	case w.queue <- ev:
		w.mu.Unlock()
	default:
		w.overflow = append(w.overflow, ev)
		w.mu.Unlock()
	}
}

func (d *EigrpDaemon) getOrCreateRouteWorker(netinst string) *routeQueueWorker {
	if netinst == "" {
		netinst = "default"
	}
	d.routeWorkersMu.Lock()
	defer d.routeWorkersMu.Unlock()
	if d.routeWorkers == nil {
		d.routeWorkers = make(map[string]*routeQueueWorker)
	}
	w, exists := d.routeWorkers[netinst]
	if !exists {
		w = &routeQueueWorker{
			queue: make(chan routeEvent, 16384),
			stop:  make(chan struct{}),
			done:  make(chan struct{}),
		}
		d.routeWorkers[netinst] = w
		go d.runRouteWorker(w)
	}
	return w
}

func (d *EigrpDaemon) runRouteWorker(w *routeQueueWorker) {
	defer close(w.done)
	for {
		// First flush any items in overflow into queue
		w.mu.Lock()
	overflowLoop:
		for len(w.overflow) > 0 {
			select {
			case w.queue <- w.overflow[0]:
				w.overflow[0] = routeEvent{}
				w.overflow = w.overflow[1:]
			default:
				break overflowLoop
			}
		}
		w.mu.Unlock()

		select {
		case <-w.stop:
			for {
				w.mu.Lock()
				if len(w.overflow) > 0 {
					select {
					case w.queue <- w.overflow[0]:
						w.overflow[0] = routeEvent{}
						w.overflow = w.overflow[1:]
					default:
					}
				}
				w.mu.Unlock()

				select {
				case ev := <-w.queue:
					d.processRouteEvent(ev)
				default:
					w.mu.Lock()
					if len(w.overflow) > 0 {
						ev := w.overflow[0]
						w.overflow[0] = routeEvent{}
						w.overflow = w.overflow[1:]
						w.mu.Unlock()
						d.processRouteEvent(ev)
						continue
					}
					w.mu.Unlock()
					return
				}
			}
		case ev := <-w.queue:
			d.processRouteEvent(ev)
		}
	}
}

func (d *EigrpDaemon) processRouteEvent(ev routeEvent) {
	switch ev.eventType {
	case routeEventAdd:
		d.OnRouteAdd(ev.netinst, ev.prefix, ev.nexthop, ev.metric, ev.wideMetric, ev.isExt, ev.preference, ev.ifname)
	case routeEventDel:
		d.OnRouteDel(ev.netinst, ev.prefix)
	}
}

func (d *EigrpDaemon) EnqueueRouteAdd(netinst, prefix, nexthop string, metric uint32, wideMetric uint64, isExt bool, preference uint32, ifname ...string) {
	var ifn string
	if len(ifname) > 0 {
		ifn = ifname[0]
	}
	w := d.getOrCreateRouteWorker(netinst)
	w.enqueue(routeEvent{
		eventType:  routeEventAdd,
		netinst:    netinst,
		prefix:     prefix,
		nexthop:    nexthop,
		metric:     metric,
		wideMetric: wideMetric,
		isExt:      isExt,
		preference: preference,
		ifname:     ifn,
	})
}

func (d *EigrpDaemon) EnqueueRouteDel(netinst, prefix string) {
	w := d.getOrCreateRouteWorker(netinst)
	w.enqueue(routeEvent{
		eventType: routeEventDel,
		netinst:   netinst,
		prefix:    prefix,
	})
}

func (d *EigrpDaemon) StopRouteWorker(netinst string) {
	if netinst == "" {
		netinst = "default"
	}
	d.routeWorkersMu.Lock()
	if d.routeWorkers == nil {
		d.routeWorkersMu.Unlock()
		return
	}
	w, exists := d.routeWorkers[netinst]
	if exists {
		delete(d.routeWorkers, netinst)
		close(w.stop)
	}
	d.routeWorkersMu.Unlock()

	if exists {
		select {
		case <-w.done:
		case <-time.After(2 * time.Second):
		}
	}
}

func (d *EigrpDaemon) StopAllRouteWorkers() {
	d.routeWorkersMu.Lock()
	if d.routeWorkers == nil {
		d.routeWorkersMu.Unlock()
		return
	}
	workers := make([]*routeQueueWorker, 0, len(d.routeWorkers))
	for ni, w := range d.routeWorkers {
		delete(d.routeWorkers, ni)
		close(w.stop)
		workers = append(workers, w)
	}
	d.routeWorkersMu.Unlock()

	for _, w := range workers {
		select {
		case <-w.done:
		case <-time.After(2 * time.Second):
		}
	}
}

//export srlGoRouteAdd
func srlGoRouteAdd(netinst *C.char, prefix *C.char, nexthop *C.char, metric C.uint32_t, wideMetric C.uint64_t, isExt C.int, preference C.uint32_t, ifname *C.char) {
	if daemonApp != nil {
		ni := C.GoString(netinst)
		pfx := C.GoString(prefix)
		nh := C.GoString(nexthop)
		m := uint32(metric)
		wm := uint64(wideMetric)
		ext := isExt != 0
		pref := uint32(preference)
		var ifn string
		if ifname != nil {
			ifn = C.GoString(ifname)
		}
		daemonApp.EnqueueRouteAdd(ni, pfx, nh, m, wm, ext, pref, ifn)
	}
}

//export srlGoRouteDel
func srlGoRouteDel(netinst *C.char, prefix *C.char) {
	if daemonApp != nil {
		ni := C.GoString(netinst)
		pfx := C.GoString(prefix)
		daemonApp.EnqueueRouteDel(ni, pfx)
	}
}

//export srlGoLog
func srlGoLog(level C.int, msg *C.char) {
	logMessage(int(level), C.GoString(msg))
}

//export srlGoNeighborReport
func srlGoNeighborReport(netinst *C.char, ip *C.char, ifname *C.char, state *C.char, hold C.uint16_t, uptime C.uint64_t, srtt C.uint32_t, rto C.uint32_t, bfdState *C.char, restartState *C.char, authMode *C.char) {
	if daemonApp != nil {
		daemonApp.OnNeighborReport(C.GoString(netinst), C.GoString(ip), C.GoString(ifname), C.GoString(state), uint16(hold), uint64(uptime), uint32(srtt), uint32(rto), C.GoString(bfdState), C.GoString(restartState), C.GoString(authMode))
	}
}

//export srlGoInterfaceReport
func srlGoInterfaceReport(netinst *C.char, ifname, ipAddr *C.char, prefixlen C.uint32_t, operState *C.char) {
	if daemonApp != nil {
		daemonApp.OnInterfaceReport(C.GoString(netinst), C.GoString(ifname), C.GoString(ipAddr), uint32(prefixlen), C.GoString(operState))
	}
}

//export srlGoTopologyPrefixReport
func srlGoTopologyPrefixReport(netinst *C.char, prefix *C.char, active C.int, fd C.uint32_t, wideFd C.uint64_t, succCount C.uint32_t) {
	if daemonApp != nil {
		daemonApp.OnTopologyPrefix(C.GoString(netinst), C.GoString(prefix), active != 0, uint32(fd), uint64(wideFd), uint32(succCount))
	}
}

//export srlGoTopologyRouteReport
func srlGoTopologyRouteReport(netinst *C.char, nexthop *C.char, ifname *C.char, isSucc C.int, isFeasSucc C.int, dist C.uint32_t, wideDist C.uint64_t, rd C.uint32_t, wideRd C.uint64_t) {
	if daemonApp != nil {
		daemonApp.OnTopologyRoute(C.GoString(netinst), C.GoString(nexthop), C.GoString(ifname), isSucc != 0, isFeasSucc != 0, uint32(dist), uint64(wideDist), uint32(rd), uint64(wideRd))
	}
}

//export srlGoTrafficReport
func srlGoTrafficReport(netinst *C.char, ifname *C.char, rmcast C.uint64_t, umcast C.uint64_t, rucast C.uint64_t, uucast C.uint64_t, rexmits C.uint64_t, cr C.uint64_t) {
	if daemonApp != nil {
		daemonApp.OnTrafficReport(C.GoString(netinst), C.GoString(ifname), uint64(rmcast), uint64(umcast), uint64(rucast), uint64(uucast), uint64(rexmits), uint64(cr))
	}
}

// ShimSetPktFdDisabled sets whether AF_PACKET packet sockets are disabled.
func ShimSetPktFdDisabled(disabled bool) {
	C.srlShimSetPktFdDisabled(C.bool(disabled))
}

// ShimGetPktFdDisabled returns whether AF_PACKET packet sockets are disabled.
func ShimGetPktFdDisabled() bool {
	return bool(C.srlShimGetPktFdDisabled())
}

// ShimPacketHash computes the FNV-1a packet hash for deduplication.
func ShimPacketHash(afi int, src, dst, payload []byte) uint32 {
	if len(src) == 0 || len(dst) == 0 {
		return 0
	}
	var pPayload unsafe.Pointer
	if len(payload) > 0 {
		pPayload = unsafe.Pointer(&payload[0])
	}
	return uint32(C.srlTestPacketHash(
		C.int(afi),
		unsafe.Pointer(&src[0]),
		unsafe.Pointer(&dst[0]),
		pPayload,
		C.size_t(len(payload)),
	))
}

// ShimDedupCheck checks and records packet deduplication across receive sockets.
func ShimDedupCheck(rxSrc, afi uint8, hash uint32, length, ipID, eigrpCsum uint16) bool {
	return bool(C.srlTestDedupCheck(
		C.uint8_t(rxSrc),
		C.uint8_t(afi),
		C.uint32_t(hash),
		C.uint16_t(length),
		C.uint16_t(ipID),
		C.uint16_t(eigrpCsum),
	))
}

// ShimDedupReset clears test deduplication cache entries.
func ShimDedupReset() {
	C.srlTestDedupReset()
}

// ShimTestResolveInterfaceV4 tests wire interface resolution for IPv4 packets.
func ShimTestResolveInterfaceV4(netinst string, sllIfindex uint32, vlanID uint16, srcIP, dstIP string) uint32 {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	var cSrc, cDst *C.char
	if srcIP != "" {
		cSrc = C.CString(srcIP)
		defer C.free(unsafe.Pointer(cSrc))
	}
	if dstIP != "" {
		cDst = C.CString(dstIP)
		defer C.free(unsafe.Pointer(cDst))
	}
	return uint32(C.srlTestResolveInterfaceV4(cNetinst, C.uint32_t(sllIfindex), C.uint16_t(vlanID), cSrc, cDst))
}

// ShimTestResolveInterfaceV6 tests wire interface resolution for IPv6 packets.
func ShimTestResolveInterfaceV6(netinst string, sllIfindex uint32, vlanID uint16, srcIP, dstIP string) uint32 {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	var cSrc, cDst *C.char
	if srcIP != "" {
		cSrc = C.CString(srcIP)
		defer C.free(unsafe.Pointer(cSrc))
	}
	if dstIP != "" {
		cDst = C.CString(dstIP)
		defer C.free(unsafe.Pointer(cDst))
	}
	return uint32(C.srlTestResolveInterfaceV6(cNetinst, C.uint32_t(sllIfindex), C.uint16_t(vlanID), cSrc, cDst))
}

// ShimTestRegisterInterface registers a mock interface in the C shim for testing.
func ShimTestRegisterInterface(netinst, ifname string, ifidx, rootIfidx uint32, ipAddr string, prefixlen uint8, isV6, active bool) {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	cIfname := C.CString(ifname)
	defer C.free(unsafe.Pointer(cIfname))
	var cIP *C.char
	if ipAddr != "" {
		cIP = C.CString(ipAddr)
		defer C.free(unsafe.Pointer(cIP))
	}
	C.srlTestRegisterInterface(cNetinst, cIfname, C.eigrp_ifindex_t(ifidx), C.eigrp_ifindex_t(rootIfidx), cIP, C.uint8_t(prefixlen), C.bool(isV6), C.bool(active))
}

// ShimTestRegisterInterfaceWithVlan registers a mock interface with an explicit VLAN ID in the C shim.
func ShimTestRegisterInterfaceWithVlan(netinst, ifname string, ifidx, rootIfidx uint32, vlanID uint16, ipAddr string, prefixlen uint8, isV6, active bool) {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	cIfname := C.CString(ifname)
	defer C.free(unsafe.Pointer(cIfname))
	var cIP *C.char
	if ipAddr != "" {
		cIP = C.CString(ipAddr)
		defer C.free(unsafe.Pointer(cIP))
	}
	C.srlTestRegisterInterfaceWithVlan(cNetinst, cIfname, C.eigrp_ifindex_t(ifidx), C.eigrp_ifindex_t(rootIfidx), C.uint16_t(vlanID), cIP, C.uint8_t(prefixlen), C.bool(isV6), C.bool(active))
}

// ShimInterfaceSetVlanID sets the explicit VLAN ID on a registered interface.
func ShimInterfaceSetVlanID(netinst, ifname string, vlanID uint16) int {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	cIfname := C.CString(ifname)
	defer C.free(unsafe.Pointer(cIfname))
	return int(C.srlShimInterfaceSetVlanId(cNetinst, cIfname, C.uint16_t(vlanID)))
}

// ShimTestClearInterfaces clears registered interfaces in the C shim.
func ShimTestClearInterfaces() {
	C.srlTestClearInterfaces()
}

// ShimTestRunBPFFilter runs the generated cBPF filter against a packet buffer and ifindex.
func ShimTestRunBPFFilter(ifindexes []uint32, pkt []byte, ifindex uint32) uint32 {
	var pIfindexes *C.uint32_t
	if len(ifindexes) > 0 {
		pIfindexes = (*C.uint32_t)(unsafe.Pointer(&ifindexes[0]))
	}
	var pPkt *C.uint8_t
	if len(pkt) > 0 {
		pPkt = (*C.uint8_t)(unsafe.Pointer(&pkt[0]))
	}
	return uint32(C.srlTestRunBPFFilter(pIfindexes, C.size_t(len(ifindexes)), pPkt, C.size_t(len(pkt)), C.uint32_t(ifindex)))
}

// ShimTestMatchRootWireIfname tests root wire interface name matching logic.
func ShimTestMatchRootWireIfname(devName, baseName string) bool {
	cDev := C.CString(devName)
	defer C.free(unsafe.Pointer(cDev))
	cBase := C.CString(baseName)
	defer C.free(unsafe.Pointer(cBase))
	return bool(C.srlTestMatchRootWireIfname(cDev, cBase))
}

// ShimTestIsLocalPrefix tests whether a prefix belongs to local connected interfaces or loopbacks.
func ShimTestIsLocalPrefix(netinst, prefix string, isV6 bool) bool {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	cPfx := C.CString(prefix)
	defer C.free(unsafe.Pointer(cPfx))
	return bool(C.srlTestIsLocalPrefix(cNetinst, cPfx, C.bool(isV6)))
}

// ShimNeighborsReport triggers neighbor reporting for a network instance.
func ShimNeighborsReport(netinst string) {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	C.srlShimNeighborsReport(cNetinst)
}

// ShimTopologyReport triggers topology reporting for a network instance.
func ShimTopologyReport(netinst string) {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	C.srlShimTopologyReport(cNetinst)
}

// ShimTrafficReport triggers traffic reporting for a network instance.
func ShimTrafficReport(netinst string) {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	C.srlShimTrafficReport(cNetinst)
}

// ShimInterfacesReport triggers interface reporting for a network instance.
func ShimInterfacesReport(netinst string) {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	C.srlShimInterfacesReport(cNetinst)
}

//export srlGoEventLogReport
func srlGoEventLogReport(netinst *C.char, eventNum C.uint32_t, timestampMs C.uint64_t, msg *C.char) {
	if daemonApp != nil {
		daemonApp.OnEventLogReport(C.GoString(netinst), uint32(eventNum), uint64(timestampMs), C.GoString(msg))
	}
}

// ShimInterfaceBandwidthPercentUpdate updates the interface bandwidth-percent configuration.
func ShimInterfaceBandwidthPercentUpdate(netinst, ifname, afiName string, percent uint32) int {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	cIfname := C.CString(ifname)
	defer C.free(unsafe.Pointer(cIfname))
	var cAfi *C.char
	if afiName != "" {
		cAfi = C.CString(afiName)
		defer C.free(unsafe.Pointer(cAfi))
	}
	return int(C.srlShimInterfaceBandwidthPercentUpdate(cNetinst, cIfname, cAfi, C.uint32_t(percent)))
}

// ShimTrafficShareBalancedUpdate updates traffic-share balanced mode for a network instance and AFI.
func ShimTrafficShareBalancedUpdate(netinst, afiName string, balanced bool) int {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	var cAfi *C.char
	if afiName != "" {
		cAfi = C.CString(afiName)
		defer C.free(unsafe.Pointer(cAfi))
	}
	return int(C.srlShimTrafficShareBalancedUpdate(cNetinst, cAfi, C.bool(balanced)))
}

// ShimAutoSummaryUpdate updates auto-summary configuration for a network instance and AFI.
func ShimAutoSummaryUpdate(netinst, afiName string, enabled bool) int {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	var cAfi *C.char
	if afiName != "" {
		cAfi = C.CString(afiName)
		defer C.free(unsafe.Pointer(cAfi))
	}
	return int(C.srlShimAutoSummaryUpdate(cNetinst, cAfi, C.bool(enabled)))
}

// ShimDefaultMetricUpdate updates the default redistribution metric for a network instance and AFI.
func ShimDefaultMetricUpdate(netinst, afiName string, bw, delay uint32, reliability, load uint8, mtu uint32) int {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	var cAfi *C.char
	if afiName != "" {
		cAfi = C.CString(afiName)
		defer C.free(unsafe.Pointer(cAfi))
	}
	return int(C.srlShimDefaultMetricUpdate(cNetinst, cAfi, C.uint32_t(bw), C.uint32_t(delay), C.uint8_t(reliability), C.uint8_t(load), C.uint32_t(mtu)))
}

// ShimMaxPrefixUpdate updates the topology maximum-prefix limit for a network instance and AFI.
func ShimMaxPrefixUpdate(netinst, afiName string, maxPrefixes uint32, threshold uint8, warningOnly bool) int {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	var cAfi *C.char
	if afiName != "" {
		cAfi = C.CString(afiName)
		defer C.free(unsafe.Pointer(cAfi))
	}
	return int(C.srlShimMaxPrefixUpdate(cNetinst, cAfi, C.uint32_t(maxPrefixes), C.uint8_t(threshold), C.bool(warningOnly)))
}

// ShimTopologyClear clears topology entries for a network instance.
func ShimTopologyClear(netinst, prefix string) int {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	var cPfx *C.char
	if prefix != "" {
		cPfx = C.CString(prefix)
		defer C.free(unsafe.Pointer(cPfx))
	}
	return int(C.srlShimTopologyClear(cNetinst, cPfx))
}

// ShimEventLogSizeUpdate updates the DUAL event log size for a network instance.
func ShimEventLogSizeUpdate(netinst string, size uint32) int {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	return int(C.srlShimEventLogSizeUpdate(cNetinst, C.uint32_t(size)))
}

// ShimEventLogClear clears the DUAL event log for a network instance.
func ShimEventLogClear(netinst string) int {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	return int(C.srlShimEventLogClear(cNetinst))
}

// ShimEventLogReport triggers DUAL event log reporting for a network instance.
func ShimEventLogReport(netinst string) {
	cNetinst := C.CString(netinst)
	defer C.free(unsafe.Pointer(cNetinst))
	C.srlShimEventLogReport(cNetinst)
}

// ShimTestRel030OverridesCheck runs unit checks on rel-0.3.0 CShim overrides.
func ShimTestRel030OverridesCheck() int {
	return int(C.srlTestRel030OverridesCheck())
}

