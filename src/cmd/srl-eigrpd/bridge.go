package main

/*
#cgo CFLAGS: -I../../upstream/eigrp/eigrp/code -I../../cshim
#cgo LDFLAGS: -rdynamic -L../../cshim -L../../upstream/eigrp/eigrp/code -Wl,--wrap=eigrp_sys_intf_update -Wl,--wrap=eigrp_check_md5_digest -Wl,--wrap=eigrp_check_sha256_digest -Wl,--wrap=eigrp_auth_tlv_md5_encode -Wl,--wrap=eigrp_auth_tlv_sha256_encode -Wl,--wrap=eigrp_make_md5_digest -Wl,--wrap=eigrp_make_sha256_digest -Wl,--start-group -leigrp-core -lsrl-cshim -Wl,--end-group -lpthread -ldl -lstdc++
#include "srl_cshim.h"
*/
import "C"
import "time"

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
}

type routeQueueWorker struct {
	queue chan routeEvent
	stop  chan struct{}
	done  chan struct{}
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
			queue: make(chan routeEvent, 1024),
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
		select {
		case <-w.stop:
			for {
				select {
				case ev := <-w.queue:
					d.processRouteEvent(ev)
				default:
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
		d.OnRouteAdd(ev.netinst, ev.prefix, ev.nexthop, ev.metric, ev.wideMetric, ev.isExt, ev.preference)
	case routeEventDel:
		d.OnRouteDel(ev.netinst, ev.prefix)
	}
}

func (d *EigrpDaemon) EnqueueRouteAdd(netinst, prefix, nexthop string, metric uint32, wideMetric uint64, isExt bool, preference uint32) {
	w := d.getOrCreateRouteWorker(netinst)
	select {
	case <-w.stop:
		return
	default:
	}
	select {
	case w.queue <- routeEvent{
		eventType:  routeEventAdd,
		netinst:    netinst,
		prefix:     prefix,
		nexthop:    nexthop,
		metric:     metric,
		wideMetric: wideMetric,
		isExt:      isExt,
		preference: preference,
	}:
	case <-w.stop:
	}
}

func (d *EigrpDaemon) EnqueueRouteDel(netinst, prefix string) {
	w := d.getOrCreateRouteWorker(netinst)
	select {
	case <-w.stop:
		return
	default:
	}
	select {
	case w.queue <- routeEvent{
		eventType: routeEventDel,
		netinst:   netinst,
		prefix:    prefix,
	}:
	case <-w.stop:
	}
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
func srlGoRouteAdd(netinst *C.char, prefix *C.char, nexthop *C.char, metric C.uint32_t, wideMetric C.uint64_t, isExt C.int, preference C.uint32_t) {
	if daemonApp != nil {
		ni := C.GoString(netinst)
		pfx := C.GoString(prefix)
		nh := C.GoString(nexthop)
		m := uint32(metric)
		wm := uint64(wideMetric)
		ext := isExt != 0
		pref := uint32(preference)
		daemonApp.EnqueueRouteAdd(ni, pfx, nh, m, wm, ext, pref)
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
