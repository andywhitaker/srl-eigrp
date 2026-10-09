package main

/*
#cgo CFLAGS: -I../../upstream/eigrp/eigrp/code -I../../cshim
#cgo LDFLAGS: -rdynamic -L../../cshim -L../../upstream/eigrp/eigrp/code -Wl,--wrap=eigrp_sys_intf_update -Wl,--wrap=eigrp_check_md5_digest -Wl,--wrap=eigrp_check_sha256_digest -Wl,--wrap=eigrp_auth_tlv_md5_encode -Wl,--wrap=eigrp_auth_tlv_sha256_encode -Wl,--wrap=eigrp_make_md5_digest -Wl,--wrap=eigrp_make_sha256_digest -Wl,--start-group -leigrp-core -lsrl-cshim -Wl,--end-group -lpthread -ldl -lstdc++
#include "srl_cshim.h"
*/
import "C"

//export srlGoRouteAdd
func srlGoRouteAdd(netinst *C.char, prefix *C.char, nexthop *C.char, metric C.uint32_t, wideMetric C.uint64_t, isExt C.int) {
	if daemonApp != nil {
		daemonApp.OnRouteAdd(C.GoString(netinst), C.GoString(prefix), C.GoString(nexthop), uint32(metric), uint64(wideMetric), isExt != 0)
	}
}

//export srlGoRouteDel
func srlGoRouteDel(netinst *C.char, prefix *C.char) {
	if daemonApp != nil {
		daemonApp.OnRouteDel(C.GoString(netinst), C.GoString(prefix))
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
